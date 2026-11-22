#!/usr/bin/env python3
"""
src/telegram_notifier.py — Strictly Outbound-Only Telegram Notifier.

Security & Guardrails:
- Outbound-only: only calls POST https://api.telegram.org/bot<TOKEN>/sendMessage.
- Zero inbound polling and zero interactive commands.
- Atomic file locking via fcntl.flock on the sent-message ledger.
- 24-hour SHA-256 deduplication and daily rate cap (default: 6/day).
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import html
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LEDGER_PATH = REPO_ROOT / "state" / ".telegram_sent_log.json"
TELEGRAM_API_BASE = "https://api.telegram.org"


class TelegramNotifier:
    """Strictly outbound-only Telegram Bot API notifier with dedup and daily rate cap."""

    def __init__(
        self,
        bot_token: str | None = None,
        chat_id: str | None = None,
        ledger_path: Path | str | None = None,
        daily_cap: int = 6,
    ) -> None:
        self.bot_token = (
            bot_token
            if bot_token is not None
            else os.getenv("TELEGRAM_BOT_TOKEN", "")
        ).strip()
        self.chat_id = (
            chat_id
            if chat_id is not None
            else (
                os.getenv("TELEGRAM_CHAT_ID")
                or os.getenv("TELEGRAM_ALLOWED_USER_ID")
                or ""
            )
        ).strip()
        self.ledger_path = Path(ledger_path) if ledger_path is not None else DEFAULT_LEDGER_PATH
        self.daily_cap = max(1, int(daily_cap))

    @staticmethod
    def escape_html(text: str) -> str:
        """Escape HTML special characters for Telegram HTML parse_mode."""
        return html.escape(text or "", quote=True)

    @staticmethod
    def chunk_message(text: str, max_len: int = 4096) -> list[str]:
        """Split a message into chunks <= max_len, preferring newline then space boundaries."""
        if max_len < 1:
            raise ValueError("max_len must be >= 1")
        if not text:
            return []
        if len(text) <= max_len:
            return [text]

        chunks: list[str] = []
        remaining = text
        while remaining:
            if len(remaining) <= max_len:
                chunks.append(remaining)
                break

            window = remaining[:max_len]
            split_idx = window.rfind("\n")
            if split_idx <= 0:
                split_idx = window.rfind(" ")
            if split_idx <= 0:
                split_idx = max_len

            chunk = remaining[:split_idx].rstrip()
            if not chunk:
                chunk = remaining[:max_len]
                split_idx = max_len

            chunks.append(chunk)
            remaining = remaining[split_idx:].lstrip("\n")
            if remaining.startswith(" ") and split_idx < max_len:
                remaining = remaining.lstrip(" ")

        return chunks

    @staticmethod
    def compute_dedup_hash(category: str, text: str) -> str:
        """Compute deterministic SHA-256 hash over category and normalized message text."""
        payload = f"{category.strip().lower()}::{text.strip()}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _read_ledger_unlocked(self, file_obj: Any) -> dict[str, Any]:
        file_obj.seek(0)
        raw = file_obj.read().strip()
        if not raw:
            return {"entries": []}
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and isinstance(data.get("entries"), list):
                return data
        except json.JSONDecodeError:
            pass
        return {"entries": []}

    def _write_ledger_unlocked(self, file_obj: Any, data: dict[str, Any]) -> None:
        file_obj.seek(0)
        file_obj.truncate()
        json.dump(data, file_obj, ensure_ascii=False, indent=2)
        file_obj.flush()

    @staticmethod
    def _prune_entries(entries: list[dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
        cutoff = now - timedelta(days=7)
        kept: list[dict[str, Any]] = []
        for entry in entries:
            ts_raw = entry.get("timestamp")
            if not isinstance(ts_raw, str):
                continue
            try:
                ts = datetime.fromisoformat(ts_raw)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts >= cutoff:
                    kept.append(entry)
            except ValueError:
                continue
        return kept

    def _post_chunk(self, chunk: str, parse_mode: str) -> None:
        url = f"{TELEGRAM_API_BASE}/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": chunk,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            if not body.get("ok"):
                raise RuntimeError(f"Telegram API returned ok=false: {body}")

    def send(
        self,
        text: str,
        *,
        category: str = "general",
        dry_run: bool = False,
        force: bool = False,
        parse_mode: str = "HTML",
    ) -> dict[str, Any]:
        """
        Send an outbound Telegram notification with 24h deduplication and daily rate cap.

        When dry_run=True, performs zero network I/O and does not mutate the ledger.
        """
        chunks = self.chunk_message(text)
        msg_hash = self.compute_dedup_hash(category, text)

        if not chunks:
            return {
                "sent": False,
                "status": "skipped_empty",
                "chunks": 0,
                "hash": msg_hash,
                "detail": "Empty message text",
                "preview": "",
            }

        if dry_run:
            return {
                "sent": False,
                "status": "dry_run",
                "chunks": len(chunks),
                "hash": msg_hash,
                "detail": "Dry run: no network I/O performed",
                "preview": chunks[0],
            }

        if not self.bot_token or not self.chat_id:
            return {
                "sent": False,
                "status": "skipped_unconfigured",
                "chunks": len(chunks),
                "hash": msg_hash,
                "detail": "Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID",
            }

        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc)
        today_str = now.date().isoformat()
        dedup_cutoff = now - timedelta(hours=24)

        with open(self.ledger_path, "a+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                ledger = self._read_ledger_unlocked(f)
                entries = self._prune_entries(ledger.get("entries", []), now)

                if not force:
                    for entry in entries:
                        if entry.get("hash") == msg_hash:
                            try:
                                ts = datetime.fromisoformat(str(entry.get("timestamp", "")))
                                if ts.tzinfo is None:
                                    ts = ts.replace(tzinfo=timezone.utc)
                                if ts >= dedup_cutoff:
                                    return {
                                        "sent": False,
                                        "status": "skipped_duplicate",
                                        "chunks": len(chunks),
                                        "hash": msg_hash,
                                        "detail": "Duplicate message within 24h window",
                                    }
                            except ValueError:
                                continue

                    sent_today = sum(1 for e in entries if e.get("date") == today_str)
                    if sent_today >= self.daily_cap:
                        return {
                            "sent": False,
                            "status": "skipped_rate_cap",
                            "chunks": len(chunks),
                            "hash": msg_hash,
                            "detail": f"Daily cap reached ({sent_today}/{self.daily_cap})",
                        }

                for chunk in chunks:
                    self._post_chunk(chunk, parse_mode=parse_mode)

                entries.append(
                    {
                        "hash": msg_hash,
                        "category": category,
                        "timestamp": now.isoformat(),
                        "date": today_str,
                        "chunks": len(chunks),
                    }
                )
                self._write_ledger_unlocked(f, {"entries": entries})
                return {
                    "sent": True,
                    "status": "sent",
                    "chunks": len(chunks),
                    "hash": msg_hash,
                    "detail": f"Sent {len(chunks)} chunk(s)",
                }
            except (urllib.error.URLError, RuntimeError, OSError, json.JSONDecodeError, ValueError) as exc:
                return {
                    "sent": False,
                    "status": "error",
                    "chunks": len(chunks),
                    "hash": msg_hash,
                    "detail": str(exc),
                }
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def send_notification(
    text: str,
    *,
    category: str = "general",
    dry_run: bool = False,
    force: bool = False,
    parse_mode: str = "HTML",
    bot_token: str | None = None,
    chat_id: str | None = None,
    ledger_path: Path | str | None = None,
    daily_cap: int = 6,
) -> dict[str, Any]:
    """Convenience wrapper around TelegramNotifier.send()."""
    notifier = TelegramNotifier(
        bot_token=bot_token,
        chat_id=chat_id,
        ledger_path=ledger_path,
        daily_cap=daily_cap,
    )
    return notifier.send(
        text,
        category=category,
        dry_run=dry_run,
        force=force,
        parse_mode=parse_mode,
    )


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Outbound-Only Telegram Notifier")
    parser.add_argument("--text", required=True, help="Message text to send")
    parser.add_argument("--category", default="general", help="Notification category for dedup")
    parser.add_argument("--dry-run", action="store_true", help="Do not perform network I/O")
    parser.add_argument("--force", action="store_true", help="Bypass dedup and daily rate cap")
    parser.add_argument("--parse-mode", default="HTML", help="Telegram parse_mode (default: HTML)")
    args = parser.parse_args(argv)

    result = send_notification(
        args.text,
        category=args.category,
        dry_run=args.dry_run,
        force=args.force,
        parse_mode=args.parse_mode,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("status") != "error" else 1


if __name__ == "__main__":
    raise SystemExit(_main())
