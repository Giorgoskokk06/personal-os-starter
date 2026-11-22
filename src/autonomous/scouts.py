"""
src/autonomous/scouts.py — Read-Only RSS/Atom Intelligence Scouts.

Strictly read-only: ZERO shell/subprocess/file-edit on repo code.
Enforces 1MB payload cap, XXE/DTD rejection, OWASP IPI detection, HTML cleaning,
recency/prerelease/per-repo release filtering, and ephemeral cryptographic nonce isolation.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import json
from pathlib import Path
import re
from typing import Any
import urllib.request
import xml.etree.ElementTree as ET

from src.autonomous import REPO_ROOT, load_policy
from src.security.sanitizer import (
    MAX_HEADLINE_LEN,
    MAX_SUMMARY_LEN,
    OWASP_IPI_BLOCKLIST_RE,
    strip_html_and_normalize,
    wrap_untrusted_payload_with_nonce,
)

MAX_PAYLOAD_BYTES: int = 1_000_000
ATOM_NS = "{http://www.w3.org/2005/Atom}"
DC_NS = "{http://purl.org/dc/elements/1.1/}"

_USER_AGENT = "Personal-OS-AutonomousScout/1.0 (Read-Only Feed Reader; Linux x86_64)"

_PRERELEASE_RE = re.compile(
    r"(?:^|[\s._\-/v])(rc\d*|alpha\d*|beta\d*|dev\d*|nightly|pre\d*|snapshot)(?:$|[\s._\-/])",
    re.IGNORECASE,
)


def _find_first_text(
    el: ET.Element,
    tags: tuple[str, ...],
    *,
    preserve_markup: bool = False,
) -> str:
    for tag in tags:
        child = el.find(tag)
        if child is None:
            continue
        if preserve_markup and len(child) > 0:
            raw = (child.text or "") + "".join(
                ET.tostring(sub, encoding="unicode") for sub in child
            )
            if raw.strip():
                return raw.strip()
        text = "".join(child.itertext()).strip()
        if text:
            return text
    return ""


def _find_link(el: ET.Element) -> str:
    rss_link = el.find("link")
    if rss_link is not None:
        if rss_link.text and rss_link.text.strip():
            return rss_link.text.strip()
        href = rss_link.get("href", "").strip()
        if href:
            return href

    atom_links = el.findall(f"{ATOM_NS}link")
    for link_el in atom_links:
        rel = (link_el.get("rel") or "alternate").lower()
        href = (link_el.get("href") or "").strip()
        if rel == "alternate" and href:
            return href
    for link_el in atom_links:
        href = (link_el.get("href") or "").strip()
        if href:
            return href
        if link_el.text and link_el.text.strip():
            return link_el.text.strip()
    return ""


def _parse_published_datetime(published_str: str) -> datetime | None:
    raw = str(published_str or "").strip()
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(raw)
        if dt is not None:
            return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError, IndexError):
        pass
    iso_candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(iso_candidate)
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _is_prerelease(title: str, url: str) -> bool:
    probe = f"{title or ''} {url or ''}"
    return bool(_PRERELEASE_RE.search(probe))


def filter_scout_items(
    items: list[dict[str, Any]],
    *,
    recency_days: int = 14,
    max_releases_per_repo: int = 1,
    skip_prereleases: bool = True,
    is_release_feed: bool = False,
    now_utc: datetime | None = None,
) -> list[dict[str, Any]]:
    """Filter scout items by recency window, prerelease tags, and per-repo release cap."""
    ref_now = now_utc or datetime.now(timezone.utc)
    cutoff = ref_now - timedelta(days=max(1, int(recency_days)))

    recent_items: list[tuple[datetime, dict[str, Any]]] = []
    undated_items: list[dict[str, Any]] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "") or "")
        url = str(item.get("url", "") or "")
        item_is_release = is_release_feed or "/releases/tag/" in url.lower()

        if skip_prereleases and item_is_release and _is_prerelease(title, url):
            continue

        dt = _parse_published_datetime(str(item.get("published", "") or ""))
        if dt is None:
            if not item_is_release:
                undated_items.append(item)
            continue

        if dt < cutoff:
            continue

        recent_items.append((dt, item))

    if is_release_feed or any("/releases/tag/" in str(it.get("url", "")).lower() for _, it in recent_items):
        recent_items.sort(key=lambda pair: pair[0], reverse=True)
        per_source_counts: dict[str, int] = {}
        capped: list[dict[str, Any]] = []
        cap = max(1, int(max_releases_per_repo))
        for _, item in recent_items:
            url = str(item.get("url", "") or "")
            item_is_release = is_release_feed or "/releases/tag/" in url.lower()
            if item_is_release:
                src_key = str(item.get("source") or "unknown")
                count = per_source_counts.get(src_key, 0)
                if count >= cap:
                    continue
                per_source_counts[src_key] = count + 1
            capped.append(item)
        return capped + undated_items

    return [it for _, it in recent_items] + undated_items


def parse_feed_xml(
    xml_bytes: bytes,
    source_name: str,
    stream_id: str,
    *,
    recency_days: int = 14,
    max_releases_per_repo: int = 1,
    skip_prereleases: bool = True,
    is_release_feed: bool = False,
    now_utc: datetime | None = None,
) -> list[dict[str, Any]]:
    """
    Parse RSS <item> or Atom <entry> XML bytes with strict XXE/DTD and size guards.

    Raises:
        ValueError: If payload exceeds MAX_PAYLOAD_BYTES or contains <!DOCTYPE / <!ENTITY.
    """
    if len(xml_bytes) > MAX_PAYLOAD_BYTES:
        raise ValueError("Payload exceeds 1MB limit")

    lower_bytes = xml_bytes.lower()
    if b"<!doctype" in lower_bytes or b"<!entity" in lower_bytes:
        raise ValueError("XXE/DTD rejected")

    root = ET.fromstring(xml_bytes)

    entries = root.findall(".//item")
    if not entries:
        entries = root.findall(f".//{ATOM_NS}entry")
    if not entries:
        entries = root.findall(".//entry")

    parsed_items: list[dict[str, Any]] = []
    for entry in entries:
        raw_title = _find_first_text(entry, ("title", f"{ATOM_NS}title"), preserve_markup=True)
        raw_summary = _find_first_text(
            entry,
            (
                "description",
                f"{ATOM_NS}summary",
                f"{ATOM_NS}content",
                "summary",
                "content",
            ),
            preserve_markup=True,
        )
        published = _find_first_text(
            entry,
            (
                "pubDate",
                f"{ATOM_NS}published",
                f"{ATOM_NS}updated",
                f"{DC_NS}date",
                "published",
                "updated",
            ),
        )
        url = _find_link(entry)

        clean_title = strip_html_and_normalize(raw_title)[:MAX_HEADLINE_LEN]
        clean_summary = strip_html_and_normalize(raw_summary)[:MAX_SUMMARY_LEN]

        if not clean_title and not clean_summary:
            continue

        combined_probe = f"{clean_title} {clean_summary}"
        ipi_flagged = bool(OWASP_IPI_BLOCKLIST_RE.search(combined_probe))

        item_payload = {
            "stream_id": stream_id,
            "source": source_name,
            "title": clean_title,
            "url": url,
            "published": published,
            "summary": clean_summary,
        }
        nonce_block, _ = wrap_untrusted_payload_with_nonce(
            [item_payload],
            {"stream_id": stream_id, "source": source_name, "ipi_flagged": ipi_flagged},
        )

        parsed_items.append(
            {
                "stream_id": stream_id,
                "source": source_name,
                "title": clean_title,
                "url": url,
                "published": published,
                "summary": clean_summary,
                "sanitized_nonce_block": nonce_block,
                "ipi_flagged": ipi_flagged,
            }
        )

    return filter_scout_items(
        parsed_items,
        recency_days=recency_days,
        max_releases_per_repo=max_releases_per_repo,
        skip_prereleases=skip_prereleases,
        is_release_feed=is_release_feed,
        now_utc=now_utc,
    )


def _fetch_source_feed(
    source: dict[str, Any],
    stream_id: str,
    timeout: int,
    *,
    recency_days: int = 14,
    max_releases_per_repo: int = 1,
    skip_prereleases: bool = True,
) -> list[dict[str, Any]]:
    source_type = str(source.get("type", "")).strip().lower()
    url = str(source.get("url", "")).strip()
    name = str(source.get("name", url or "unknown")).strip()
    if source_type == "local" or not url or not url.startswith(("http://", "https://")):
        return []

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": _USER_AGENT,
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        xml_bytes = resp.read(MAX_PAYLOAD_BYTES + 1)

    is_release_feed = source_type == "atom" or "/releases.atom" in url.lower()
    return parse_feed_xml(
        xml_bytes,
        source_name=name,
        stream_id=stream_id,
        recency_days=recency_days,
        max_releases_per_repo=max_releases_per_repo,
        skip_prereleases=skip_prereleases,
        is_release_feed=is_release_feed,
    )


def run_scout(
    stream_id: str,
    *,
    policy: dict[str, Any] | None = None,
    offline: bool = False,
    cache_dir: Path | None = None,
    raw_dir: Path | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """
    Execute a read-only scout for the given stream_id.

    In offline mode, reads from cache_dir/<stream_id>.json without network I/O.
    In live mode, fetches all configured sources in parallel, filters IPI items,
    updates cache, and writes sanitized output to raw_dir/<stream_id>_<today>.json.
    """
    active_policy = policy if policy is not None else load_policy()
    guardrails = active_policy.get("guardrails", {}) if isinstance(active_policy, dict) else {}
    if not isinstance(guardrails, dict):
        guardrails = {}
    recency_days = int(guardrails.get("recency_window_days", 14))
    max_releases_per_repo = int(guardrails.get("max_releases_per_repo", 1))
    skip_prereleases = bool(guardrails.get("skip_prereleases", True))

    now_utc = datetime.now(timezone.utc)
    fetched_at = now_utc.isoformat()
    today_str = now_utc.date().isoformat()

    resolved_cache_dir = (
        Path(cache_dir) if cache_dir is not None else REPO_ROOT / "state" / "autonomous" / "cache"
    )
    resolved_raw_dir = (
        Path(raw_dir) if raw_dir is not None else REPO_ROOT / "state" / "autonomous" / "raw"
    )
    cache_file = resolved_cache_dir / f"{stream_id}.json"

    if offline:
        if cache_file.exists():
            try:
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
                cached_items = cached.get("items", []) if isinstance(cached, dict) else []
                filtered_cached = filter_scout_items(
                    cached_items,
                    recency_days=recency_days,
                    max_releases_per_repo=max_releases_per_repo,
                    skip_prereleases=skip_prereleases,
                    now_utc=now_utc,
                )
                safe_items = [it for it in filtered_cached if not it.get("ipi_flagged")]
                ipi_blocked = len(filtered_cached) - len(safe_items)
                return {
                    "stream_id": stream_id,
                    "mode": "OFFLINE_CACHE",
                    "fetched_at": cached.get("fetched_at", fetched_at) if isinstance(cached, dict) else fetched_at,
                    "items": safe_items,
                    "errors": [],
                    "ipi_blocked_count": ipi_blocked,
                }
            except Exception as exc:
                return {
                    "stream_id": stream_id,
                    "mode": "OFFLINE_EMPTY",
                    "fetched_at": fetched_at,
                    "items": [],
                    "errors": [f"Cache read error: {exc}"],
                    "ipi_blocked_count": 0,
                }
        return {
            "stream_id": stream_id,
            "mode": "OFFLINE_EMPTY",
            "fetched_at": fetched_at,
            "items": [],
            "errors": [],
            "ipi_blocked_count": 0,
        }

    streams = active_policy.get("streams", {}) if isinstance(active_policy, dict) else {}
    stream_cfg = streams.get(stream_id, {}) if isinstance(streams, dict) else {}
    sources = stream_cfg.get("sources", []) if isinstance(stream_cfg, dict) else []

    all_items: list[dict[str, Any]] = []
    errors: list[str] = []

    if sources:
        with ThreadPoolExecutor(max_workers=6) as executor:
            future_map = {
                executor.submit(
                    _fetch_source_feed,
                    src,
                    stream_id,
                    timeout,
                    recency_days=recency_days,
                    max_releases_per_repo=max_releases_per_repo,
                    skip_prereleases=skip_prereleases,
                ): src
                for src in sources
                if isinstance(src, dict)
                and str(src.get("type", "")).strip().lower() != "local"
                and str(src.get("url", "")).strip().startswith(("http://", "https://"))
            }
            for fut in as_completed(future_map):
                src = future_map[fut]
                src_name = src.get("name", src.get("url", "unknown"))
                try:
                    items = fut.result()
                    all_items.extend(items)
                except Exception as exc:
                    errors.append(f"{src_name}: {exc}")

    safe_items = [it for it in all_items if not it.get("ipi_flagged")]
    ipi_blocked_count = len(all_items) - len(safe_items)

    result_payload = {
        "stream_id": stream_id,
        "mode": "LIVE",
        "fetched_at": fetched_at,
        "items": safe_items,
        "errors": errors,
        "ipi_blocked_count": ipi_blocked_count,
    }

    try:
        resolved_cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(
            json.dumps(result_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception as exc:
        errors.append(f"Cache write error: {exc}")

    try:
        resolved_raw_dir.mkdir(parents=True, exist_ok=True)
        raw_file = resolved_raw_dir / f"{stream_id}_{today_str}.json"
        raw_file.write_text(
            json.dumps(result_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception as exc:
        errors.append(f"Raw write error: {exc}")

    return result_payload
