"""
src/autonomous/staging_gate.py — Draft PR Staging Gate & Verification Runner.

Hard invariants:
- auto_merge_main MUST be False (otherwise HARD_BLOCK).
- Branch MUST start with "autonomous/draft-" (never main/master).
- Candidate verdict MUST be "OS_UPGRADE_CANDIDATE".
- Weekly Draft PR cap (default 2 per ISO calendar week) tracked via fcntl.flock.
- Failures are recorded silently to staging_log.json (NEVER sent to Telegram).
"""

from __future__ import annotations

import fcntl
import json
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from src.autonomous import REPO_ROOT, load_policy

DEFAULT_LEDGER_PATH = REPO_ROOT / "state" / ".autonomous_pr_ledger.json"
DEFAULT_LOG_PATH = REPO_ROOT / "state" / "autonomous" / "staging_log.json"


class StagingGate:
    """Enforces autonomous draft-PR safety gates, weekly caps, and silent failure logging."""

    def __init__(
        self,
        policy: dict[str, Any] | None = None,
        ledger_path: Path | None = None,
        log_path: Path | None = None,
    ) -> None:
        self.policy = policy if policy is not None else load_policy()
        self.ledger_path = Path(ledger_path) if ledger_path is not None else DEFAULT_LEDGER_PATH
        self.log_path = Path(log_path) if log_path is not None else DEFAULT_LOG_PATH

    @staticmethod
    def _iso_week_key(ref_date: date) -> tuple[int, int]:
        iso = ref_date.isocalendar()
        return (int(iso[0]), int(iso[1]))

    @staticmethod
    def _read_json_unlocked(file_obj: Any, default_key: str) -> dict[str, Any]:
        file_obj.seek(0)
        raw = file_obj.read().strip()
        if not raw:
            return {default_key: []}
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and isinstance(data.get(default_key), list):
                return data
            if isinstance(data, list):
                return {default_key: data}
        except json.JSONDecodeError:
            pass
        return {default_key: []}

    @staticmethod
    def _write_json_unlocked(file_obj: Any, payload: dict[str, Any]) -> None:
        file_obj.seek(0)
        file_obj.truncate()
        json.dump(payload, file_obj, ensure_ascii=False, indent=2)
        file_obj.flush()

    def get_prs_this_week(self, today: date | None = None) -> list[dict[str, Any]]:
        """Return all recorded autonomous Draft PRs created in the target ISO calendar week."""
        ref_date = today or datetime.now(timezone.utc).date()
        target_week = self._iso_week_key(ref_date)

        if not self.ledger_path.exists():
            return []

        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ledger_path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
            try:
                ledger = self._read_json_unlocked(fh, "prs")
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

        matching: list[dict[str, Any]] = []
        for entry in ledger.get("prs", []):
            if not isinstance(entry, dict):
                continue
            iso_year = entry.get("iso_year")
            iso_week = entry.get("iso_week")
            if isinstance(iso_year, int) and isinstance(iso_week, int):
                if (iso_year, iso_week) == target_week:
                    matching.append(entry)
                continue
            created_raw = entry.get("created_date")
            if isinstance(created_raw, str):
                try:
                    parsed = date.fromisoformat(created_raw[:10])
                    if self._iso_week_key(parsed) == target_week:
                        matching.append(entry)
                except ValueError:
                    continue
        return matching

    def validate_candidate(
        self,
        *,
        branch_name: str,
        candidate: dict[str, Any],
        today: date | None = None,
    ) -> dict[str, Any]:
        """Validate a staging PR candidate against non-negotiable guardrails and weekly caps."""
        guardrails = self.policy.get("guardrails", {})
        if not isinstance(guardrails, dict):
            guardrails = {}

        max_per_week = int(guardrails.get("max_draft_prs_per_week", 2))
        prs_this_week = self.get_prs_this_week(today=today)
        pr_count = len(prs_this_week)

        def _block(reason: str) -> dict[str, Any]:
            return {
                "allowed": False,
                "status": "HARD_BLOCK",
                "reason": reason,
                "prs_this_week": pr_count,
                "max_per_week": max_per_week,
            }

        if guardrails.get("auto_merge_main", True) is not False:
            return _block("auto_merge_main_must_be_false")

        if branch_name in {"main", "master"} or not branch_name.startswith("autonomous/draft-"):
            return _block("invalid_staging_branch_name")

        if candidate.get("verdict") != "OS_UPGRADE_CANDIDATE":
            return _block("candidate_not_os_upgrade_verdict")

        if pr_count >= max_per_week:
            return _block("weekly_draft_pr_cap_reached")

        return {
            "allowed": True,
            "status": "ALLOWED",
            "reason": "passed_all_staging_gates",
            "prs_this_week": pr_count,
            "max_per_week": max_per_week,
        }

    def record_pr_created(
        self,
        *,
        branch_name: str,
        pr_url: str,
        title: str,
        today: date | None = None,
    ) -> dict[str, Any]:
        """Record a newly opened Draft PR into the flock-protected weekly ledger."""
        ref_date = today or datetime.now(timezone.utc).date()
        iso_year, iso_week = self._iso_week_key(ref_date)

        record = {
            "branch_name": branch_name,
            "pr_url": pr_url,
            "title": title,
            "created_date": ref_date.isoformat(),
            "iso_year": iso_year,
            "iso_week": iso_week,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }

        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ledger_path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                ledger = self._read_json_unlocked(fh, "prs")
                ledger["prs"].append(record)
                self._write_json_unlocked(fh, ledger)
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

        return record

    def record_fail_silent(
        self,
        *,
        branch_name: str,
        failed_step: str,
        detail: str,
    ) -> dict[str, Any]:
        """Log a staging failure to staging_log.json without ever sending a Telegram alert."""
        entry = {
            "branch_name": branch_name,
            "failed_step": failed_step,
            "detail": detail,
            "notified_telegram": False,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                log_data = self._read_json_unlocked(fh, "failures")
                log_data["failures"].append(entry)
                self._write_json_unlocked(fh, log_data)
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

        return {
            "recorded": True,
            "notified_telegram": False,
            "branch_name": branch_name,
            "failed_step": failed_step,
        }

    def run_verification_gate(
        self,
        *,
        worktree_path: Path | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Execute (or dry-run plan) the mandatory repository verification gate."""
        cwd = Path(worktree_path) if worktree_path is not None else REPO_ROOT
        checks: list[tuple[str, list[str]]] = [
            ("pytest -v", [sys.executable, "-m", "pytest", "-v"]),
            ("python3 scripts/audit_public.py", [sys.executable, "scripts/audit_public.py"]),
        ]
        planned_commands = [label for label, _ in checks]

        if dry_run:
            return {
                "passed": True,
                "dry_run": True,
                "worktree_path": str(cwd),
                "planned_commands": planned_commands,
                "results": [],
            }

        results: list[dict[str, Any]] = []
        for label, cmd in checks:
            proc = subprocess.run(
                cmd,
                cwd=str(cwd),
                capture_output=True,
                text=True,
                check=False,
            )
            step_result = {
                "command": label,
                "returncode": proc.returncode,
                "passed": proc.returncode == 0,
                "stdout_tail": (proc.stdout or "").strip().splitlines()[-5:],
                "stderr_tail": (proc.stderr or "").strip().splitlines()[-5:],
            }
            results.append(step_result)
            if proc.returncode != 0:
                return {
                    "passed": False,
                    "dry_run": False,
                    "worktree_path": str(cwd),
                    "planned_commands": planned_commands,
                    "failed_command": label,
                    "results": results,
                }

        return {
            "passed": True,
            "dry_run": False,
            "worktree_path": str(cwd),
            "planned_commands": planned_commands,
            "results": results,
        }


__all__ = ["StagingGate", "DEFAULT_LEDGER_PATH", "DEFAULT_LOG_PATH"]
