"""
src/autonomous/sentinels.py — Deterministic & Proactive Sentinels.

Implements:
- S1: Local State & Schedule Watcher
- S2: Financial Runway & Kingman Capacity Sentinel
- S4: Repository Health Sentinel (AST skeleton freshness + offline pytest suite)
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
import subprocess
import sys
from typing import Any

import yaml

from src.autonomous import REPO_ROOT, load_policy


def _load_yaml_dict(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _resolve_state_file(explicit: Path | None, filename: str) -> Path:
    if explicit is not None:
        return Path(explicit)
    live_path = REPO_ROOT / "state" / filename
    if live_path.exists():
        return live_path
    return REPO_ROOT / "state.example" / filename


def run_s1_state_watcher(
    *,
    dry_run: bool = False,
    offline: bool = False,
    state_dir: Path | None = None,
) -> dict[str, Any]:
    """Inspect local state directory readiness without external side effects."""
    resolved_state_dir = (
        Path(state_dir)
        if state_dir is not None
        else ((REPO_ROOT / "state") if (REPO_ROOT / "state").exists() else (REPO_ROOT / "state.example"))
    )
    tracked = [
        name
        for name in ("current_priorities.yaml", "pillar_metrics.yaml", "DECISION_LOG.md")
        if (resolved_state_dir / name).exists()
    ]
    mode_label = "offline" if offline else ("dry_run" if dry_run else "local")
    return {
        "stream_id": "S1",
        "actionable": False,
        "new_items": [],
        "tracked_state_files": tracked,
        "summary": f"S1 ({mode_label}): {len(tracked)}/3 core state files present in {resolved_state_dir.name}/.",
    }


def run_s2_runway_sentinel(
    *,
    today: date | None = None,
    metrics_path: Path | None = None,
    priorities_path: Path | None = None,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute Financial Runway gap, Kingman capacity utilization, and calibration staleness."""
    ref_today = today or date.today()
    resolved_metrics = _resolve_state_file(metrics_path, "pillar_metrics.yaml")
    resolved_priorities = _resolve_state_file(priorities_path, "current_priorities.yaml")
    active_policy = policy if policy is not None else load_policy()

    metrics = _load_yaml_dict(resolved_metrics)
    priorities = _load_yaml_dict(resolved_priorities)

    fin_shield = metrics.get("financial_shield", {})
    if not isinstance(fin_shield, dict):
        fin_shield = {}

    fin_targets = active_policy.get("financial_targets", {})
    if not isinstance(fin_targets, dict):
        fin_targets = {}

    guardrails = active_policy.get("guardrails", {})
    if not isinstance(guardrails, dict):
        guardrails = {}

    current_runway_eur = float(fin_shield.get("current_runway_eur", 0.0))
    target_runway_eur = float(
        fin_shield.get("target_runway_eur", fin_targets.get("runway_target_eur", 10000.0))
    )
    deadline_str = str(
        fin_shield.get("target_deadline", fin_targets.get("runway_deadline", "2026-12-31"))
    )
    hardware_gate_open = bool(fin_shield.get("hardware_unlock_gate_open", False))
    staleness_threshold_days = int(guardrails.get("staleness_threshold_days", 7))

    try:
        deadline_date = date.fromisoformat(deadline_str)
    except ValueError:
        deadline_date = date(2026, 12, 31)

    days_remaining = max(0, (deadline_date - ref_today).days)
    runway_gap_eur = round(max(0.0, target_runway_eur - current_runway_eur), 2)
    weeks_remaining = max(1.0, days_remaining / 7.0)
    required_weekly_eur = round(runway_gap_eur / weeks_remaining, 2) if runway_gap_eur > 0 else 0.0

    cap_model = priorities.get("capacity_model", {})
    if not isinstance(cap_model, dict):
        cap_model = {}

    discretionary_pool = float(cap_model.get("discretionary_pool_hours", 28.0))
    cap_hours = float(cap_model.get("hard_deep_work_cap_hours", 21.0))
    committed_hours = float(cap_model.get("committed_deep_work_hours", 0.0))

    utilization_rho = round(committed_hours / discretionary_pool, 4) if discretionary_pool > 0 else 0.0
    slack_hours = round(cap_hours - committed_hours, 2)

    last_calibrated_str = str(priorities.get("last_calibrated", ref_today.isoformat()))
    try:
        last_calibrated_date = date.fromisoformat(last_calibrated_str)
    except ValueError:
        last_calibrated_date = ref_today
        last_calibrated_str = ref_today.isoformat()

    days_since_calibration = max(0, (ref_today - last_calibrated_date).days)
    is_stale = days_since_calibration > staleness_threshold_days

    actionable = bool(
        is_stale
        or slack_hours < 0
        or (runway_gap_eur > 0 and days_remaining <= 14)
    )

    summary = (
        f"Runway {current_runway_eur:.0f}/{target_runway_eur:.0f} EUR "
        f"(gap {runway_gap_eur:.0f} EUR, {days_remaining}d left, {required_weekly_eur:.0f} EUR/wk); "
        f"rho={utilization_rho:.2f}, slack={slack_hours:.1f}h; "
        f"calibrated {days_since_calibration}d ago ({'STALE' if is_stale else 'FRESH'})."
    )

    return {
        "stream_id": "S2",
        "today": ref_today.isoformat(),
        "current_runway_eur": current_runway_eur,
        "target_runway_eur": target_runway_eur,
        "runway_gap_eur": runway_gap_eur,
        "days_remaining": days_remaining,
        "required_weekly_eur": required_weekly_eur,
        "hardware_gate_open": hardware_gate_open,
        "utilization_rho": utilization_rho,
        "committed_hours": committed_hours,
        "cap_hours": cap_hours,
        "slack_hours": slack_hours,
        "last_calibrated": last_calibrated_str,
        "days_since_calibration": days_since_calibration,
        "is_stale": is_stale,
        "actionable": actionable,
        "summary": summary,
    }


def run_s4_repo_health(
    *,
    offline: bool = True,
    run_pytest: bool = True,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Check repository health: AST skeleton freshness and offline pytest suite."""
    root = Path(repo_root) if repo_root is not None else REPO_ROOT
    checks: list[dict[str, Any]] = []
    any_failed = False

    try:
        from src.skeletonizer import skeletonize_directory

        src_dir = root / "src"
        skeletons = skeletonize_directory(src_dir, extensions=(".py",), max_tokens=5000)
        syntax_errors = [
            path for path, stub in skeletons.items() if stub.startswith("# SyntaxError")
        ]
        if syntax_errors:
            any_failed = True
            checks.append(
                {
                    "name": "ast_skeleton_freshness",
                    "passed": False,
                    "detail": f"SyntaxError in: {', '.join(syntax_errors)}",
                }
            )
        else:
            checks.append(
                {
                    "name": "ast_skeleton_freshness",
                    "passed": True,
                    "detail": f"Skeletonized {len(skeletons)} Python modules cleanly.",
                }
            )
    except Exception as exc:
        any_failed = True
        checks.append(
            {
                "name": "ast_skeleton_freshness",
                "passed": False,
                "detail": f"Skeletonizer error: {exc}",
            }
        )

    if run_pytest:
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-q"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            passed = proc.returncode == 0
            if not passed:
                any_failed = True
            output_tail = (proc.stdout or proc.stderr or "").strip().splitlines()[-3:]
            checks.append(
                {
                    "name": "pytest_suite",
                    "passed": passed,
                    "detail": " | ".join(output_tail) if output_tail else f"exit={proc.returncode}",
                }
            )
        except Exception as exc:
            any_failed = True
            checks.append(
                {
                    "name": "pytest_suite",
                    "passed": False,
                    "detail": f"pytest execution error: {exc}",
                }
            )

    status = "RED" if any_failed else "GREEN"
    actionable = status == "RED"
    failed_names = [c["name"] for c in checks if not c["passed"]]
    summary = (
        f"S4 Repo Health: {status} ({len(checks)} checks"
        + (f"; failed: {', '.join(failed_names)}" if failed_names else "; all passed")
        + ")."
    )

    return {
        "stream_id": "S4",
        "offline": offline,
        "status": status,
        "actionable": actionable,
        "checks": checks,
        "summary": summary,
    }
