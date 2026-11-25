"""
src/autonomous/cli.py - Unified Scheduled Worker CLI.

Usage:
    python3 -m src.autonomous.cli --job <s1|s2|s3|s4|l1|l3|github-scout|scouts|wed-digest|sat-digest|sun-digest|staging-check|draft-pr-factory> [--offline] [--dry-run] [--notify] [--with-agy] [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from src.autonomous import REPO_ROOT, load_policy
from src.autonomous.agy_bridge import run_agy_draft_pr_factory, run_agy_synthesis
from src.autonomous.critic import classify_item, sanitize_ste180_telegram, synthesize_digest
from src.autonomous.scouts import filter_scout_items, run_github_scout, run_scout
from src.autonomous.sentinels import (
    run_s1_state_watcher,
    run_s2_runway_sentinel,
    run_s4_repo_health,
)
from src.autonomous.staging_gate import StagingGate
from src.telegram_notifier import TelegramNotifier

JOB_CHOICES = (
    "s1",
    "s2",
    "s3",
    "s4",
    "l1",
    "l3",
    "github-scout",
    "scouts",
    "wed-digest",
    "sat-digest",
    "sun-digest",
    "staging-check",
    "draft-pr-factory",
)

DIGEST_STREAMS: dict[str, tuple[str, ...]] = {
    "wednesday": ("S2", "S3"),
    "saturday": ("L1", "L3"),
    "sunday": (),
}


def _default_dirs() -> tuple[Path, Path, Path]:
    cache_dir = REPO_ROOT / "state" / "autonomous" / "cache"
    raw_dir = REPO_ROOT / "state" / "autonomous" / "raw"
    reports_dir = REPO_ROOT / "reports" / "autonomous"
    return cache_dir, raw_dir, reports_dir


def _run_scout_with_critic(
    stream_id: str,
    *,
    policy: dict[str, Any],
    offline: bool,
    current_runway_eur: float,
    cache_dir: Path,
    raw_dir: Path,
) -> dict[str, Any]:
    scout_res = (
        run_github_scout(
            policy=policy,
            offline=offline,
            cache_dir=cache_dir,
            raw_dir=raw_dir,
        )
        if stream_id.upper() == "GITHUB"
        else run_scout(
            stream_id,
            policy=policy,
            offline=offline,
            cache_dir=cache_dir,
            raw_dir=raw_dir,
        )
    )
    classified = [
        classify_item(item, policy=policy, current_runway_eur=current_runway_eur)
        for item in scout_res.get("items", [])
    ]
    kept = [c for c in classified if c["verdict"] != "DROP"]
    dropped = [c for c in classified if c["verdict"] == "DROP"]
    upgrades = sorted(
        [c for c in kept if c["verdict"] == "OS_UPGRADE_CANDIDATE"],
        key=lambda c: float(c.get("score", 0.0)),
        reverse=True,
    )
    briefs = [c for c in kept if c["verdict"] == "INTEL_BRIEF"]
    drop_reasons: dict[str, int] = {}
    for d in dropped:
        reason = str(d.get("reason") or "dropped")
        drop_reasons[reason] = drop_reasons.get(reason, 0) + 1
    if int(scout_res.get("ipi_blocked_count", 0)) > 0:
        drop_reasons["ipi_quarantined_layer1"] = int(scout_res["ipi_blocked_count"])

    return {
        **scout_res,
        "kept_count": len(kept),
        "dropped_count": len(dropped),
        "drop_reasons": drop_reasons,
        "dropped_items": [
            {
                "title": d["item"].get("repo_full_name") or d["item"].get("title"),
                "reason": d["reason"],
            }
            for d in dropped
        ],
        "upgrade_candidates": upgrades,
        "intel_briefs": briefs,
        "actionable": len(upgrades) > 0 if stream_id.upper() == "GITHUB" else len(kept) > 0,
        "summary": (
            f"Scout {stream_id} ({scout_res.get('mode')}): "
            f"{len(upgrades)} upgrade candidates, {len(briefs)} brief(s), "
            f"{len(dropped)} critic-dropped, {scout_res.get('ipi_blocked_count', 0)} IPI-quarantined."
            if stream_id.upper() == "GITHUB"
            else f"Scout {stream_id} ({scout_res.get('mode')}): {len(kept)} kept, {len(dropped)} dropped."
        ),
    }


def _select_digest_streams(digest_type: str, policy: dict[str, Any]) -> list[str]:
    if digest_type == "sunday":
        return []
    streams_cfg = policy.get("streams", {})
    matched: list[str] = []
    if isinstance(streams_cfg, dict):
        for sid, cfg in streams_cfg.items():
            if not isinstance(cfg, dict):
                continue
            slot = str(cfg.get("digest_slot", "")).lower()
            sources = cfg.get("sources", [])
            if slot == digest_type and isinstance(sources, list) and any(
                isinstance(s, dict) and s.get("type") != "local" for s in sources
            ):
                matched.append(str(sid))
    return matched or list(DIGEST_STREAMS[digest_type])


def _build_notification_html(job: str, result: dict[str, Any]) -> str:
    if job in {"wed-digest", "sat-digest", "sun-digest"}:
        tg_html = result.get("telegram_html")
        return str(tg_html).strip() if isinstance(tg_html, str) else ""

    if isinstance(result.get("telegram_html"), str) and result["telegram_html"].strip():
        return result["telegram_html"].strip()

    if job == "s4":
        checks = result.get("checks") or []
        failed = [
            str(c.get("name", "check"))
            for c in checks
            if isinstance(c, dict) and not c.get("passed", True)
        ]
        failed_str = ", ".join(failed) if failed else "health check"
        return sanitize_ste180_telegram(
            f"• Health check failure ({failed_str}) -> Regression risk -> Inspect pytest/AST.",
            title="Personal OS - Repo Health",
        )

    summary = str(result.get("summary") or "").strip()
    if not summary:
        return ""
    return sanitize_ste180_telegram(
        f"• {summary} -> Review -> Confirm.",
        title=f"Personal OS - {job.upper()}",
    )


def _truncate_telegram_html(text: str, max_len: int = 3900) -> str:
    if len(text) <= max_len:
        return text
    lines = text.splitlines()
    kept: list[str] = []
    current_len = 0
    footer = "\n…"
    budget = max_len - len(footer)
    for line in lines:
        added = len(line) + (1 if kept else 0)
        if current_len + added > budget:
            break
        kept.append(line)
        current_len += added
    return ("\n".join(kept) + footer) if kept else text[:budget].rstrip() + "…"


def _load_l3_items_for_pr_factory(
    *,
    policy: dict[str, Any],
    offline: bool,
    dry_run: bool,
    cache_dir: Path,
    raw_dir: Path,
) -> list[dict[str, Any]]:
    guardrails = policy.get("guardrails", {}) if isinstance(policy, dict) else {}
    if not isinstance(guardrails, dict):
        guardrails = {}
    recency_days = int(guardrails.get("recency_window_days", 14))
    max_releases = int(guardrails.get("max_releases_per_repo", 1))
    skip_prereleases = bool(guardrails.get("skip_prereleases", True))

    if raw_dir.exists():
        raw_files = sorted(raw_dir.glob("L3_*.json"), reverse=True)
        for rf in raw_files:
            try:
                data = json.loads(rf.read_text(encoding="utf-8"))
                items = data.get("items", []) if isinstance(data, dict) else []
                if isinstance(items, list) and items:
                    safe = [it for it in items if isinstance(it, dict) and not it.get("ipi_flagged")]
                    return filter_scout_items(
                        safe,
                        recency_days=recency_days,
                        max_releases_per_repo=max_releases,
                        skip_prereleases=skip_prereleases,
                        is_release_feed=True,
                    )
            except (OSError, json.JSONDecodeError):
                continue

    scout_res = run_scout(
        "L3",
        policy=policy,
        offline=offline or dry_run,
        cache_dir=cache_dir,
        raw_dir=raw_dir,
    )
    items = scout_res.get("items", [])
    return [it for it in items if isinstance(it, dict) and not it.get("ipi_flagged")]


def execute_job(
    job: str,
    *,
    offline: bool = False,
    dry_run: bool = False,
    notify: bool = False,
    with_agy: bool = False,
) -> dict[str, Any]:
    """Execute a single autonomous operations job and optionally dispatch Telegram notification."""
    policy = load_policy()
    cache_dir, raw_dir, reports_dir = _default_dirs()

    s2_snapshot = run_s2_runway_sentinel(policy=policy)
    current_runway_eur = float(s2_snapshot.get("current_runway_eur", 4500.0))

    if job == "s1":
        result = run_s1_state_watcher(dry_run=dry_run, offline=offline)
    elif job == "s2":
        result = s2_snapshot
    elif job in {"s3", "l1", "l3"}:
        result = _run_scout_with_critic(
            job.upper(),
            policy=policy,
            offline=offline,
            current_runway_eur=current_runway_eur,
            cache_dir=cache_dir,
            raw_dir=raw_dir,
        )
    elif job == "github-scout":
        result = _run_scout_with_critic(
            "GITHUB",
            policy=policy,
            offline=offline,
            current_runway_eur=current_runway_eur,
            cache_dir=cache_dir,
            raw_dir=raw_dir,
        )
    elif job == "scouts":
        stream_reports = {
            sid: _run_scout_with_critic(
                sid,
                policy=policy,
                offline=offline,
                current_runway_eur=current_runway_eur,
                cache_dir=cache_dir,
                raw_dir=raw_dir,
            )
            for sid in ("GITHUB", "S3", "L1", "L3")
        }
        all_upgrades = [
            cand
            for rep in stream_reports.values()
            for cand in rep.get("upgrade_candidates", [])
        ]
        total_kept = sum(int(rep.get("kept_count", 0)) for rep in stream_reports.values())
        total_dropped = sum(int(rep.get("dropped_count", 0)) for rep in stream_reports.values())
        result = {
            "streams": stream_reports,
            "kept_count": total_kept,
            "dropped_count": total_dropped,
            "upgrade_candidates": all_upgrades,
            "actionable": len(all_upgrades) > 0,
            "summary": (
                f"Scouts complete: {len(all_upgrades)} OS upgrade candidates, "
                f"{total_kept} kept across 4 streams ({total_dropped} dropped)."
            ),
        }
    elif job == "s4":
        result = run_s4_repo_health(offline=offline, run_pytest=not dry_run)
    elif job in {"wed-digest", "sat-digest", "sun-digest"}:
        digest_type = {
            "wed-digest": "wednesday",
            "sat-digest": "saturday",
            "sun-digest": "sunday",
        }[job]
        target_streams = _select_digest_streams(digest_type, policy)
        scout_results = [
            run_scout(
                sid,
                policy=policy,
                offline=offline,
                cache_dir=cache_dir,
                raw_dir=raw_dir,
            )
            for sid in target_streams
        ]
        sentinel_results: dict[str, Any] = {"S2": s2_snapshot}
        if digest_type == "sunday":
            sentinel_results["S1"] = run_s1_state_watcher(dry_run=dry_run, offline=offline)
            sentinel_results["S4"] = run_s4_repo_health(offline=offline, run_pytest=not dry_run)

        result = synthesize_digest(
            digest_type,
            scout_results=scout_results,
            sentinel_results=sentinel_results,
            policy=policy,
            current_runway_eur=current_runway_eur,
            reports_dir=None if dry_run else reports_dir,
        )

        report_updated = False
        pr_tg_lines: list[str] = []
        if digest_type == "saturday":
            prs_this_week = StagingGate(policy=policy).get_prs_this_week()
            result["draft_prs_this_week"] = prs_this_week
            if prs_this_week:
                result["actionable"] = True
                pr_md_lines: list[str] = ["", "## Autonomous Draft PRs This Week"]
                for pr in prs_this_week[:3]:
                    title = str(pr.get("title") or "Autonomous Draft")[:100]
                    pr_url = str(pr.get("pr_url") or "").strip()
                    branch = str(pr.get("branch_name") or "").strip()
                    esc_title = TelegramNotifier.escape_html(title)
                    if pr_url.startswith(("http://", "https://")):
                        esc_url = TelegramNotifier.escape_html(pr_url)
                        pr_tg_lines.append(
                            f'• Draft PR: <a href="{esc_url}">{esc_title}</a> -> Ready for review -> Inspect diff.'
                        )
                    else:
                        pr_tg_lines.append(
                            f"• Draft PR: {esc_title} ({TelegramNotifier.escape_html(pr_url or branch)}) -> Ready for review -> Inspect diff."
                        )
                    pr_md_lines.append(f"- **{title}** (`{branch}`): {pr_url}")

                result["report_markdown"] = result["report_markdown"].rstrip() + "\n" + "\n".join(pr_md_lines) + "\n"
                report_updated = True

        digest_title = {
            "wednesday": "Personal OS - Wednesday Digest",
            "saturday": "Personal OS - Saturday Digest",
            "sunday": "Personal OS - Sunday Digest",
        }[digest_type]

        sentinel_actionable = any(
            isinstance(v, dict) and v.get("actionable") is True
            for v in sentinel_results.values()
        )

        if with_agy and not offline:
            agy_res = run_agy_synthesis(result["neon_critic_prompt_packet"], dry_run=dry_run)
            result["agy_synthesis"] = agy_res
            if agy_res.get("used_agy") and agy_res.get("output"):
                raw_output = str(agy_res["output"]).strip()
                sanitized_tg = sanitize_ste180_telegram(
                    raw_output,
                    title=digest_title,
                    pr_links=pr_tg_lines,
                )
                result["telegram_html"] = sanitized_tg
                if not sanitized_tg and not sentinel_actionable and not pr_tg_lines:
                    result["actionable"] = False
                elif sanitized_tg:
                    result["actionable"] = True
                result["report_markdown"] = (
                    result["report_markdown"].rstrip()
                    + "\n\n## Critic Synthesis (Headless Worker)\n\n"
                    + raw_output
                    + "\n"
                )
                report_updated = True
            else:
                if pr_tg_lines and not result.get("telegram_html"):
                    result["telegram_html"] = sanitize_ste180_telegram(
                        "",
                        title=digest_title,
                        pr_links=pr_tg_lines,
                    )
                elif pr_tg_lines and result.get("telegram_html"):
                    result["telegram_html"] = _truncate_telegram_html(
                        result["telegram_html"].rstrip() + "\n" + "\n".join(pr_tg_lines)
                    )
                elif not sentinel_actionable:
                    result["telegram_html"] = ""
                    result["actionable"] = False
        else:
            if pr_tg_lines and not result.get("telegram_html"):
                result["telegram_html"] = sanitize_ste180_telegram(
                    "",
                    title=digest_title,
                    pr_links=pr_tg_lines,
                )
            elif pr_tg_lines and result.get("telegram_html"):
                result["telegram_html"] = _truncate_telegram_html(
                    result["telegram_html"].rstrip() + "\n" + "\n".join(pr_tg_lines)
                )
            elif not sentinel_actionable:
                result["telegram_html"] = ""
                result["actionable"] = False

        if report_updated and result.get("report_path") and not dry_run:
            Path(result["report_path"]).write_text(result["report_markdown"], encoding="utf-8")

    elif job == "staging-check":
        gate = StagingGate(policy=policy)
        gate_res = gate.run_verification_gate(dry_run=dry_run)
        result = {
            **gate_res,
            "actionable": False,
            "summary": (
                f"Staging verification gate: "
                f"{'DRY-RUN' if dry_run else ('PASSED' if gate_res.get('passed') else 'FAILED')}."
            ),
        }
    elif job == "draft-pr-factory":
        l3_items = _load_l3_items_for_pr_factory(
            policy=policy,
            offline=offline,
            dry_run=dry_run,
            cache_dir=cache_dir,
            raw_dir=raw_dir,
        )
        classified = [
            classify_item(item, policy=policy, current_runway_eur=current_runway_eur)
            for item in l3_items
        ]
        upgrades = sorted(
            [c for c in classified if c["verdict"] == "OS_UPGRADE_CANDIDATE"],
            key=lambda c: float(c.get("score", 0.0)),
            reverse=True,
        )
        if not upgrades:
            result = {
                "status": "noop",
                "actionable": False,
                "candidates_found": 0,
                "pr_url": None,
                "notified_telegram": False,
                "summary": "Draft PR Factory: 0 OS_UPGRADE_CANDIDATE items (NO-OP).",
            }
        else:
            top_candidate = upgrades[0]
            pr_res = run_agy_draft_pr_factory(
                top_candidate,
                gate=StagingGate(policy=policy),
                dry_run=dry_run,
            )
            result = {
                **pr_res,
                "actionable": False,
                "candidates_found": len(upgrades),
                "summary": f"Draft PR Factory ({pr_res.get('status')}): {pr_res.get('branch')}",
            }
    else:
        raise ValueError(f"Unknown job: {job}")

    notification: dict[str, Any]
    if notify:
        html_msg = _build_notification_html(job, result) if bool(result.get("actionable")) else ""
        if bool(result.get("actionable")) and html_msg.strip():
            daily_cap = int(policy.get("guardrails", {}).get("daily_telegram_cap", 6))
            notifier = TelegramNotifier(daily_cap=daily_cap)
            notification = notifier.send(
                html_msg,
                category=job,
                dry_run=dry_run,
                parse_mode="HTML",
            )
        else:
            notification = {
                "sent": False,
                "status": "skipped_not_actionable",
                "detail": "Silent-By-Default: result.actionable is False or empty STE-180 output",
            }
    else:
        notification = {
            "sent": False,
            "status": "notify_disabled",
            "detail": "--notify flag not provided",
        }

    return {
        "job": job,
        "offline": offline,
        "dry_run": dry_run,
        "notify": notify,
        "with_agy": with_agy,
        "actionable": bool(result.get("actionable", False)),
        "result": result,
        "notification": notification,
    }


def _print_human_summary(job: str, payload: dict[str, Any]) -> None:
    res = payload["result"]
    summary = res.get("summary") or f"actionable={payload['actionable']}"
    notif_status = payload["notification"].get("status")
    print(f"[{job}] {summary} (notify={notif_status})")

    upgrades = res.get("upgrade_candidates") or []
    if upgrades:
        print("\nOS Upgrade Candidates:")
        for cand in upgrades:
            it = cand.get("item", {})
            name = it.get("repo_full_name") or it.get("title") or "Candidate"
            target = cand.get("target_module") or "src/autonomous/"
            proposal = cand.get("integration_proposal") or ""
            print(f"  - {name} (score={cand.get('score')}) -> {target}")
            if proposal:
                print(f"    Proposal: {proposal}")

    dropped_items = res.get("dropped_items") or []
    if dropped_items:
        print("\nFiltered Noise / Drops:")
        for d in dropped_items:
            print(f"  - {d.get('title')} [{d.get('reason')}]")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Personal OS Autonomous Operations CLI")
    parser.add_argument("--job", required=True, choices=JOB_CHOICES, help="Autonomous job to execute")
    parser.add_argument("--offline", action="store_true", help="Disable network I/O and use local cache")
    parser.add_argument("--dry-run", action="store_true", help="Run without external side effects")
    parser.add_argument("--notify", action="store_true", help="Send Telegram notification if actionable=True")
    parser.add_argument("--with-agy", action="store_true", help="Enrich digests via headless worker synthesis")
    parser.add_argument("--json", action="store_true", help="Output structured JSON")
    args = parser.parse_args(argv)

    payload = execute_job(
        args.job,
        offline=args.offline,
        dry_run=args.dry_run,
        notify=args.notify,
        with_agy=args.with_agy,
    )

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        _print_human_summary(args.job, payload)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
