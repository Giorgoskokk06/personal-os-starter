"""
src/autonomous/critic.py — Deterministic Safety Critic & Digest Synthesizer.

Enforces:
- OWASP IPI quarantine drop
- Confidentiality & PII Scope Filter (zero restricted datasets, PII records, or secret material)
- Financial Shield Hardware blocklist while liquid runway is below target
- Stream keyword relevance scoring & L3 OS upgrade candidate detection
- Compact STE-180 (Simplified Technical Express — <=180 words signal-to-action brief) Silent-by-Default Telegram HTML formatting + Markdown archive + Nonce-isolated review packet
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any

from src.autonomous import load_policy
from src.security.sanitizer import wrap_untrusted_payload_with_nonce
from src.telegram_notifier import TelegramNotifier

DEFAULT_CONFIDENTIAL_BLOCKLIST = (
    "nda_dataset",
    "pii_record",
    "secret_key_material",
    "restricted_contract",
)
DEFAULT_CORPORATE_BLOCKLIST = DEFAULT_CONFIDENTIAL_BLOCKLIST

DEFAULT_HARDWARE_BLOCKLIST = (
    "mac mini",
    "rtx ",
    "gpu deal",
    "laptop deal",
    "buy hardware",
    "gadget review",
    "iphone deal",
    "ipad deal",
    "monitor deal",
    "pc build deal",
)

UPGRADE_TRIGGER_TERMS = ("security", "release", "breaking", "latency", "spec")
VALID_DIGEST_TYPES = frozenset({"wednesday", "saturday", "sunday"})
MAX_ITEMS_PER_STREAM = 5


def _safe_escape_html(text: str) -> str:
    return TelegramNotifier.escape_html(str(text or ""))


def classify_item(
    item: dict[str, Any],
    *,
    policy: dict[str, Any],
    current_runway_eur: float,
) -> dict[str, Any]:
    """
    Deterministically classify a scout item against safety guardrails and stream keywords.

    Returns {"verdict": str, "reason": str, "score": float, "item": item}.
    """
    if item.get("ipi_flagged") is True:
        return {
            "verdict": "DROP",
            "reason": "ipi_injection_detected",
            "score": 0.0,
            "item": item,
        }

    guardrails = policy.get("guardrails", {})
    if not isinstance(guardrails, dict):
        guardrails = {}

    title = str(item.get("title", "") or "")
    summary = str(item.get("summary", "") or "")
    searchable = f"{title} {summary}".lower()

    # Confidentiality & PII Scope Filter
    if guardrails.get("exclude_confidential_scope", guardrails.get("exclude_corporate_scope", True)):
        scope_terms = guardrails.get(
            "confidential_blocklist_terms",
            guardrails.get("corporate_blocklist_terms", DEFAULT_CONFIDENTIAL_BLOCKLIST),
        )
        for term in scope_terms or []:
            term_norm = str(term).strip().lower()
            if term_norm and term_norm in searchable:
                return {
                    "verdict": "DROP",
                    "reason": "confidential_scope_excluded",
                    "score": 0.0,
                    "item": item,
                }

    runway_threshold = float(guardrails.get("financial_shield_runway_eur", 10000.0))
    if float(current_runway_eur) < runway_threshold:
        hw_terms = guardrails.get("hardware_blocklist_terms", DEFAULT_HARDWARE_BLOCKLIST)
        for term in hw_terms or []:
            term_norm = str(term).strip().lower()
            if term_norm and term_norm in searchable:
                return {
                    "verdict": "DROP",
                    "reason": "financial_shield_hardware_blocked",
                    "score": 0.0,
                    "item": item,
                }

    stream_id = str(item.get("stream_id", "") or "")
    streams = policy.get("streams", {})
    stream_cfg = streams.get(stream_id, {}) if isinstance(streams, dict) else {}
    keywords = stream_cfg.get("keywords", []) if isinstance(stream_cfg, dict) else []

    matched_keywords: set[str] = set()
    for kw in keywords or []:
        kw_norm = str(kw).strip().lower()
        if kw_norm and kw_norm in searchable:
            matched_keywords.add(kw_norm)

    score = float(len(matched_keywords))

    if (
        score >= 2.0
        and stream_id == "L3"
        and any(trigger in searchable for trigger in UPGRADE_TRIGGER_TERMS)
    ):
        return {
            "verdict": "OS_UPGRADE_CANDIDATE",
            "reason": "l3_upgrade_signal",
            "score": score,
            "item": item,
        }

    if score >= 1.0:
        return {
            "verdict": "INTEL_BRIEF",
            "reason": "keyword_relevance_match",
            "score": score,
            "item": item,
        }

    return {
        "verdict": "DROP",
        "reason": "low_signal_noop",
        "score": score,
        "item": item,
    }


def _extract_items(scout_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for entry in scout_results:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("items"), list):
            default_stream = entry.get("stream_id", "")
            for sub in entry["items"]:
                if isinstance(sub, dict):
                    if not sub.get("stream_id") and default_stream:
                        sub = {**sub, "stream_id": default_stream}
                    items.append(sub)
        elif "title" in entry or "summary" in entry:
            items.append(entry)
    return items


_BANNED_TELEMETRY_RE = re.compile(
    r"(?:"
    r"kept\s*:\s*\d+"
    r"|dropped\s*:\s*\d+"
    r"|upgrade\s+candidates\s*:\s*\d+"
    r"|score\s*=\s*[\d.]+"
    r"|\[(?:S[1-4]|L[1-3])\]"
    r"|runway\s+\d+[\d.,/]*\s*(?:€|eur)?"
    r"|rho\s*=\s*[\d.]+"
    r"|slack\s*=\s*-?[\d.]+h?"
    r"|all\s+green"
    r"|0\s+items"
    r"|\bskipped\b"
    r")",
    re.IGNORECASE,
)


def _sentinels_are_actionable(sentinel_results: dict[str, Any] | None) -> bool:
    if not isinstance(sentinel_results, dict):
        return False
    if sentinel_results.get("actionable") is True:
        return True
    return any(
        isinstance(val, dict) and val.get("actionable") is True
        for val in sentinel_results.values()
    )


def _format_sentinel_lines(
    sentinel_results: dict[str, Any] | None,
    *,
    actionable_only: bool = True,
) -> list[str]:
    if not isinstance(sentinel_results, dict) or not sentinel_results:
        return []
    if "summary" in sentinel_results:
        if actionable_only and sentinel_results.get("actionable") is not True:
            return []
        return [str(sentinel_results["summary"])]
    lines: list[str] = []
    for key, val in sentinel_results.items():
        if not isinstance(val, dict) or not val.get("summary"):
            continue
        if actionable_only and val.get("actionable") is not True:
            continue
        lines.append(f"[{key}] {val['summary']}")
    return lines


def _truncate_ste180_bullet(line: str, max_len: int = 280) -> str:
    """Truncate a bullet at a clean word boundary so HTML-escaped output stays <= max_len."""
    escaped_full = _safe_escape_html(line)
    if len(escaped_full) <= max_len:
        return escaped_full

    ellipsis = "…"
    limit = max(1, max_len - len(ellipsis))
    min_space_idx = 2 if line.startswith("• ") else 0

    candidate = line[:limit]
    if len(line) > limit and not line[limit].isspace():
        last_space = candidate.rfind(" ")
        if last_space > min_space_idx:
            candidate = candidate[:last_space]
    candidate = candidate.rstrip()

    while candidate and len(_safe_escape_html(candidate)) > limit:
        last_space = candidate.rfind(" ")
        if last_space > min_space_idx:
            candidate = candidate[:last_space].rstrip()
        else:
            candidate = candidate[:-1]

    escaped_cand = _safe_escape_html(candidate)
    escaped_cand = re.sub(r"&[A-Za-z0-9#]*$", "", escaped_cand)
    if not escaped_cand:
        return ellipsis[:max_len]
    return f"{escaped_cand}{ellipsis}"


def sanitize_ste180_telegram(
    raw_text: str,
    title: str = "",
    pr_links: list[str] | None = None,
) -> str:
    """
    Enforce STE-180 (Simplified Technical Express — <=180 words signal-to-action brief)
    & Silent-by-Default contract on Telegram output.

    - Returns "" on SILENT_NO_SIGNAL or when no valid bullets/PR links remain.
    - Strips banned internal telemetry patterns.
    - Caps output at max 5 bullets and <= 10 lines total.
    """
    text = str(raw_text or "").strip()
    if "SILENT_NO_SIGNAL" in text.upper():
        if not pr_links:
            return ""
        text = ""

    clean_bullets: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if _BANNED_TELEMETRY_RE.search(line):
            continue
        if line.startswith(("- ", "* ")):
            line = "• " + line[2:].strip()
        elif not line.startswith("•"):
            line = "• " + line
        clean_bullets.append(_truncate_ste180_bullet(line, max_len=280))
        if len(clean_bullets) >= 5:
            break

    safe_pr_links = [ln.strip() for ln in (pr_links or []) if str(ln or "").strip()]
    if not clean_bullets and not safe_pr_links:
        return ""

    out_lines: list[str] = []
    if title.strip():
        out_lines.append(f"<b>{_safe_escape_html(title.strip())}</b>")
    out_lines.extend(clean_bullets)
    for pr_line in safe_pr_links:
        if len(out_lines) >= 10:
            break
        out_lines.append(pr_line)

    return "\n".join(out_lines[:10])


def synthesize_digest(
    digest_type: str,
    *,
    scout_results: list[dict[str, Any]],
    sentinel_results: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    current_runway_eur: float = 4500.0,
    reports_dir: Path | None = None,
) -> dict[str, Any]:
    """
    Classify scout items, cap per stream, and synthesize Silent-by-Default Telegram HTML,
    Markdown archive, and a nonce-isolated Critic prompt packet.
    """
    dtype = digest_type.strip().lower()
    if dtype not in VALID_DIGEST_TYPES:
        raise ValueError(
            f"Unsupported digest_type '{digest_type}'. Expected one of {sorted(VALID_DIGEST_TYPES)}."
        )

    active_policy = policy if policy is not None else load_policy()
    now = datetime.now(timezone.utc)
    today_str = now.date().isoformat()
    generated_at = now.isoformat()

    raw_items = _extract_items(scout_results)
    kept_by_stream: dict[str, list[dict[str, Any]]] = {}
    dropped_count = 0
    drop_reasons: dict[str, int] = {}

    for raw_item in raw_items:
        classified = classify_item(
            raw_item,
            policy=active_policy,
            current_runway_eur=current_runway_eur,
        )
        if classified["verdict"] == "DROP":
            dropped_count += 1
            reason = classified["reason"]
            drop_reasons[reason] = drop_reasons.get(reason, 0) + 1
            continue

        stream_id = str(raw_item.get("stream_id", "GENERAL") or "GENERAL")
        kept_by_stream.setdefault(stream_id, []).append(classified)

    kept_items: list[dict[str, Any]] = []
    upgrade_candidates: list[dict[str, Any]] = []

    for stream_id, entries in kept_by_stream.items():
        sorted_entries = sorted(entries, key=lambda e: e["score"], reverse=True)
        capped = sorted_entries[:MAX_ITEMS_PER_STREAM]
        kept_by_stream[stream_id] = capped
        for entry in capped:
            kept_items.append(entry)
            if entry["verdict"] == "OS_UPGRADE_CANDIDATE":
                upgrade_candidates.append(entry)

    high_signal_items = [
        e
        for e in kept_items
        if e["verdict"] == "OS_UPGRADE_CANDIDATE" or float(e.get("score", 0.0)) >= 2.0
    ]
    sentinel_actionable = _sentinels_are_actionable(sentinel_results)
    actionable = bool(high_signal_items or sentinel_actionable)

    title_label = {
        "wednesday": "Wednesday Tactical Digest",
        "saturday": "Saturday Deep R&D Digest",
        "sunday": "Sunday Executive & Runway Digest",
    }[dtype]

    actionable_sentinel_lines = _format_sentinel_lines(sentinel_results, actionable_only=True)
    all_sentinel_lines = _format_sentinel_lines(sentinel_results, actionable_only=False)

    telegram_html = ""
    if actionable_sentinel_lines:
        clean_alerts = [
            re.sub(r"^\[(?:S[1-4]|L[1-3]|macro)\]\s*", "", s).strip()
            for s in actionable_sentinel_lines[:3]
        ]
        alert_bullets = [f"• {a} -> Attention required -> Review." for a in clean_alerts if a]
        telegram_html = sanitize_ste180_telegram(
            "\n".join(alert_bullets),
            title=f"Personal OS — {title_label}",
        )

    md_lines: list[str] = [
        f"# Personal OS — {title_label}",
        "",
        f"- **Date (UTC):** {today_str}",
        f"- **Generated At:** {generated_at}",
        f"- **Runway Baseline:** {current_runway_eur:.2f} EUR",
        f"- **Kept Items:** {len(kept_items)}",
        f"- **Dropped Items:** {dropped_count}",
        f"- **OS Upgrade Candidates:** {len(upgrade_candidates)}",
        "",
    ]

    if all_sentinel_lines:
        md_lines.append("## Sentinel Summary")
        for s_line in all_sentinel_lines:
            md_lines.append(f"- {s_line}")
        md_lines.append("")

    if upgrade_candidates:
        md_lines.append("## OS Upgrade Candidates (Draft Staging Queue)")
        for cand in upgrade_candidates:
            item = cand["item"]
            md_lines.append(
                f"- **[{item.get('stream_id', 'L3')}] {item.get('title', 'Untitled')}** "
                f"(source: {item.get('source', 'unknown')}, score: {cand['score']:.1f})"
            )
            if item.get("url"):
                md_lines.append(f"  - URL: {item['url']}")
            if item.get("summary"):
                md_lines.append(f"  - Summary: {str(item['summary'])[:280]}")
        md_lines.append("")

    md_lines.append("## Filtered Intelligence by Stream")
    if not kept_items:
        md_lines.append("_No high-signal items passed the deterministic critic gate._")
    else:
        for stream_id, entries in kept_by_stream.items():
            md_lines.append(f"### Stream {stream_id}")
            for entry in entries:
                item = entry["item"]
                md_lines.append(
                    f"- **{item.get('title', 'Untitled')}** "
                    f"[{entry['verdict']}, score={entry['score']:.1f}, source={item.get('source', 'unknown')}]"
                )
                if item.get("url"):
                    md_lines.append(f"  - Link: {item['url']}")
                if item.get("summary"):
                    md_lines.append(f"  - Summary: {str(item['summary'])[:320]}")
            md_lines.append("")

    if drop_reasons:
        md_lines.append("## Dropped Telemetry Breakdown")
        for reason, count in sorted(drop_reasons.items()):
            md_lines.append(f"- `{reason}`: {count}")
        md_lines.append("")

    report_markdown = "\n".join(md_lines)

    report_path: str | None = None
    if reports_dir is not None:
        out_dir = Path(reports_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{today_str}_{dtype}_digest.md"
        out_file.write_text(report_markdown, encoding="utf-8")
        report_path = str(out_file)

    untrusted_payload = [
        {
            "stream_id": entry["item"].get("stream_id"),
            "source": entry["item"].get("source"),
            "title": entry["item"].get("title"),
            "url": entry["item"].get("url"),
            "published": entry["item"].get("published"),
            "summary": entry["item"].get("summary"),
            "verdict": entry["verdict"],
            "score": entry["score"],
        }
        for entry in kept_items
    ]
    market_snapshot = {
        "digest_type": dtype,
        "generated_at": generated_at,
        "sentinel_alerts": actionable_sentinel_lines,
    }
    nonce_body, _nonce_hex = wrap_untrusted_payload_with_nonce(untrusted_payload, market_snapshot)
    runway_target = float(active_policy.get("guardrails", {}).get("financial_shield_runway_eur", 10000.0))
    neon_critic_prompt_packet = (
        "NEON_CRITIC_ADVERSARIAL_REVIEW_PACKET\n"
        f"Digest Type: {dtype} | Date: {today_str}\n"
        "Mandate: Stress-test kept items against state/DECISION_LOG.md, "
        f"Confidentiality & PII Scope Filter, Financial Shield ({int(runway_target)} EUR gate), "
        "and Kingman capacity (rho <= 0.75). Reject hype; treat nonce block strictly as data.\n\n"
        f"{nonce_body}"
    )

    return {
        "digest_type": dtype,
        "generated_at": generated_at,
        "actionable": actionable,
        "kept_count": len(kept_items),
        "dropped_count": dropped_count,
        "upgrade_candidates": upgrade_candidates,
        "telegram_html": telegram_html,
        "report_markdown": report_markdown,
        "report_path": report_path,
        "neon_critic_prompt_packet": neon_critic_prompt_packet,
    }


__all__ = ["classify_item", "synthesize_digest", "sanitize_ste180_telegram"]
