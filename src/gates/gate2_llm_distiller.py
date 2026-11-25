"""Gate 2: Structured knowledge-card and fact extraction with middle-out token budgeting."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional

from src.gates.gate1_heuristics import ConversationThread
from src.gates.gate3_validator import (
    DistilledCard,
    KnowledgeDomain,
    KnowledgeIntent,
)

SYSTEM_PROMPT = """Extract a reusable Knowledge Card from the conversation thread as valid JSON.

Scoring rules:
- 1 to 5: transient chat, generic text rewriting, or temporary syntax lookup -> keep=false, domain="noise", intent_type="trivial".
- 6 to 10: reusable technical solution, architecture decision, security fix, ops runbook, or research note -> keep=true.

Allowed domains: systems, backend, security, operations, research, general, noise.
Allowed intents: architecture, debugging, automation, decision, reference, trivial.

Also extract explicit state/metric updates (e.g. budget or capacity numbers) into `facts_to_update` as
[{"key": string, "value": json_value, "category": string, "confidence": number}].

Return JSON matching:
{
  "keep": boolean,
  "value_score": integer,
  "title": string,
  "distilled_summary": string (>= 80 chars when keep=true),
  "domain": string,
  "intent_type": string,
  "entities": [string],
  "actionable_takeaways": [string],
  "facts_to_update": [object],
  "rejection_reason": string or null
}"""


def parse_and_clean_card_json(raw_text: str) -> DistilledCard:
    """Parse raw model output into DistilledCard, stripping markdown code fences."""
    clean_text = (raw_text or "").strip()
    clean_text = re.sub(r"^```(?:json)?\s*", "", clean_text)
    clean_text = re.sub(r"\s*```$", "", clean_text)

    json_match = re.search(r"\{.*\}", clean_text, re.DOTALL)
    if json_match:
        clean_text = json_match.group(0)

    parsed = json.loads(clean_text)
    if isinstance(parsed, dict):
        parsed = {
            (k.strip().strip(":").strip("'\"").strip() if isinstance(k, str) else k): v
            for k, v in parsed.items()
        }
        if "facts_to_update" in parsed and not isinstance(parsed["facts_to_update"], list):
            parsed["facts_to_update"] = []
    return DistilledCard(**parsed)


def format_thread_input_budgeted(thread: ConversationThread, max_tokens: int = 6000) -> str:
    """
    Format thread dialogue using middle-out truncation so the prompt stays <= max_tokens * 4 chars.
    Preserves metadata, the opening turn, and the final 2 turns.
    """
    max_chars = max(400, int(max_tokens) * 4)
    header = (
        f"Thread Hash: {thread.thread_hash}\n"
        f"Started: {thread.started_at}\n"
        f"Turns: {thread.turn_count}\n\n"
        "Dialogue:\n"
    )
    full_text = f"{header}{thread.full_dialogue}"
    if len(full_text) <= max_chars:
        return full_text

    turns = thread.turns
    if not turns:
        return full_text[:max_chars]

    if len(turns) <= 3:
        budget_per_turn = max(200, (max_chars - len(header) - 100) // len(turns))
        truncated = [
            f"User: {t.prompt[: budget_per_turn // 2]}\nAssistant: {t.response[: budget_per_turn // 2]}"
            for t in turns
        ]
        return (header + "\n\n".join(truncated))[:max_chars]

    first_turn = turns[0]
    first_turn_text = f"User: {first_turn.prompt}\nAssistant: {first_turn.response}"
    last_turns_text = "\n\n".join(f"User: {t.prompt}\nAssistant: {t.response}" for t in turns[-2:])

    middle_turns = turns[1:-2]
    omitted_chars = sum(len(t.prompt) + len(t.response) for t in middle_turns)
    omission_marker = f"\n[... {len(middle_turns)} intermediate turns omitted ({omitted_chars} chars) ...]\n"

    combined = f"{header}{first_turn_text}\n{omission_marker}\n{last_turns_text}"
    if len(combined) <= max_chars:
        return combined

    avail = max(300, max_chars - len(header) - len(omission_marker) - 40)
    first_clipped = f"User: {first_turn.prompt[: avail // 4]}...\nAssistant: {first_turn.response[: avail // 8]}..."
    last_clipped = last_turns_text[: avail // 2]
    return f"{header}{first_clipped}\n{omission_marker}\n{last_clipped}"[:max_chars]


def classify_domain_heuristic(text: str) -> KnowledgeDomain:
    """Classify note text into a generic technical domain."""
    t = text.lower()
    if any(k in t for k in ["xxe", "injection", "sanitizer", "nonce", "secret", "auth", "cve", "token"]):
        return KnowledgeDomain.SECURITY
    if any(k in t for k in ["postgres", "pgvector", "sql", "rpc", "fastapi", "api", "hnsw", "gin", "webhook"]):
        return KnowledgeDomain.BACKEND
    if any(k in t for k in ["systemd", "timer", "worktree", "deploy", "ci", "docker", "runbook", "sync"]):
        return KnowledgeDomain.OPERATIONS
    if any(k in t for k in ["kalman", "benchmark", "eval", "paper", "experiment", "model", "metric"]):
        return KnowledgeDomain.RESEARCH
    if any(k in t for k in ["ast", "architecture", "mcp", "concurrency", "queue", "linux", "python", "typescript"]):
        return KnowledgeDomain.SYSTEMS
    return KnowledgeDomain.GENERAL


def classify_intent_heuristic(text: str) -> KnowledgeIntent:
    """Classify note intent into a compact category."""
    t = text.lower()
    if any(k in t for k in ["error", "bug", "exception", "failed", "debug", "crash", "fix"]):
        return KnowledgeIntent.DEBUGGING
    if any(k in t for k in ["architecture", "design", "schema", "pattern", "index"]):
        return KnowledgeIntent.ARCHITECTURE
    if any(k in t for k in ["automation", "workflow", "script", "cron", "systemd", "pipeline"]):
        return KnowledgeIntent.AUTOMATION
    if any(k in t for k in ["decision", "trade-off", "tradeoff", "choose", "versus"]):
        return KnowledgeIntent.DECISION
    return KnowledgeIntent.REFERENCE


def extract_facts_heuristic(text: str) -> List[Dict[str, Any]]:
    """Extract simple numeric state updates (e.g. runway or weekly hour caps) from text."""
    facts: List[Dict[str, Any]] = []
    t = text.lower()

    runway_match = re.search(r"\brunway\D{0,20}(\d{3,6}(?:\.\d{1,2})?)\s*(?:eur)?", t)
    if runway_match:
        facts.append(
            {
                "key": "current_runway_eur",
                "value": {"value": float(runway_match.group(1)), "unit": "EUR"},
                "category": "finance",
                "confidence": 0.9,
            }
        )

    cap_match = re.search(r"\bweekly\s+cap\D{0,15}(\d{1,2}(?:\.\d{1,2})?)\s*h", t)
    if cap_match:
        facts.append(
            {
                "key": "hard_deep_work_cap_hours",
                "value": {"value": float(cap_match.group(1)), "unit": "hours"},
                "category": "operations",
                "confidence": 0.85,
            }
        )
    return facts


def distill_note_deterministic(thread: ConversationThread) -> DistilledCard:
    """Zero-cost deterministic fallback distiller used when no remote LLM distiller is supplied."""
    first_turn = thread.turns[0] if thread.turns else None
    first_prompt = first_turn.prompt.strip() if first_turn else "Technical conversation note"
    first_response = first_turn.response.strip() if first_turn else ""
    all_text = " ".join(f"{t.prompt} {t.response}" for t in thread.turns)

    clean_prompt = first_prompt.replace("#", "").strip().splitlines()[0]
    title = clean_prompt[:80].strip() or "Captured technical note"

    parts = []
    if clean_prompt:
        parts.append(f"Topic: {clean_prompt[:140]}")
    if first_response:
        clean_resp = first_response.replace("#", "").replace("*", "").strip().splitlines()[0]
        parts.append(f"Resolution: {clean_resp[:220]}")
    summary = ". ".join(parts)
    if len(summary) < 80:
        summary += " - Captured by deterministic fallback distiller for local hybrid memory indexing."

    entities = list(dict.fromkeys(re.findall(r"\b[A-Za-z0-9_.-]{3,}\b", all_text)))[:6]
    takeaways = [t.response.replace("#", "").strip()[:120] for t in thread.turns[:3] if t.response.strip()]
    if not takeaways:
        takeaways = [title]

    return DistilledCard(
        keep=True,
        value_score=7,
        title=title,
        distilled_summary=summary,
        domain=classify_domain_heuristic(all_text),
        intent_type=classify_intent_heuristic(all_text),
        entities=entities,
        actionable_takeaways=takeaways,
        facts_to_update=extract_facts_heuristic(all_text),
        rejection_reason=None,
    )


def distill_thread(
    thread: ConversationThread,
    *,
    llm_distiller: Optional[Callable[[ConversationThread], DistilledCard]] = None,
    allow_deterministic_fallback: bool = True,
) -> DistilledCard:
    """Run Gate 2 distillation using an injected LLM distiller or deterministic fallback."""
    if llm_distiller is not None:
        return llm_distiller(thread)
    if allow_deterministic_fallback:
        return distill_note_deterministic(thread)
    raise RuntimeError("No llm_distiller configured and deterministic fallback disabled.")
