"""3-step memory ingestion pipeline (heuristics -> distiller -> schema validator)."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from src.gates.gate1_heuristics import (
    ConversationThread,
    ConversationTurn,
    compute_thread_hash,
    evaluate_gate1,
    filter_threads_gate1,
)
from src.gates.gate2_llm_distiller import (
    distill_note_deterministic,
    distill_thread,
    format_thread_input_budgeted,
    parse_and_clean_card_json,
)
from src.gates.gate3_validator import (
    DistilledCard,
    KnowledgeCardPayload,
    KnowledgeDomain,
    KnowledgeIntent,
    construct_embedding_text,
    validate_and_dedupe_card,
)


def run_ingestion_pipeline(
    threads: List[ConversationThread],
    *,
    existing_hashes: Optional[Dict[str, int]] = None,
    llm_distiller: Optional[Callable[[ConversationThread], DistilledCard]] = None,
    embedding_fn: Optional[Callable[[str], List[float]]] = None,
) -> Dict[str, Any]:
    """Run Gate 1 -> Gate 2 -> Gate 3 on a batch of threads without touching any DB."""
    passed_g1, rejected_g1 = filter_threads_gate1(threads, existing_hashes=existing_hashes)

    accepted_payloads: List[KnowledgeCardPayload] = []
    rejected_g2_g3: List[Dict[str, str]] = []

    for thread in passed_g1:
        card = distill_thread(thread, llm_distiller=llm_distiller)
        if not card.keep or card.value_score < 6:
            rejected_g2_g3.append(
                {
                    "thread_hash": thread.thread_hash,
                    "stage": "gate2",
                    "reason": card.rejection_reason or "low_value_or_dropped",
                }
            )
            continue

        embed_text = construct_embedding_text(
            title=card.title,
            domain=card.domain.value,
            intent_type=card.intent_type.value,
            entities=card.entities,
            distilled_summary=card.distilled_summary,
            actionable_takeaways=card.actionable_takeaways,
        )
        vec = embedding_fn(embed_text) if embedding_fn is not None else [0.0] * 768
        ok, payload, err = validate_and_dedupe_card(
            card,
            thread,
            existing_hashes=existing_hashes,
            embedding=vec,
        )
        if ok and payload is not None:
            accepted_payloads.append(payload)
        else:
            rejected_g2_g3.append(
                {
                    "thread_hash": thread.thread_hash,
                    "stage": "gate3",
                    "reason": err or "validation_failed",
                }
            )

    return {
        "accepted": accepted_payloads,
        "rejected_gate1": [
            {"thread_hash": th.thread_hash, "reason": reason} for th, reason in rejected_g1
        ],
        "rejected_gate2_gate3": rejected_g2_g3,
    }


__all__ = [
    "ConversationTurn",
    "ConversationThread",
    "compute_thread_hash",
    "evaluate_gate1",
    "filter_threads_gate1",
    "format_thread_input_budgeted",
    "parse_and_clean_card_json",
    "distill_note_deterministic",
    "distill_thread",
    "DistilledCard",
    "KnowledgeCardPayload",
    "KnowledgeDomain",
    "KnowledgeIntent",
    "construct_embedding_text",
    "validate_and_dedupe_card",
    "run_ingestion_pipeline",
]
