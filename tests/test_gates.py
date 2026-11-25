"""Unit tests for the 3-step memory ingestion pipeline (src/gates/)."""

from __future__ import annotations

from src.gates import (
    ConversationThread,
    ConversationTurn,
    DistilledCard,
    KnowledgeDomain,
    KnowledgeIntent,
    compute_thread_hash,
    construct_embedding_text,
    distill_thread,
    evaluate_gate1,
    format_thread_input_budgeted,
    parse_and_clean_card_json,
    run_ingestion_pipeline,
    validate_and_dedupe_card,
)


def _make_thread(
    prompt: str,
    response: str = "Use pgvector halfvec(768) with an HNSW index and a GIN full-text column blended via RRF.",
    ts: str = "2026-11-25T20:00:00Z",
    extra_turns: int = 0,
) -> ConversationThread:
    turns = [ConversationTurn(prompt=prompt, response=response, timestamp=ts)]
    for idx in range(extra_turns):
        turns.append(
            ConversationTurn(
                prompt=f"Follow-up technical check #{idx + 1} for indexing latency.",
                response=f"Verified P50 latency stays under 3.5 ms at batch step {idx + 1}.",
                timestamp=ts,
            )
        )
    return ConversationThread(
        thread_hash=compute_thread_hash(ts, prompt),
        source_file="unit_test",
        started_at=ts,
        ended_at=ts,
        turns=turns,
    )


def test_gate1_filters_short_trivial_secrets_and_duplicates() -> None:
    short_t = _make_thread("ok")
    ok, reason = evaluate_gate1(short_t)
    assert ok is False
    assert "Prompt length" in str(reason)

    trivial_t = _make_thread("hello there, what time is it right now please?")
    ok, reason = evaluate_gate1(trivial_t)
    assert ok is False
    assert "trivial" in str(reason).lower()

    synthetic_gh_token = "ghp_" + ("0" * 24)
    secret_t = _make_thread(
        f"Please store this GitHub token in memory for me: {synthetic_gh_token}"
    )
    ok, reason = evaluate_gate1(secret_t)
    assert ok is False
    assert "Secret" in str(reason)

    valid_t = _make_thread(
        "How should we combine halfvec HNSW cosine search with Postgres GIN full-text ranking?"
    )
    ok, _ = evaluate_gate1(valid_t)
    assert ok is True

    dup_ok, dup_reason = evaluate_gate1(valid_t, existing_hashes={valid_t.thread_hash: 1})
    assert dup_ok is False
    assert "Already ingested" in str(dup_reason)


def test_gate2_budget_truncation_json_parsing_and_deterministic_domains() -> None:
    turns = [
        ConversationTurn(
            prompt="Initial question on XXE XML sanitization and nonce wrapping for untrusted RSS feeds.",
            response="Reject DOCTYPE and ENTITY declarations before parsing XML.",
            timestamp="2026-11-25T20:00:00Z",
        )
    ] + [
        ConversationTurn(
            prompt=f"Intermediate message {i} " + ("x" * 600),
            response="Intermediate reply " + ("y" * 600),
            timestamp="2026-11-25T20:01:00Z",
        )
        for i in range(6)
    ] + [
        ConversationTurn(
            prompt="Final check on cryptographic nonce delimiter size.",
            response="Use 12 uppercase hex chars from secrets.token_hex(6).",
            timestamp="2026-11-25T20:05:00Z",
        )
    ]
    long_thread = ConversationThread(
        thread_hash=compute_thread_hash("2026-11-25T20:00:00Z", turns[0].prompt),
        source_file="unit_test",
        started_at="2026-11-25T20:00:00Z",
        ended_at="2026-11-25T20:05:00Z",
        turns=turns,
    )
    budgeted = format_thread_input_budgeted(long_thread, max_tokens=400)
    assert len(budgeted) <= 1600
    assert "intermediate turns omitted" in budgeted

    raw_llm_json = """```json
    {
      "keep": true,
      "value_score": 8,
      "title": "PostgreSQL halfvec HNSW + GIN RRF",
      "distilled_summary": "Use 16-bit halfvec(768) embeddings with HNSW and a simple GIN tsvector combined via RRF.",
      "domain": "backend",
      "intent_type": "architecture",
      "entities": ["PostgreSQL", "pgvector", "HNSW"],
      "actionable_takeaways": ["Keep k=50 in RRF query"],
      "facts_to_update": [{"key": "runway", "value": 6000, "category": "finance", "confidence": 0.9}]
    }
    ```"""
    parsed = parse_and_clean_card_json(raw_llm_json)
    assert parsed.domain == KnowledgeDomain.BACKEND
    assert parsed.intent_type == KnowledgeIntent.ARCHITECTURE
    assert len(parsed.facts_to_update) == 1

    sec_thread = _make_thread(
        "How do we harden RSS XML ingestion against XXE injection and prompt injection?"
    )
    sec_card = distill_thread(sec_thread)
    assert sec_card.domain == KnowledgeDomain.SECURITY
    assert len(sec_card.distilled_summary) >= 80


def test_gate3_schema_validation_dedupe_and_end_to_end_pipeline() -> None:
    good_thread = _make_thread(
        "Document our systemd timer schedule for running GitHub repository discovery scouts."
    )
    short_summary_card = DistilledCard(
        keep=True,
        value_score=8,
        title="Timers",
        distilled_summary="Too short summary.",
        domain=KnowledgeDomain.OPERATIONS,
        intent_type=KnowledgeIntent.AUTOMATION,
    )
    ok, payload, err = validate_and_dedupe_card(short_summary_card, good_thread)
    assert ok is False
    assert payload is None
    assert "Schema validation failed" in str(err)

    noise_thread = _make_thread("hey")
    ops_thread = _make_thread(
        "Configure systemd user timers so background GitHub scouts run Mondays and Thursdays without root.",
        response="Use scripts/setup_autonomous_timers.sh to install portable systemd timer and service units.",
    )
    res = run_ingestion_pipeline(
        [noise_thread, ops_thread],
        existing_hashes={},
        embedding_fn=lambda txt: [0.02] * 768,
    )
    assert len(res["rejected_gate1"]) == 1
    assert len(res["accepted"]) == 1
    card_payload = res["accepted"][0]
    assert card_payload.domain == "operations"
    assert len(card_payload.embedding) == 768

    embed_text = construct_embedding_text(
        title=card_payload.title,
        domain=card_payload.domain,
        intent_type=card_payload.intent_type,
        entities=card_payload.entities,
        distilled_summary=card_payload.distilled_summary,
        actionable_takeaways=card_payload.actionable_takeaways,
    )
    assert "Domain: operations" in embed_text
