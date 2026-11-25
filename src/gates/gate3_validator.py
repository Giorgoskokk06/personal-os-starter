"""Gate 3: Schema validation, length checks, and deduplication before database insert."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from src.gates.gate1_heuristics import ConversationThread


class KnowledgeDomain(str, Enum):
    SYSTEMS = "systems"
    BACKEND = "backend"
    SECURITY = "security"
    OPERATIONS = "operations"
    RESEARCH = "research"
    GENERAL = "general"
    NOISE = "noise"


class KnowledgeIntent(str, Enum):
    ARCHITECTURE = "architecture"
    DEBUGGING = "debugging"
    AUTOMATION = "automation"
    DECISION = "decision"
    REFERENCE = "reference"
    TRIVIAL = "trivial"


VALID_DB_DOMAINS = {
    KnowledgeDomain.SYSTEMS.value,
    KnowledgeDomain.BACKEND.value,
    KnowledgeDomain.SECURITY.value,
    KnowledgeDomain.OPERATIONS.value,
    KnowledgeDomain.RESEARCH.value,
    KnowledgeDomain.GENERAL.value,
}

VALID_DB_INTENTS = {
    KnowledgeIntent.ARCHITECTURE.value,
    KnowledgeIntent.DEBUGGING.value,
    KnowledgeIntent.AUTOMATION.value,
    KnowledgeIntent.DECISION.value,
    KnowledgeIntent.REFERENCE.value,
}


class DistilledCard(BaseModel):
    """Structured output returned by Gate 2 distillation."""

    keep: bool
    value_score: int = Field(ge=1, le=10)
    title: str = Field(default="")
    distilled_summary: str = Field(default="")
    domain: KnowledgeDomain
    intent_type: KnowledgeIntent
    entities: List[str] = Field(default_factory=list)
    actionable_takeaways: List[str] = Field(default_factory=list)
    facts_to_update: List[Dict[str, Any]] = Field(default_factory=list)
    rejection_reason: Optional[str] = None

    @field_validator("title", "distilled_summary", mode="before")
    @classmethod
    def normalize_null_strings(cls, v: Any) -> str:
        return "" if v is None else str(v)


class KnowledgeCardPayload(BaseModel):
    """Validated Gate 3 record ready for PostgreSQL pgvector insertion."""

    thread_hash: str
    source_file: str
    started_at: datetime
    ended_at: datetime
    turn_count: int = Field(ge=1)
    title: str = Field(min_length=3, max_length=200)
    distilled_summary: str = Field(min_length=80)
    domain: str
    intent_type: str
    value_score: int = Field(ge=6, le=10)
    entities: List[str] = Field(default_factory=list)
    actionable_takeaways: List[str] = Field(default_factory=list)
    raw_turns: List[Dict[str, Any]] = Field(default_factory=list)
    embedding: List[float] = Field(min_length=768, max_length=768)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        if v not in VALID_DB_DOMAINS:
            raise ValueError(f"Invalid database domain '{v}'. Allowed: {sorted(VALID_DB_DOMAINS)}")
        return v

    @field_validator("intent_type")
    @classmethod
    def validate_intent(cls, v: str) -> str:
        if v not in VALID_DB_INTENTS:
            raise ValueError(f"Invalid database intent '{v}'. Allowed: {sorted(VALID_DB_INTENTS)}")
        return v

    @model_validator(mode="after")
    def validate_dates(self) -> "KnowledgeCardPayload":
        if self.started_at > self.ended_at:
            self.ended_at = self.started_at
        return self


def construct_embedding_text(
    title: str,
    domain: str,
    intent_type: str,
    entities: List[str],
    distilled_summary: str,
    actionable_takeaways: List[str],
) -> str:
    """Build deterministic canonical text passed to the embedding model."""
    entities_str = ", ".join(entities) if entities else "None"
    takeaways_str = " ; ".join(actionable_takeaways) if actionable_takeaways else "None"
    return (
        f"Title: {title}\n"
        f"Domain: {domain} | Intent: {intent_type}\n"
        f"Entities: {entities_str}\n"
        f"Summary: {distilled_summary}\n"
        f"Takeaways: {takeaways_str}"
    )


def _parse_iso_dt(raw: str) -> datetime:
    cleaned = raw.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(cleaned)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def validate_and_dedupe_card(
    card: DistilledCard,
    thread: ConversationThread,
    *,
    existing_hashes: Optional[Dict[str, int]] = None,
    embedding: Optional[List[float]] = None,
) -> Tuple[bool, Optional[KnowledgeCardPayload], Optional[str]]:
    """
    Validate Gate 2 output against schema bounds, summary length, and duplicate hashes
    before sending a row to the database.
    """
    if not card.keep or card.value_score < 6 or card.domain == KnowledgeDomain.NOISE:
        return False, None, card.rejection_reason or "Rejected by Gate 2 score/keep threshold"

    if existing_hashes and thread.thread_hash in existing_hashes:
        if thread.turn_count <= existing_hashes[thread.thread_hash]:
            return False, None, f"Duplicate thread_hash {thread.thread_hash[:12]}"

    vector = embedding if embedding is not None else [0.0] * 768
    try:
        payload = KnowledgeCardPayload(
            thread_hash=thread.thread_hash,
            source_file=thread.source_file,
            started_at=_parse_iso_dt(thread.started_at),
            ended_at=_parse_iso_dt(thread.ended_at),
            turn_count=max(1, thread.turn_count),
            title=card.title.strip(),
            distilled_summary=card.distilled_summary.strip(),
            domain=card.domain.value,
            intent_type=card.intent_type.value,
            value_score=card.value_score,
            entities=card.entities,
            actionable_takeaways=card.actionable_takeaways,
            raw_turns=[t.to_dict() for t in thread.turns],
            embedding=vector,
        )
        return True, payload, None
    except ValidationError as exc:
        return False, None, f"Schema validation failed: {exc.errors()[0].get('msg', str(exc))}"
