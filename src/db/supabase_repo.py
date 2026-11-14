"""Clean Supabase PostgreSQL + pgvector RRF repository wrapper."""

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from supabase import Client, create_client

logger = logging.getLogger(__name__)


class KnowledgeCardPayload(BaseModel):
    """Schema for upserting distilled knowledge cards into public.knowledge_cards."""

    thread_hash: str
    source_file: str = "micro_ingestion"
    started_at: datetime
    ended_at: datetime
    turn_count: int = 1
    title: str
    distilled_summary: str
    domain: str = "general_tech"
    intent_type: str = "reference_knowledge"
    value_score: int = Field(default=8, ge=6, le=10)
    entities: List[str] = Field(default_factory=list)
    actionable_takeaways: List[str] = Field(default_factory=list)
    raw_turns: List[Dict[str, Any]] = Field(default_factory=list)
    embedding: List[float]


def get_supabase_client(url: Optional[str] = None, key: Optional[str] = None) -> Client:
    """Initializes and returns a Supabase client with PostgREST root auto-detection."""
    sb_url = url or os.environ.get("SUPABASE_URL", "")
    sb_key = (
        key
        or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        or os.environ.get("SUPABASE_KEY", "")
    )
    if not sb_url or not sb_key:
        raise ValueError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be configured")

    client = create_client(sb_url, sb_key)

    # Auto-detect whether PostgREST is mounted at root (local) or /rest/v1 (cloud)
    try:
        import httpx
        from yarl import URL

        clean_url = sb_url.rstrip("/")
        resp = httpx.get(f"{clean_url}/rest/v1/", timeout=1.0)
        if resp.status_code == 404 or "PGRST125" in resp.text:
            client.postgrest.base_url = URL(clean_url)
    except Exception:
        pass

    return client


class SupabaseRepo:
    """Repository for hybrid RRF search and idempotent knowledge card persistence."""

    def __init__(
        self,
        client: Optional[Client] = None,
        url: Optional[str] = None,
        key: Optional[str] = None,
    ):
        self.client = client if client else get_supabase_client(url, key)

    def fetch_existing_hashes(self, thread_hashes: List[str]) -> Dict[str, int]:
        """Batch query to check existing thread hashes and their turn_count."""
        if not thread_hashes:
            return {}

        try:
            results: Dict[str, int] = {}
            chunk_size = 100
            for i in range(0, len(thread_hashes), chunk_size):
                chunk = thread_hashes[i : i + chunk_size]
                response = (
                    self.client.table("knowledge_cards")
                    .select("thread_hash, turn_count")
                    .in_("thread_hash", chunk)
                    .execute()
                )
                for row in response.data or []:
                    results[row["thread_hash"]] = row["turn_count"]
            return results
        except Exception as e:
            logger.error(f"Error querying existing hashes from Supabase: {e}")
            return {}

    def upsert_knowledge_cards(
        self, cards: List[KnowledgeCardPayload]
    ) -> List[Dict[str, Any]]:
        """Batch upserts KnowledgeCardPayload records into public.knowledge_cards."""
        if not cards:
            return []

        rows = [
            {
                "thread_hash": card.thread_hash,
                "source_file": card.source_file,
                "started_at": card.started_at.isoformat(),
                "ended_at": card.ended_at.isoformat(),
                "turn_count": card.turn_count,
                "title": card.title,
                "distilled_summary": card.distilled_summary,
                "domain": card.domain,
                "intent_type": card.intent_type,
                "value_score": card.value_score,
                "entities": card.entities,
                "actionable_takeaways": card.actionable_takeaways,
                "raw_turns": card.raw_turns,
                "embedding": card.embedding,
            }
            for card in cards
        ]

        try:
            response = (
                self.client.table("knowledge_cards")
                .upsert(rows, on_conflict="thread_hash")
                .execute()
            )
            return response.data or []
        except Exception as e:
            logger.error(f"Error upserting knowledge cards to Supabase: {e}")
            raise

    def match_knowledge_hybrid(
        self,
        query_text: str,
        query_embedding: Optional[List[float]] = None,
        match_count: int = 10,
        filter_domain: Optional[str] = None,
        filter_min_score: int = 6,
        full_text_weight: float = 1.0,
        semantic_weight: float = 1.5,
        rrf_k: int = 50,
    ) -> List[Dict[str, Any]]:
        """Calls match_knowledge_hybrid RPC for Reciprocal Rank Fusion retrieval."""
        params = {
            "query_text": query_text,
            "query_embedding": query_embedding,
            "match_count": match_count,
            "filter_domain": filter_domain,
            "filter_min_score": filter_min_score,
            "full_text_weight": full_text_weight,
            "semantic_weight": semantic_weight,
            "rrf_k": rrf_k,
        }
        try:
            response = self.client.rpc("match_knowledge_hybrid", params).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"Error executing match_knowledge_hybrid RPC: {e}")
            raise
