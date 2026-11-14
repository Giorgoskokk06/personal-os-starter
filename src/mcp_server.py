#!/usr/bin/env python3
"""
src/mcp_server.py — Personal OS Starter FastMCP Server
Exposes 7 core memory & deterministic guard tools over stdio:
1. query_hybrid_memory: Sub-3.5ms RRF hybrid memory retrieval in pipe-delimited wire format.
2. ingest_micro_card: Real-time micro-ingestion into public.knowledge_cards with SHA-256 dedup.
3. verify_capacity_slack: Kingman Capacity Guard (rho <= 0.75 spare-time weekly cap).
4. check_runway_gate: Financial Shield Gate (target runway guard before capex purchases).
5. get_active_facts: Evolving Fact Layer with in-memory TTL cache.
6. edit_capacity_allocation: Core memory edit with Kingman Guard & OCC cloud sync.
7. log_decision_mirror: 4-part Cognitive Mirror decision logger + high-value card ingestion.
"""

import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from dotenv import load_dotenv
from fastmcp import FastMCP

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

load_dotenv(REPO_ROOT / ".env")

STATE_DIR = REPO_ROOT / "state"

mcp = FastMCP(name="personal-os-brain")

_yaml_cache: Dict[Path, tuple[float, Any]] = {}
_supabase_client: Optional[Any] = None
create_client = None


def _read_yaml_cached(file_path: Path) -> Any:
    mtime = file_path.stat().st_mtime
    if file_path in _yaml_cache:
        cached_mtime, cached_data = _yaml_cache[file_path]
        if cached_mtime == mtime:
            return cached_data
    with open(file_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    _yaml_cache[file_path] = (mtime, data)
    return data


def get_supabase() -> Any:
    global _supabase_client, create_client
    if _supabase_client is not None:
        return _supabase_client

    if create_client is None:
        from supabase import create_client as _cc

        create_client = _cc

    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or os.environ.get("SUPABASE_KEY")
    if not url or not key:
        raise ValueError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in environment")

    client = create_client(url, key)
    try:
        import httpx
        from yarl import URL

        clean_url = url.rstrip("/")
        resp = httpx.get(f"{clean_url}/rest/v1/", timeout=1.0)
        if resp.status_code == 404 or "PGRST125" in resp.text:
            client.postgrest.base_url = URL(clean_url)
    except Exception:
        pass

    _supabase_client = client
    return _supabase_client


VALID_DOMAINS = {
    "engineering_rd",
    "work_career",
    "personal_os_code",
    "fitness_health",
    "systems_projects",
    "career_finance",
    "personal_life",
    "general_tech",
}

DOMAIN_ALIASES = {
    "engineering": "engineering_rd",
    "academic": "engineering_rd",
    "rd": "engineering_rd",
    "systems": "systems_projects",
    "work": "work_career",
    "career": "career_finance",
    "finance": "career_finance",
    "health": "fitness_health",
    "fitness": "fitness_health",
    "personal": "personal_life",
    "system": "personal_os_code",
    "personal_os": "personal_os_code",
}

VALID_INTENTS = {
    "architecture_design",
    "debugging_troubleshooting",
    "academic_study",
    "workflow_automation",
    "decision_making",
    "personal_reflection",
    "reference_knowledge",
}


def _normalize_domain(domain: Optional[str], fallback: Optional[str] = None) -> Optional[str]:
    if not domain:
        return fallback
    cleaned = domain.strip().lower()
    if cleaned in VALID_DOMAINS:
        return cleaned
    if cleaned in DOMAIN_ALIASES:
        return DOMAIN_ALIASES[cleaned]
    return fallback


def _embed_text_if_available(text: str, is_query: bool = True) -> Optional[List[float]]:
    """Computes 768-dim embedding via Gemini API when GEMINI_API_KEY is available."""
    api_key = os.environ.get("GEMINI_API_KEY")
    sb_url = os.environ.get("SUPABASE_URL", "")
    if not api_key or "127.0.0.1" in sb_url or "localhost" in sb_url:
        return None
    try:
        import httpx

        model = os.environ.get("GEMINI_EMBEDDING_MODEL", "gemini-embedding-001")
        prefix = "task: search result | query: " if is_query else "title: micro_card | text: "
        resp = httpx.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:embedContent",
            headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
            json={
                "content": {"parts": [{"text": f"{prefix}{text[:2000]}"}]},
                "output_dimensionality": 768,
            },
            timeout=1.5,
        )
        if resp.status_code == 200:
            vals = resp.json().get("embedding", {}).get("values")
            if isinstance(vals, list) and len(vals) == 768:
                return vals
    except Exception:
        pass
    return None


@mcp.tool
def query_hybrid_memory(
    query_text: str,
    query_embedding: Optional[List[float]] = None,
    domain_filter: Optional[str] = None,
    top_k: int = 5,
) -> str:
    """Retrieves knowledge cards via match_knowledge_hybrid RRF in pipe-delimited format."""
    sb = get_supabase()
    effective_embedding = (
        query_embedding
        if (query_embedding and len(query_embedding) == 768)
        else _embed_text_if_available(query_text, is_query=True)
    )
    rpc_params: Dict[str, Any] = {
        "query_text": query_text,
        "query_embedding": effective_embedding,
        "match_count": top_k,
    }
    normalized_domain = _normalize_domain(domain_filter, fallback=None)
    if normalized_domain:
        rpc_params["filter_domain"] = normalized_domain

    res = sb.rpc("match_knowledge_hybrid", rpc_params).execute()
    rows = res.data or []

    header = "SCHEMA: id|domain|intent|rrf_score|summary"
    if not rows:
        return f"{header}\nEMPTY_RESULT"

    lines = [header]
    for r in rows:
        summary_val = r.get("summary") or r.get("distilled_summary", "")
        intent_val = r.get("intent") or r.get("intent_type", "")
        clean_summary = str(summary_val).replace("\n", " ").replace("|", "/")
        lines.append(
            f"{r.get('id')}|{r.get('domain')}|{intent_val}|"
            f"{round(float(r.get('rrf_score', 0.0)), 4)}|{clean_summary}"
        )
    return "\n".join(lines)


@mcp.tool
def ingest_micro_card(
    raw_text: str,
    domain: str,
    intent: str,
    summary: str,
    embedding: Optional[List[float]] = None,
    value_score: int = 8,
    entities: Optional[List[str]] = None,
    actionable_takeaways: Optional[List[str]] = None,
    facts_to_update: Optional[List[Dict[str, Any]]] = None,
    source_file: str = "micro_ingestion",
) -> dict:
    """Real-time micro-ingestion of decisions/notes into public.knowledge_cards with deduplication."""
    effective_raw = (raw_text or "").strip()
    effective_summary = (summary or "").strip()
    effective_source = source_file or "micro_ingestion"

    if len(effective_raw) < 40 or value_score < 6:
        return {"stored": False, "reason": "Gate 1/2 Rejected (<40 chars or value_score < 6)"}

    # Scrub verbose boilerplate phrasing on summary via local style linter
    try:
        from src.stylistics.naturalizer import purge_style_cliches

        if effective_summary:
            effective_summary = purge_style_cliches(effective_summary) or effective_summary
    except Exception:
        pass

    content_hash = hashlib.sha256(effective_raw.encode("utf-8")).hexdigest()
    now_iso = datetime.now(timezone.utc).isoformat()
    safe_domain = _normalize_domain(domain, fallback="general_tech") or "general_tech"
    safe_intent = intent if intent in VALID_INTENTS else "reference_knowledge"

    sb = get_supabase()

    # Sub-10ms thread_hash deduplication pre-check BEFORE calling embedding API
    try:
        existing_res = (
            sb.table("knowledge_cards")
            .select("id")
            .eq("thread_hash", content_hash)
            .limit(1)
            .execute()
        )
        if existing_res.data:
            return {
                "stored": True,
                "deduplicated": True,
                "content_hash": content_hash,
                "domain": safe_domain,
            }
    except Exception:
        pass

    effective_embedding = (
        embedding
        if (embedding and len(embedding) == 768)
        else (_embed_text_if_available(f"{effective_summary}\n{effective_raw}", is_query=False) or [0.0] * 768)
    )

    payload = {
        "thread_hash": content_hash,
        "source_file": effective_source,
        "started_at": now_iso,
        "ended_at": now_iso,
        "turn_count": 1,
        "title": effective_summary[:100] if effective_summary else effective_raw[:50],
        "distilled_summary": effective_summary,
        "domain": safe_domain,
        "intent_type": safe_intent,
        "value_score": value_score,
        "entities": [str(e) for e in (entities or []) if e][:20],
        "actionable_takeaways": [str(t) for t in (actionable_takeaways or []) if t][:10],
        "raw_turns": [{"prompt": effective_raw, "response": "", "timestamp": now_iso}],
        "embedding": effective_embedding,
    }

    upsert_res = sb.table("knowledge_cards").upsert(payload, on_conflict="thread_hash").execute()
    card_id = (
        upsert_res.data[0].get("id")
        if upsert_res.data and isinstance(upsert_res.data, list)
        else None
    )

    facts_upserted = 0
    for f_item in list(facts_to_update or []):
        fkey = f_item.get("key") or f_item.get("fact_key")
        fval = f_item.get("value") if "value" in f_item else f_item.get("fact_value")
        if fkey and fval is not None:
            try:
                upsert_user_fact(
                    fact_key=str(fkey),
                    fact_value=fval,
                    category=str(f_item.get("category", "general")),
                    confidence=float(f_item.get("confidence", 1.0)),
                    source_card_id=card_id,
                )
                facts_upserted += 1
            except Exception:
                pass

    return {
        "stored": True,
        "deduplicated": False,
        "content_hash": content_hash,
        "domain": safe_domain,
        "facts_upserted": facts_upserted,
    }


@mcp.tool
def verify_capacity_slack(proposed_additional_hours: float) -> dict:
    """Verifies Kingman queue capacity guard (max rho <= 0.75 against configured spare-time weekly cap)."""
    priorities_path = STATE_DIR / "current_priorities.yaml"
    data = _read_yaml_cached(priorities_path)
    cap = data["capacity_model"]
    pool = float(cap["discretionary_pool_hours"])
    committed = float(cap["committed_deep_work_hours"])
    max_rho = float(cap["max_utilization_rho"])
    hard_cap = float(cap["hard_deep_work_cap_hours"])

    new_total = round(committed + proposed_additional_hours, 2)
    new_rho = new_total / pool
    wait_multiplier = round(new_rho / max(1.0 - new_rho, 0.01), 2)

    is_allowed = (new_rho <= max_rho) and (new_total <= hard_cap)
    excess_hours = round(new_total - hard_cap, 1)

    return {
        "allowed": is_allowed,
        "current_committed_hours": committed,
        "proposed_total_hours": new_total,
        "hard_cap_hours": hard_cap,
        "new_utilization_rho": round(new_rho, 3),
        "max_allowed_rho": max_rho,
        "kingman_congestion_factor": wait_multiplier,
        "directive": (
            "APPROVED: Within Kingman queuing slack limits."
            if is_allowed
            else f"HARD_BLOCK: Exceeds weekly cap by {excess_hours}h. Remove existing work before adding."
        ),
    }


@mcp.tool
def check_runway_gate(proposed_expense_eur: float, category: str) -> dict:
    """Verifies Financial Shield Gate (liquid runway target guard before non-essential hardware spend)."""
    metrics_path = STATE_DIR / "pillar_metrics.yaml"
    data = _read_yaml_cached(metrics_path)
    fin = data["financial_shield"]
    current = float(fin["current_runway_eur"])
    target = float(fin["target_runway_eur"])
    unlocked = current >= target

    guarded_categories = {"hardware", "laptop", "workstation", "equipment", "non_essential_capex"}
    if category.lower() in guarded_categories and not unlocked:
        return {
            "approved": False,
            "deficit_eur": round(target - current, 2),
            "directive": f"HARD_BLOCK: Target runway ({int(target)} EUR) not yet locked. Non-essential hardware blocked.",
        }

    return {
        "approved": True,
        "remaining_after_expense_eur": round(current - proposed_expense_eur, 2),
        "directive": "APPROVED: Expense does not violate the Financial Shield gate.",
    }


_facts_cache: Dict[str, tuple[float, List[Dict[str, Any]]]] = {}
FACTS_CACHE_TTL_SECONDS = 30.0

VALID_FACT_CATEGORIES = {
    "finance",
    "career",
    "engineering_rd",
    "health",
    "preferences",
    "general",
}

FACT_CATEGORY_ALIASES = {
    "fitness": "health",
    "health_fitness": "health",
    "academic": "engineering_rd",
    "engineering": "engineering_rd",
    "work": "career",
    "career_finance": "career",
    "money": "finance",
    "runway": "finance",
    "personal": "general",
}


def _normalize_fact_category(category: Optional[str]) -> str:
    if not category:
        return "general"
    clean = category.strip().lower()
    if clean in VALID_FACT_CATEGORIES:
        return clean
    return FACT_CATEGORY_ALIASES.get(clean, "general")


def upsert_user_fact(
    fact_key: str,
    fact_value: Any,
    category: str = "general",
    confidence: float = 1.0,
    source_card_id: Optional[str] = None,
) -> dict:
    """Atomically stores an active fact in public.user_facts with contradiction archiving."""
    global _facts_cache
    _facts_cache.clear()

    safe_category = _normalize_fact_category(category)
    val_payload = fact_value if isinstance(fact_value, (dict, list)) else {"value": fact_value}
    sb = get_supabase()
    res = sb.rpc(
        "upsert_user_fact",
        {
            "p_fact_key": fact_key.strip(),
            "p_fact_value": val_payload,
            "p_category": safe_category,
            "p_confidence": float(confidence),
            "p_source_card_id": source_card_id,
        },
    ).execute()
    data = res.data or []
    return data[0] if data else {"action": "UNKNOWN", "fact_key": fact_key}


def _is_fact_decayed(fact_value: Any, now_utc: datetime) -> bool:
    """Returns True if a JSONB fact_value is resolved or expired."""
    if not isinstance(fact_value, dict):
        return False

    status = fact_value.get("status")
    if isinstance(status, str) and status.strip().upper().startswith("RESOLVED"):
        return True

    expires_at = fact_value.get("expires_at")
    if isinstance(expires_at, str) and expires_at.strip():
        raw_exp = expires_at.strip()
        if raw_exp.endswith("Z"):
            raw_exp = raw_exp[:-1] + "+00:00"
        try:
            exp_dt = datetime.fromisoformat(raw_exp)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt < now_utc:
                return True
        except ValueError:
            pass

    return False


@mcp.tool
def get_active_facts(
    category: Optional[str] = None,
    include_resolved: bool = False,
    force_refresh: bool = False,
) -> str:
    """Retrieves evolving active facts from public.user_facts in pipe-delimited format."""
    global _facts_cache

    now = time.time()
    cached_entry = _facts_cache.get("__all__")
    all_facts: Optional[List[Dict[str, Any]]] = None

    if not force_refresh and cached_entry is not None:
        cache_time, cached_rows = cached_entry
        if now - cache_time < FACTS_CACHE_TTL_SECONDS:
            all_facts = cached_rows

    if all_facts is None:
        sb = get_supabase()
        res = (
            sb.table("user_facts")
            .select("id, fact_key, category, fact_value, confidence, updated_at")
            .order("fact_key")
            .execute()
        )
        all_facts = res.data or []
        _facts_cache["__all__"] = (now, all_facts)

    norm_category = _normalize_fact_category(category) if category else None
    filtered_facts = (
        [f for f in all_facts if f.get("category") == norm_category]
        if norm_category
        else all_facts
    )
    if not include_resolved:
        now_utc = datetime.now(timezone.utc)
        filtered_facts = [
            f for f in filtered_facts if not _is_fact_decayed(f.get("fact_value"), now_utc)
        ]

    header = "SCHEMA: fact_key|category|confidence|updated_at|fact_value"
    if not filtered_facts:
        return f"{header}\nEMPTY_RESULT"

    lines = [header]
    for r in filtered_facts:
        raw_val = r.get("fact_value", {})
        val_str = json.dumps(raw_val, ensure_ascii=False) if isinstance(raw_val, (dict, list)) else str(raw_val)
        clean_val = val_str.replace("\n", " ").replace("|", "/")
        conf = round(float(r.get("confidence", 1.0)), 2)
        lines.append(f"{r.get('fact_key')}|{r.get('category')}|{conf}|{r.get('updated_at')}|{clean_val}")

    return "\n".join(lines)


PILLAR_ALIASES: Dict[str, str] = {
    "pillar_a": "pillar_a_systems",
    "pillar_a_systems": "pillar_a_systems",
    "pillar_a_finance": "pillar_a_finance",
    "systems": "pillar_a_systems",
    "finance": "pillar_a_finance",
    "a": "pillar_a_systems",
    "pillar_b": "pillar_b_open_source",
    "pillar_b_open_source": "pillar_b_open_source",
    "pillar_b_career": "pillar_b_career",
    "open_source": "pillar_b_open_source",
    "oss": "pillar_b_open_source",
    "career": "pillar_b_career",
    "work": "pillar_b_career",
    "b": "pillar_b_open_source",
    "pillar_c": "pillar_c_engineering",
    "pillar_c_engineering": "pillar_c_engineering",
    "engineering": "pillar_c_engineering",
    "rd": "pillar_c_engineering",
    "c": "pillar_c_engineering",
    "pillar_d": "pillar_d_health",
    "pillar_d_health": "pillar_d_health",
    "health": "pillar_d_health",
    "fitness": "pillar_d_health",
    "d": "pillar_d_health",
}


def _resolve_pillar_key(raw_pillar: str, available_keys: List[str]) -> Optional[str]:
    cleaned = raw_pillar.strip().lower()
    if cleaned in available_keys:
        return cleaned
    aliased = PILLAR_ALIASES.get(cleaned)
    if aliased and aliased in available_keys:
        return aliased
    prefix_key = (
        aliased[:9]
        if aliased and aliased.startswith("pillar_")
        else (f"pillar_{cleaned}_" if len(cleaned) == 1 else None)
    )
    if prefix_key:
        for key in available_keys:
            if key.startswith(prefix_key):
                return key
    return None


@mcp.tool
def edit_capacity_allocation(
    pillar: str,
    allocated_hours: float,
    focus_text: Optional[str] = None,
    sync_to_cloud: bool = True,
) -> dict:
    """Modifies pillar deep work hours in current_priorities.yaml under Kingman cap with cloud sync."""
    try:
        alloc_h = float(allocated_hours)
    except (ValueError, TypeError):
        return {"success": False, "allowed": False, "reason": "allocated_hours must be a valid number"}

    if alloc_h < 0.0:
        return {"success": False, "allowed": False, "reason": "allocated_hours must be non-negative (>= 0)"}

    priorities_path = STATE_DIR / "current_priorities.yaml"
    with open(priorities_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    active_sprint = data.get("active_sprint", {})
    target_pillar = _resolve_pillar_key(pillar, list(active_sprint.keys()))
    if not target_pillar:
        return {
            "success": False,
            "allowed": False,
            "reason": f"Unknown pillar '{pillar}'. Valid pillars: {list(active_sprint.keys())}",
        }

    cap = data.get("capacity_model", {})
    pool = float(cap.get("discretionary_pool_hours", 20.0))
    max_rho = float(cap.get("max_utilization_rho", 0.75))
    hard_cap = float(cap.get("hard_deep_work_cap_hours", 15.0))

    new_total = 0.0
    for k, v in active_sprint.items():
        new_total += alloc_h if k == target_pillar else float(v.get("allocated_hours", 0.0))

    new_total = round(new_total, 2)
    new_rho = round(new_total / pool, 3)
    wait_multiplier = round(new_rho / max(1.0 - new_rho, 0.01), 2)
    is_allowed = (new_rho <= max_rho) and (new_total <= hard_cap)

    if not is_allowed:
        excess_hours = round(new_total - hard_cap, 1)
        return {
            "success": False,
            "allowed": False,
            "pillar": target_pillar,
            "current_committed_hours": float(cap.get("committed_deep_work_hours", 0.0)),
            "proposed_total_hours": new_total,
            "hard_cap_hours": hard_cap,
            "new_utilization_rho": new_rho,
            "max_allowed_rho": max_rho,
            "kingman_congestion_factor": wait_multiplier,
            "directive": f"HARD_BLOCK: Exceeds weekly cap by {excess_hours}h. Remove existing work before adding.",
        }

    data["active_sprint"][target_pillar]["allocated_hours"] = alloc_h
    if focus_text is not None and focus_text.strip():
        data["active_sprint"][target_pillar]["focus"] = focus_text.strip()
    data["capacity_model"]["committed_deep_work_hours"] = new_total
    data["last_calibrated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    tmp_path = priorities_path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, sort_keys=False, allow_unicode=True)
    tmp_path.replace(priorities_path)

    global _yaml_cache
    _yaml_cache.clear()

    cloud_res = None
    if sync_to_cloud:
        try:
            from src.state_sync import push_state

            cloud_res = push_state(key="current_priorities", updated_by="fastmcp_tool")
        except Exception as e:
            cloud_res = {"status": "error", "message": str(e)}

    return {
        "success": True,
        "allowed": True,
        "pillar": target_pillar,
        "allocated_hours": alloc_h,
        "total_committed_hours": new_total,
        "new_utilization_rho": new_rho,
        "cloud_sync": cloud_res,
        "directive": "APPROVED: Core capacity allocation updated.",
    }


@mcp.tool
def log_decision_mirror(
    pressure_context: str,
    first_principle: str,
    rejected_trap: str,
    executable_rule: str,
    pillar_or_domain: str = "personal_os_code",
    title: Optional[str] = None,
    sync_to_cloud: bool = True,
    ingest_card: bool = True,
) -> dict:
    """Records strategic decisions into state/DECISION_LOG.md and knowledge cards."""
    p_ctx = pressure_context.strip() if pressure_context else ""
    f_princ = first_principle.strip() if first_principle else ""
    r_trap = rejected_trap.strip() if rejected_trap else ""
    e_rule = executable_rule.strip() if executable_rule else ""

    if not p_ctx or not f_princ or not r_trap or not e_rule:
        return {
            "success": False,
            "reason": "Missing required 4-point cognitive distillation fields.",
        }

    decision_log_path = STATE_DIR / "DECISION_LOG.md"
    existing_content = decision_log_path.read_text(encoding="utf-8") if decision_log_path.exists() else ""

    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    matches = re.findall(rf"\[DEC-{today_str}-(\d+)\]", existing_content)
    next_num = (max(int(m) for m in matches) + 1) if matches else 1
    decision_id = f"DEC-{today_str}-{next_num:02d}"

    clean_title = title.strip() if title and title.strip() else f"Decision: {e_rule[:60]}"
    safe_domain = _normalize_domain(pillar_or_domain, fallback="personal_os_code") or "personal_os_code"

    entry = (
        f"\n## [{decision_id}] {clean_title}\n\n"
        f"- **Pillar:** {safe_domain}\n\n"
        f"- **Pressure Context:** {p_ctx}\n\n"
        f"- **First Principle:** {f_princ}\n\n"
        f"- **Rejected Trap:** {r_trap}\n\n"
        f"- **Executable Rule:** {e_rule}\n"
    )

    new_content = existing_content.rstrip() + "\n" + entry
    tmp_path = decision_log_path.with_suffix(".tmp")
    tmp_path.write_text(new_content, encoding="utf-8")
    tmp_path.replace(decision_log_path)

    micro_res = None
    if ingest_card:
        try:
            raw_text = (
                f"Pressure Context: {p_ctx}\n"
                f"First Principle: {f_princ}\n"
                f"Rejected Trap: {r_trap}\n"
                f"Executable Rule: {e_rule}"
            )
            micro_res = ingest_micro_card(
                raw_text=raw_text,
                domain=safe_domain,
                intent="decision_making",
                summary=f"[{decision_id}] {clean_title}",
                value_score=9,
            )
        except Exception as e:
            micro_res = {"stored": False, "error": str(e)}

    cloud_res = None
    if sync_to_cloud:
        try:
            from src.state_sync import push_state

            cloud_res = push_state(key="decision_log", updated_by="fastmcp_tool")
        except Exception as e:
            cloud_res = {"status": "error", "message": str(e)}

    return {
        "success": True,
        "decision_id": decision_id,
        "title": clean_title,
        "pillar_or_domain": safe_domain,
        "logged_to_file": True,
        "knowledge_card": micro_res,
        "cloud_sync": cloud_res,
        "directive": f"Decision {decision_id} recorded.",
    }


if __name__ == "__main__":
    mcp.run()
