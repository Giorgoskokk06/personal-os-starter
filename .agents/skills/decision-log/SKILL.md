---
name: decision-log
description: Distills architectural and engineering decisions into a 4-part structured log entry and knowledge card.
---

# Decision Log Skill

Capture important engineering trade-offs consistently in `state/DECISION_LOG.md` and `public.knowledge_cards`.

## 4-Part Structure

1. **Pressure Context:** What technical bottleneck, constraint, or failure mode forced the decision.
2. **First Principle:** Which systems, database, or queueing constraint governs the trade-off.
3. **Rejected Trap:** Which tempting shortcut was intentionally rejected and why.
4. **Executable Rule:** The concrete check, invariant, or code guard that enforces the choice going forward.

## Persistence

Call the MCP tool `log_decision_mirror` (or `ingest_micro_card` with `intent='decision_making'` and `value_score >= 8`) so the decision is saved both in Markdown and in PostgreSQL hybrid search.
