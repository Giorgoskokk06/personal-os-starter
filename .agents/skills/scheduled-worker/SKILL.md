---
name: scheduled-worker
description: Explains how systemd timers run GitHub discovery, local health checks, Telegram alerts, and draft worktree PRs.
---

# Scheduled Worker Skill

Use this workflow when inspecting or extending background automation in `src/autonomous/` and `scripts/setup_autonomous_timers.sh`.

## Pipeline Stages

1. **Schedule (`scripts/setup_autonomous_timers.sh`, `systemd/`):**
   - Preview generated user units safely with `bash scripts/setup_autonomous_timers.sh --dry-run`.
   - Schedules cover nightly repo health (`pos-auto-s4`), GitHub/RSS scouts (`pos-auto-scouts`), daily macro radar (`pos-auto-radar`), digest synthesis (`pos-auto-digest`), and weekly draft PR generation (`pos-auto-draft-pr`).
2. **Discovery (`src/autonomous/scouts.py`):**
   - Queries GitHub Search REST API (`https://api.github.com/search/repositories`) and RSS/Atom feeds with a 1 MB payload cap, XML DOCTYPE/ENTITY rejection, HTML stripping, and nonce isolation.
3. **Deterministic Filter (`src/autonomous/critic.py`):**
   - Drops prompt injections, confidential terms, archived/forked repos, below-threshold stars, and awesome-list/tutorial spam.
   - Maps passing repos to `OS_UPGRADE_CANDIDATE` with a target module and integration proposal.
4. **Isolated Draft PRs (`src/autonomous/staging_gate.py`, `src/autonomous/agy_bridge.py`):**
   - Runs edits in a temporary `git worktree` on `autonomous/draft-*`, locks protected paths (`AGENTS.md`, `src/mcp_server.py`, `.agents/`, `supabase/migrations/`), runs `pytest` and `audit_public.py`, and never auto-merges to `main`.
