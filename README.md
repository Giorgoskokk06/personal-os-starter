# personal-os-starter

[![CI](https://github.com/Giorgoskokk06/personal-os-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/Giorgoskokk06/personal-os-starter/actions/workflows/ci.yml)

Local-first AI memory, MCP tool server, AST code skeletonizer, scheduled GitHub discovery and news filter, PostgreSQL 17 (`pgvector`) hybrid search, and a Deno Telegram webhook.

Prompt instructions alone do not enforce workload limits, spending caps, prompt-injection boundaries, or concurrent writes. This repository moves those checks into Python and PostgreSQL so an agent host cannot bypass them.

## What is included

- **FastMCP Control Plane (`src/mcp_server.py`):** Exposes 7 stdio tools (`query_hybrid_memory`, `ingest_micro_card`, `get_active_facts`, `log_decision_mirror`, `verify_capacity_slack`, `edit_capacity_allocation`, `check_runway_gate`) enforcing workload buffers (`rho <= 0.75`) and spending gates in Python.
- **3-Step Memory Ingestion Pipeline (`src/gates/`):**
  - `gate1_heuristics.py`: Zero-LLM filter dropping short/trivial inputs, secret leaks, and already-ingested thread hashes.
  - `gate2_llm_distiller.py`: Structured knowledge-card and fact extraction with middle-out token truncation and deterministic fallback.
  - `gate3_validator.py`: Pydantic schema validation, summary length checks, and deduplication before database writes.
- **PostgreSQL 17 + `pgvector` Hybrid Search (`supabase/migrations/`, `src/db/supabase_repo.py`):** Stores `halfvec(768)` embeddings with an HNSW index plus a GIN full-text column blended via Reciprocal Rank Fusion (`k = 50`), SHA-256 deduplication before embedding calls, JSONB fact contradiction history, and `FOR UPDATE` versioned state sync (`src/state_sync.py`).
- **AST Repo Mapper (`src/skeletonizer.py`):** Zero-dependency Python AST and TypeScript signature skeletonizer (`< 25 ms` per module) to fit large codebases inside tight token budgets.
- **Scheduled Background Worker (`src/autonomous/`, `scripts/setup_autonomous_timers.sh`, `systemd/`):**
  - `scouts.py` + `src/security/sanitizer.py`: Queries the GitHub Search REST API and RSS/Atom feeds with a 1 MB response cap, XML DOCTYPE/ENTITY rejection, HTML/BiDi normalization, prompt-injection blocking, and cryptographic nonce delimiters.
  - `critic.py`: Filters out awesome-lists, tutorials, archived/forked repos, and incompatible licenses; maps passing repos to concrete `OS_UPGRADE_CANDIDATE` target-module proposals.
  - `sentinels.py`, `staging_gate.py`, `agy_bridge.py`: Checks local state, workload/budget thresholds, and repo health; sends short Telegram summaries (`<= 180 words`, quiet by default via `src/telegram_notifier.py`); runs approved upgrades in an isolated `git worktree` and opens `--draft` PRs only after tests and audits pass.
- **News & Macro Signal Filter (`src/intel_radar.py`, `state.example/geopolitical_baseline.yaml`):** Fetches 6 international news and market feeds in parallel, accounts for negated headlines (such as `"no escalation"` or `"ceasefire talks"`), checks market spreads against clickbait, and labels `[LIVE]` vs `[ARCHIVE FALLBACK]` items honestly.
- **Serverless Telegram Webhook (`supabase/functions/telegram/`):** Deno/TypeScript `grammY` bot with pre-cached `botInfo` (zero cold-start `getMe` roundtrip), webhook secret and user ID checks, `/remember`, `/search`, `/radar`, `/status`, `/help` commands, and background ingestion via `EdgeRuntime.waitUntil()`.
- **Agent Configuration & Security Gates (`.agents/`, `scripts/audit_public.py`, `tests/evals/`):** Includes 4 compact subagent specs, 3 skill guides, session sync hooks, a pre-publish secret/PII scanner, and automated prompt-budget tests.

## Quickstart

All Python and Deno unit tests and offline CLI workflows run locally with zero external API keys or database setup:

```bash
git clone https://github.com/Giorgoskokk06/personal-os-starter.git
cd personal-os-starter

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp -r state.example state
cp .env.example .env

# 1. Run all unit, security, and prompt-budget tests
pytest -v

# 2. Run the Deno webhook test (if Deno is installed)
deno test --allow-env supabase/functions/telegram/grammy.deno.ts

# 3. Check repository hygiene (secrets, blocked paths, private markers)
python3 scripts/audit_public.py
```

### Try the CLI tools offline

```bash
# GitHub repository discovery -> noise filter -> Personal OS upgrade candidates
python3 -m src.autonomous.cli --job github-scout --offline --json

# 6-cluster macro & news signal filter (offline baseline mode)
python3 -m src.intel_radar --offline

# Preview portable systemd user timers without modifying your system
bash scripts/setup_autonomous_timers.sh --dry-run

# Generate a token-budgeted AST map of src/ (<25 ms)
python3 -m src.skeletonizer src --budget 1200 --markdown
```

Run the MCP server over stdio:

```bash
python3 src/mcp_server.py
```

### Database migrations

Apply the three SQL migrations in order on PostgreSQL 17 with `pgvector >= 0.7.0`:

```text
supabase/migrations/20261016000001_hybrid_rag_schema.sql
supabase/migrations/20261029000000_executive_state.sql
supabase/migrations/20261102000000_user_facts.sql
```

## Repository layout

```text
.agents/                     # Hooks, MCP plugin config, 4 subagents, and 3 skills
.github/workflows/ci.yml     # Pytest, Deno test, audit_public.py, and CLI smoke checks
AGENTS.example.md            # Compact workspace rules and delegation template
docs/ARCHITECTURE.md         # System design, database layout, and webhook flow
scripts/
  audit_public.py            # Pre-publish secret, blocked-path, and PII marker scanner
  setup_autonomous_timers.sh # Portable systemd user timer generator (--dry-run supported)
src/
  mcp_server.py              # FastMCP stdio server (7 tools)
  skeletonizer.py            # Python AST & TypeScript signature mapper
  state_sync.py              # Versioned OCC state sync & local status summary
  intel_radar.py             # 6-cluster macro & news signal filter
  telegram_notifier.py       # Outbound-only flock-guarded Telegram sender
  drive_client.py            # Optional Drive upload & share-link RPC decoder
  autonomous/                # GitHub/RSS scouts, local watchers, critic, worktree PR factory
  gates/                     # 3-step memory ingestion filter (heuristics -> distill -> validate)
  db/supabase_repo.py        # Hybrid RRF search & SHA-256 deduplication wrapper
  security/sanitizer.py      # HTML/BiDi normalization, IPI regex filter & nonce wrapper
  stylistics/naturalizer.py  # Deterministic style linter & sentence-cadence metrics
state.example/               # Synthetic YAML/Markdown state, policy & baseline templates
supabase/
  functions/                 # Deno grammY Telegram webhook, shared core, and Deno unit test
  migrations/                # pgvector halfvec(768), OCC executive_state, and user_facts SQL
systemd/                     # Portable reference .service and .timer units
tests/                       # Offline pytest suite, red-team IPI checks, and prompt-budget evals
```

## License

[MIT](LICENSE)
