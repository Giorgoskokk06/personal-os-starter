# AGENTS.example.md - Multi-Agent Rules & Guardrail Template

Copy and adapt this template to `AGENTS.md` in your private workspace. Never commit real tokens, `.env` files, or private identifiers to a public repository.

## 1. Core System Rules

1. **Session State Sync:** Sync local YAML and Markdown state files (`state/`) with PostgreSQL (`public.executive_state`) via optimistic concurrency checks (`src/state_sync.py`) at session start and stop.
2. **Python Workload & Budget Limits:** Enforce weekly off-hours capacity limits (`rho <= 0.75` within a configurable `12.0h-21.0h/week` spare-time budget, keeping a 25% slack buffer) and spending gates in `src/mcp_server.py`, not only in system prompts.
3. **Confidentiality Isolation:** Keep public templates and personal scripts separated from restricted datasets, PII records, and secret keys (`exclude_corporate_scope: true`).
4. **Model Delegation Policy:**
   * **Root Coordinator:** Keep the main session focused on planning, synthesis, and final review rather than bulk file inspection.
   * **Worker Delegation:** Route multi-file code exploration, refactoring, and test loops to capable worker models (`gemini-4-neon-medium` / `gemini-4-neon-high`). **Disallow `flash` / `flash_lite` worker delegation** (enforced in `src/autonomous/agy_bridge.py`).
5. **Objective Verification:**
   * Do not flip conclusions just to agree with user frustration or enthusiasm.
   * Report trade-offs, test failures, and operational costs explicitly.

## 2. Scheduled Worker Safety Locks

* `auto_merge_main` MUST stay `false`; automated runs may open `--draft` PRs on `autonomous/draft-*` branches only after passing `StagingGate.run_verification_gate()` inside an isolated `git worktree`.
* Untrusted external feeds and GitHub metadata MUST pass HTML/BiDi normalization, prompt-injection scanning, and cryptographic nonce wrapping (`src/security/sanitizer.py`) before any model sees them.
* Outbound notifications stay quiet by default when no threshold or upgrade candidate triggers.
