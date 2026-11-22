# AGENTS.example.md — Multi-Agent Orchestration & Guardrail Template

> Copy and adapt this template to `AGENTS.md` in your private workspace. Never commit real credentials, private identifiers, or personal financial figures to a public repository.

## 1. Core Architectural Invariants

1. **Zero-Friction Capture & Sync:** Keep local state (`state/*.yaml`, `state/*.md`) synchronized with PostgreSQL (`public.executive_state`) via Optimistic Concurrency Control (`src/state_sync.py`) so every session starts warm and ends cleanly.
2. **Neuro-Symbolic Hard Guards:** Enforce weekly off-hours personal study & open-source R&D utilization ($\rho \le 0.75$ within a configurable `12.0h–21.0h/week` spare-time budget, e.g. `15.0h / 20.0h` in `state.example/`) and capex runway gates deterministically in `src/mcp_server.py`, never via prompt suggestions alone.
3. **Confidentiality & Secret Isolation:** Keep personal tooling and public templates strictly separated from confidential datasets, PII records, and secret key material (`exclude_corporate_scope: true`).
4. **Model Policy Lockdown & Mandatory Delegation:**
   * **Root / Orchestrator:** Use frontier reasoning (`gemini-4-carbon-medium` / `gemini-4-carbon-high`) exclusively for coordination, synthesis, and final verification. Do not burn orchestrator context on bulk file reads or repetitive test loops.
   * **Delegated Workers:** Route implementation, multi-file analysis, and verification work to capable worker models (`gemini-4-neon-medium` / `gemini-4-neon-high`). **Zero `flash` or `flash_lite` worker delegation** (enforced programmatically in `src/autonomous/agy_bridge.py`).
5. **Anti-Sycophancy & Adversarial Stress-Testing:**
   * Never flip an analytical conclusion simply to mirror user frustration or enthusiasm.
   * Incorporate new constraints as weighted model parameters while preserving empirical trade-offs.
   * When goals conflict, state the **irreducible trade-off** explicitly with concrete costs and risks per option.

## 2. Autonomous Operations Safety Locks

* `auto_merge_main` MUST remain `false`; autonomous workers may open `--draft` PRs on `autonomous/draft-*` branches only after passing `StagingGate.run_verification_gate()`.
* Untrusted external feeds MUST pass HTML/control stripping, OWASP IPI filtering, and ephemeral cryptographic nonce wrapping (`src/security/sanitizer.py`) before reaching any LLM prompt.
* Notifications follow **Silent-by-Default**: zero output when no threshold or actionable signal triggers.
