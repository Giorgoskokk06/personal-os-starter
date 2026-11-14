# Cognitive Decision Log (Example)

## [DEC-2026-01-15-01] Enforce Kingman Utilization Cap (rho <= 0.75) in Tooling

- **Pillar:** personal_os_code

- **Pressure Context:** Evening and weekend R&D commitments repeatedly drifted above sustainable spare-time limits, causing queue congestion whenever a debugging task ran over estimate.

- **First Principle:** By Kingman's VUT equation, expected queue delay scales with $\rho / (1 - \rho)$; keeping utilization at $\rho \le 0.75$ preserves a 25% slack buffer to absorb variance.

- **Rejected Trap:** Relying on prompt-level reminders alone, which are easily overridden during busy weeks.

- **Executable Rule:** Route all task additions through `verify_capacity_slack` and hard-block any allocation exceeding 15.0h out of the 20.0h weekly off-hours study & open-source R&D pool (configurable within 12.0h–21.0h/week).
