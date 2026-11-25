# Systemd User Units (Scheduled Autonomous Workers)

Portable reference `.service` and `.timer` definitions for Linux `systemd --user` scheduling.

Instead of hardcoding local checkout paths, preview or install the units dynamically for your local clone:

```bash
# Preview generated units without modifying your system
bash scripts/setup_autonomous_timers.sh --dry-run

# Install and enable user timers into ~/.config/systemd/user/
bash scripts/setup_autonomous_timers.sh

# Remove installed user services and timers
bash scripts/setup_autonomous_timers.sh --uninstall
```

## Included Schedules

| Timer | Schedule | Worker Job |
| :--- | :--- | :--- |
| `pos-auto-s4.timer` | Daily `04:00` | Nightly Repo Self-Health (`pytest` + AST skeleton freshness) |
| `pos-auto-scouts.timer` | Mon & Thu `06:00` | GitHub Trending Discovery + Engineering RSS/Atom Scouts |
| `pos-auto-radar.timer` | Daily `07:45` | Multi-Perspective Macro & Geopolitical Radar (`src.intel_radar`) |
| `pos-auto-draft-pr.timer` | Saturday `07:30` | Isolated `git worktree` Self-Upgrade Draft PR Factory (`StagingGate`) |
| `pos-auto-digest.timer` | Wed & Sat `09:00` | Tactical & Deep R&D Digest Synthesis (Silent-by-Default) |
