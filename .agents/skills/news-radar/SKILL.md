---
name: news-radar
description: Runs the 6-cluster macro and geopolitical signal filter in under 5 minutes without doom-scrolling.
---

# News Radar Skill

Provides fast, low-noise situation awareness via `src/intel_radar.py` and `state.example/geopolitical_baseline.yaml`.

## Usage

- **Offline / cached briefing:** `python3 -m src.intel_radar --offline`
- **Live 6-cluster RSS briefing:** `python3 -m src.intel_radar --briefing`
- **Evaluate a single headline or URL:** `python3 -m src.intel_radar --triangulate "<claim_or_url>" --offline --json`

## How Noise Filtering Works

1. **6 Global Clusters:** Fetches international wires, macro bond/rate proxies, energy and maritime chokepoints, semiconductor supply chains, European policy feeds, and emerging-market/state-aligned outlets (tagged explicitly as official posture rather than verified fact).
2. **Negation & Acronym Handling:** Negators ("no", "rules out") and de-escalatory cues ("ceasefire talks", "de-escalation") reduce panic scores instead of triggering false alarms, while standard acronyms (`ECB`, `OPEC`, `TSMC`, `LNG`) are excluded from shout penalties.
3. **Honest Attribution:** Every feed entry carries `[LIVE <date>]` or `[ARCHIVE FALLBACK - not current news]`.
