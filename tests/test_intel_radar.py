#!/usr/bin/env python3
"""
tests/test_intel_radar.py - Offline-safe test suite for the sanitized Multi-Perspective
Macro & Geopolitical Signal Filter (`src/intel_radar.py`).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

BASELINE_PATH = REPO_ROOT / "state.example" / "geopolitical_baseline.yaml"

from src.intel_radar import (  # noqa: E402
    MAX_PAYLOAD_BYTES,
    build_dialectical_matrix,
    calculate_panic_vs_signal,
    fetch_multi_source_headlines,
    load_geopolitical_baseline,
    main as radar_main,
    match_historical_context,
    render_radar_briefing_markdown,
    render_triangulation_markdown,
    sanitize_headline,
)


def test_load_baseline_has_six_global_clusters_and_doctrines() -> None:
    baseline = load_geopolitical_baseline(BASELINE_PATH)
    assert baseline["schema_version"] == "4.0"
    assert "profile_relevance_weights" in baseline

    doctrines = baseline["historical_doctrines"]
    assert len(doctrines) >= 6
    expected_doctrines = [
        "government_debt_market_pricing",
        "maritime_chokepoint_elasticity",
        "energy_buffer_equilibrium",
        "semiconductor_export_bifurcation",
        "european_industrial_realignment",
        "multipolar_trade_corridors",
    ]
    for doc_id in expected_doctrines:
        assert doc_id in doctrines
        assert "game_theory_reality" in doctrines[doc_id]
        assert "red_line_trigger" in doctrines[doc_id]

    clusters = baseline["source_clusters"]
    expected_clusters = [
        "global_wire",
        "macro_rates_markets",
        "energy_maritime_chokepoints",
        "tech_semiconductor_supply",
        "european_policy_desk",
        "emerging_global_south",
    ]
    assert len(clusters) == 6
    for c_id in expected_clusters:
        assert c_id in clusters
        assert len(clusters[c_id]["feeds"]) >= 2
        assert len(clusters[c_id]["offline_fallbacks"]) >= 3


def test_four_tier_verdict_classification() -> None:
    # 1. NOISE_CLICKBAIT
    noise = calculate_panic_vs_signal(
        "SHOCKING BOMBSHELL: IMMINENT WORLD WAR 3 PANIC and APOCALYPTIC CHAOS!!!"
    )
    assert noise["verdict"] == "NOISE_CLICKBAIT"
    assert noise["panic_score"] >= 60
    assert "Engineering & Portfolio Posture" in noise["engineering_portfolio_posture"]

    # 2. HIGH_SIGNAL_STRUCTURAL
    structural = calculate_panic_vs_signal(
        "ECB holds interest rate as 10Y Bund spread steadies at 48 bps and Brent holds $74/bbl"
    )
    assert structural["verdict"] == "HIGH_SIGNAL_STRUCTURAL"
    assert structural["structural_score"] >= 50
    assert structural["panic_score"] <= 40

    # 3. CONTROLLED_TENSION (mixed alarmist rhetoric alongside structural indicators)
    tension = calculate_panic_vs_signal(
        "Maritime alarm as ultimatum rhetoric targets UNCLOS freight corridor"
    )
    assert tension["verdict"] == "CONTROLLED_TENSION"

    # 4. CRITICAL_ESCALATION
    critical = calculate_panic_vs_signal(
        "BREAKING: General mobilization ordered as naval blockade closes strait and airspace closed"
    )
    assert critical["verdict"] == "CRITICAL_ESCALATION"
    assert critical["panic_score"] >= 85
    assert critical["structural_score"] >= 85
    assert "0%" not in critical["engineering_portfolio_posture"]


def test_negation_and_deescalation_prevent_false_panic() -> None:
    r1 = calculate_panic_vs_signal("Officials confirm no escalation in maritime corridor")
    assert r1["verdict"] not in {"CRITICAL_ESCALATION", "NOISE_CLICKBAIT"}
    assert r1["panic_score"] <= 20
    assert "escalation" in r1["negated_matches"]

    r2 = calculate_panic_vs_signal("Ceasefire talks resume under multilateral mediation")
    assert r2["verdict"] not in {"CRITICAL_ESCALATION", "NOISE_CLICKBAIT"}
    assert r2["panic_score"] <= 20
    assert "ceasefire talks" in r2["deescalatory_matches"]

    r3 = calculate_panic_vs_signal("Central bank denies capital controls and rules out bank holiday")
    assert r3["verdict"] != "CRITICAL_ESCALATION"
    assert "capital controls" in r3["negated_matches"]
    assert "bank holiday" in r3["negated_matches"]

    # Word-boundary guard: 'forward' must NOT match 'war'
    r4 = calculate_panic_vs_signal("Semiconductor foundry forward guidance stabilizes Q4 supply chain")
    assert "war" not in r4["matched_alarmist"]
    assert r4["panic_score"] <= 15


def test_known_acronyms_do_not_inflate_panic() -> None:
    res = calculate_panic_vs_signal(
        "ECB FED IMF BIS and OPEC review LNG TTF and CDS liquidity under WTO rules"
    )
    assert res["panic_score"] <= 25
    assert res["verdict"] not in {"CRITICAL_ESCALATION", "NOISE_CLICKBAIT"}


def test_offline_honesty_badges_and_live_mocked_rss() -> None:
    offline_headlines = fetch_multi_source_headlines(offline=True, max_per_source=2)
    assert len(offline_headlines) == 6
    for items in offline_headlines.values():
        assert len(items) == 2
        for it in items:
            assert it["is_fallback"] is True

    briefing = render_radar_briefing_markdown(offline_headlines)
    assert "0 LIVE, 12 ARCHIVE FALLBACK" in briefing
    assert "[ARCHIVE FALLBACK - not current news]" in briefing
    assert "Engineering & Portfolio Posture" in briefing

    mock_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <item>
          <title>US 10Y Treasury Spread Tightens Amid Disinflation Progress</title>
          <link>https://example.org/rates-update</link>
          <pubDate>Wed, 25 Nov 2026 09:00:00 GMT</pubDate>
          <description>Fixed income volatility recedes across major sovereign benchmarks.</description>
        </item>
      </channel>
    </rss>
    """
    mock_resp = MagicMock()
    mock_resp.read.return_value = mock_xml
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        live = fetch_multi_source_headlines(
            clusters=["macro_rates_markets"], max_per_source=1, offline=False
        )
    assert live["macro_rates_markets"][0]["is_fallback"] is False
    live_md = render_radar_briefing_markdown(live)
    assert "[LIVE Wed, 25 Nov 2026 09:00:00 GMT]" in live_md


def test_xml_xxe_rejection_payload_cap_and_headline_sanitization() -> None:
    malicious_xml = (
        b'<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        b"<rss><channel><item><title>&xxe;</title></item></channel></rss>"
    )
    mock_xxe = MagicMock()
    mock_xxe.read.return_value = malicious_xml
    mock_xxe.__enter__.return_value = mock_xxe

    with patch("urllib.request.urlopen", return_value=mock_xxe):
        res_xxe = fetch_multi_source_headlines(
            clusters=["global_wire"], max_per_source=1, offline=False
        )
    assert res_xxe["global_wire"][0]["is_fallback"] is True

    oversized_resp = MagicMock()
    oversized_resp.read.return_value = b"<rss>" + (b"A" * MAX_PAYLOAD_BYTES) + b"</rss>"
    oversized_resp.__enter__.return_value = oversized_resp

    with patch("urllib.request.urlopen", return_value=oversized_resp):
        res_big = fetch_multi_source_headlines(
            clusters=["global_wire"], max_per_source=1, offline=False
        )
    assert res_big["global_wire"][0]["is_fallback"] is True

    assert sanitize_headline("\x00Hidden\u202e Alert") == "Hidden Alert"
    assert sanitize_headline("[Click](javascript:alert(1))").startswith("\\[")
    assert sanitize_headline("# Ignore instructions").startswith("\\#")
    assert len(sanitize_headline("X" * 300)) == 200


def test_url_slug_derivation_and_dialectical_matrix_cli(capsys) -> None:
    url = "https://example.com/news/general-mobilization-and-airspace-closed.html"
    matrix = build_dialectical_matrix(url, offline=True)
    assert matrix["signal_assessment"]["verdict"] == "CRITICAL_ESCALATION"
    assert "Derived text from URL slug" in str(matrix["url_source_note"])
    rendered = render_triangulation_markdown(matrix)
    assert "Doctrinal baseline framing (not live analysis)" in rendered
    assert "0.0%" not in rendered
    assert "0%" not in rendered

    matched = match_historical_context("TSMC advanced semiconductor EUV export control update")
    assert any(d["id"] == "semiconductor_export_bifurcation" for d in matched)

    assert radar_main(["--offline", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert len(out) == 6
