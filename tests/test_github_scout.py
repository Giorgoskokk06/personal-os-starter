"""Tests for GitHub trending/repo discovery scout, deterministic noise filter, and systemd timer setup."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.autonomous import REPO_ROOT, load_policy
from src.autonomous.cli import main as cli_main
from src.autonomous.critic import classify_github_repo, classify_item
from src.autonomous.scouts import (
    MAX_PAYLOAD_BYTES,
    fetch_github_trending_repos,
    normalize_github_repo_item,
    run_github_scout,
)


def test_github_scout_offline_fixture_filters_noise_and_proposes_upgrades(tmp_path: Path) -> None:
    policy = load_policy()
    res = run_github_scout(
        policy=policy,
        offline=True,
        cache_dir=tmp_path / "cache",
        raw_dir=tmp_path / "raw",
    )
    assert res["stream_id"] == "GITHUB"
    assert res["mode"] == "OFFLINE_SYNTHETIC_FIXTURE"
    assert res["ipi_blocked_count"] == 1
    assert "untrusted-org/evil-mcp-plugin" in res["quarantined_repos"]

    classified = [
        classify_item(item, policy=policy, current_runway_eur=4500.0)
        for item in res["items"]
    ]
    verdicts = {c["item"]["repo_full_name"]: c for c in classified}

    # High-signal engineering repos promoted to OS_UPGRADE_CANDIDATE with target modules
    assert verdicts["oss-labs/ast-token-budget"]["verdict"] == "OS_UPGRADE_CANDIDATE"
    assert verdicts["oss-labs/ast-token-budget"]["target_module"] == "src/skeletonizer.py"

    assert verdicts["pg-vectors/halfvec-rrf-bench"]["verdict"] == "OS_UPGRADE_CANDIDATE"
    assert verdicts["pg-vectors/halfvec-rrf-bench"]["target_module"] == "src/db/supabase_repo.py"

    assert verdicts["mcp-sec/fastmcp-policy-guard"]["verdict"] == "OS_UPGRADE_CANDIDATE"
    assert verdicts["mcp-sec/fastmcp-policy-guard"]["target_module"] == "src/mcp_server.py"

    # Medium-signal watch repo
    assert verdicts["local-sync/yaml-occ-journal"]["verdict"] == "INTEL_BRIEF"

    # Low-signal awesome-list, tutorial spam, and archived fork dropped deterministically
    assert verdicts["hype-curators/awesome-ai-agents-2026"]["verdict"] == "DROP"
    assert verdicts["hype-curators/awesome-ai-agents-2026"]["reason"] == "github_low_signal_hype"

    assert verdicts["study-notes/100-days-llm-prompts-tutorial"]["verdict"] == "DROP"
    assert verdicts["study-notes/100-days-llm-prompts-tutorial"]["reason"] == "github_low_signal_hype"

    assert verdicts["legacy-mirror/stale-agent-fork"]["verdict"] == "DROP"
    assert verdicts["legacy-mirror/stale-agent-fork"]["reason"] == "github_archived_or_fork"


def test_github_search_api_live_mock_and_1mb_cap() -> None:
    sample_api_response = {
        "total_count": 1,
        "items": [
            {
                "full_name": "db-tools/pgvector-hybrid-eval",
                "html_url": "https://github.com/db-tools/pgvector-hybrid-eval",
                "stargazers_count": 720,
                "language": "Python",
                "license": {"spdx_id": "MIT"},
                "topics": ["pgvector", "hybrid-search", "rrf", "benchmark"],
                "pushed_at": "2026-11-24T12:00:00Z",
                "archived": False,
                "fork": False,
                "description": "<b>Hybrid</b> RRF retrieval benchmark for pgvector halfvec indexes.",
            }
        ],
    }
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(sample_api_response).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        items, errors = fetch_github_trending_repos(
            [{"name": "pgvector", "query": "topic:pgvector", "target_module": "src/db/supabase_repo.py"}],
            offline=False,
            now_utc=datetime(2026, 11, 25, tzinfo=timezone.utc),
        )
    assert errors == []
    assert len(items) == 1
    assert items[0]["repo_full_name"] == "db-tools/pgvector-hybrid-eval"
    assert "<b>" not in items[0]["summary"]
    assert "<UNTRUSTED_TELEMETRY_PAYLOAD_NONCE_" in items[0]["sanitized_nonce_block"]

    oversized_resp = MagicMock()
    oversized_resp.read.return_value = b"{" + (b" " * MAX_PAYLOAD_BYTES) + b"}"
    oversized_resp.__enter__.return_value = oversized_resp

    with patch("urllib.request.urlopen", return_value=oversized_resp):
        items_over, errs_over = fetch_github_trending_repos(
            [{"name": "oversized", "query": "topic:mcp-server"}],
            offline=False,
        )
    assert items_over == []
    assert len(errs_over) == 1
    assert "1MB limit" in errs_over[0]


def test_github_critic_rejects_incompatible_license_and_low_stars() -> None:
    policy = load_policy()

    low_star = normalize_github_repo_item(
        {
            "full_name": "tiny/demo-mcp",
            "stargazers_count": 8,
            "language": "Python",
            "license": {"spdx_id": "MIT"},
            "topics": ["mcp", "fastmcp"],
            "description": "Small experimental MCP server.",
        }
    )
    res_low = classify_github_repo(low_star, policy=policy, current_runway_eur=4500.0)
    assert res_low["verdict"] == "DROP"
    assert res_low["reason"] == "github_below_min_stars"

    gpl_repo = normalize_github_repo_item(
        {
            "full_name": "corp/proprietary-wrapper",
            "stargazers_count": 500,
            "language": "Python",
            "license": {"spdx_id": "GPL-3.0"},
            "topics": ["mcp", "pgvector"],
            "description": "MCP pgvector tool.",
        }
    )
    res_lic = classify_github_repo(gpl_repo, policy=policy, current_runway_eur=4500.0)
    assert res_lic["verdict"] == "DROP"
    assert res_lic["reason"] == "github_incompatible_license"


def test_cli_github_scout_and_scouts_jobs_offline_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(["--job", "github-scout", "--offline", "--json"]) == 0
    gh_payload = json.loads(capsys.readouterr().out)
    assert gh_payload["job"] == "github-scout"
    assert gh_payload["actionable"] is True
    assert len(gh_payload["result"]["upgrade_candidates"]) == 3
    assert gh_payload["result"]["dropped_count"] == 3

    assert cli_main(["--job", "scouts", "--offline", "--dry-run", "--json"]) == 0
    scouts_payload = json.loads(capsys.readouterr().out)
    assert scouts_payload["job"] == "scouts"
    assert "GITHUB" in scouts_payload["result"]["streams"]


def test_setup_autonomous_timers_dry_run_is_portable_and_sanitized() -> None:
    script_path = REPO_ROOT / "scripts" / "setup_autonomous_timers.sh"
    assert script_path.is_file()
    proc = subprocess.run(
        ["bash", str(script_path), "--dry-run"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    out = proc.stdout
    for timer_name in (
        "pos-auto-s4.timer",
        "pos-auto-scouts.timer",
        "pos-auto-radar.timer",
        "pos-auto-draft-pr.timer",
        "pos-auto-digest.timer",
    ):
        assert timer_name in out
    assert out.count(".timer ===") == 5
    assert out.count(".service ===") == 5
    assert "pos-auto-s1" not in out
    assert str(REPO_ROOT) in out
