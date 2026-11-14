"""Self-contained unit tests for Kingman capacity & Financial Shield guards."""

from pathlib import Path
import shutil

import pytest

import src.mcp_server as mcp_server


def _unwrap(tool):
    """Support both FastMCP v2 (FunctionTool with .fn) and FastMCP v3 (plain callable)."""
    return getattr(tool, "fn", tool)


@pytest.fixture()
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Copies state.example/ into a temporary state/ directory for isolated testing."""
    example_dir = Path(__file__).resolve().parent.parent / "state.example"
    state_dir = tmp_path / "state"
    shutil.copytree(example_dir, state_dir)
    monkeypatch.setattr(mcp_server, "STATE_DIR", state_dir)
    mcp_server._yaml_cache.clear()
    return state_dir


def test_verify_capacity_slack_approves_within_cap(isolated_state: Path) -> None:
    # 12.0h committed + 2.5h = 14.5h <= 15.0h cap (rho = 0.725 <= 0.75)
    res = _unwrap(mcp_server.verify_capacity_slack)(2.5)
    assert res["allowed"] is True
    assert res["proposed_total_hours"] == 14.5
    assert res["new_utilization_rho"] <= 0.75
    assert res["directive"].startswith("APPROVED")


def test_verify_capacity_slack_blocks_overflow(isolated_state: Path) -> None:
    # 12.0h committed + 4.0h = 16.0h > 15.0h cap (rho = 0.800 > 0.75)
    res = _unwrap(mcp_server.verify_capacity_slack)(4.0)
    assert res["allowed"] is False
    assert res["proposed_total_hours"] == 16.0
    assert res["directive"].startswith("HARD_BLOCK")


def test_edit_capacity_allocation_updates_yaml_when_valid(isolated_state: Path) -> None:
    res = _unwrap(mcp_server.edit_capacity_allocation)(
        pillar="pillar_c_engineering",
        allocated_hours=5.5,
        focus_text="Updated R&D milestone",
        sync_to_cloud=False,
    )
    assert res["success"] is True
    assert res["allowed"] is True
    assert res["total_committed_hours"] == 13.0

    oss_res = _unwrap(mcp_server.edit_capacity_allocation)(
        pillar="open_source",
        allocated_hours=4.0,
        sync_to_cloud=False,
    )
    assert oss_res["success"] is True
    assert oss_res["pillar"] == "pillar_b_open_source"
    assert oss_res["total_committed_hours"] == 13.5


def test_edit_capacity_allocation_blocks_exceeding_kingman_cap(isolated_state: Path) -> None:
    res = _unwrap(mcp_server.edit_capacity_allocation)(
        pillar="pillar_c_engineering",
        allocated_hours=10.0,
        sync_to_cloud=False,
    )
    assert res["success"] is False
    assert res["allowed"] is False
    assert res["directive"].startswith("HARD_BLOCK")


def test_check_runway_gate_blocks_hardware_below_target(isolated_state: Path) -> None:
    # Synthetic example has current=4500, target=10000
    res = _unwrap(mcp_server.check_runway_gate)(proposed_expense_eur=500.0, category="hardware")
    assert res["approved"] is False
    assert res["deficit_eur"] == 5500.0
    assert res["directive"].startswith("HARD_BLOCK")


def test_check_runway_gate_allows_non_hardware_expense(isolated_state: Path) -> None:
    res = _unwrap(mcp_server.check_runway_gate)(proposed_expense_eur=50.0, category="books")
    assert res["approved"] is True
    assert res["remaining_after_expense_eur"] == 4450.0
