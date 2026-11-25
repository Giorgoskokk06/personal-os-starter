"""Prompt, docstring, and markdown hygiene tests enforcing token budgets and plain technical style."""

from __future__ import annotations

import ast
import glob
import json
from pathlib import Path
import re
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTS_EXAMPLE_MD = REPO_ROOT / "AGENTS.example.md"
README_MD = REPO_ROOT / "README.md"
ARCH_MD = REPO_ROOT / "docs" / "ARCHITECTURE.md"
SUBAGENTS_DIR = REPO_ROOT / ".agents" / "agents"
SKILLS_DIR = REPO_ROOT / ".agents" / "skills"
HOOKS_JSON = REPO_ROOT / ".agents" / "hooks.json"
MCP_CONFIG_JSON = REPO_ROOT / ".agents" / "plugins" / "personal-os-brain" / "mcp_config.json"
MCP_SERVER_PY = REPO_ROOT / "src" / "mcp_server.py"
GATE2_PY = REPO_ROOT / "src" / "gates" / "gate2_llm_distiller.py"

ALLOWED_NATIVE_TOOLS = {"view_file", "replace_file_content", "grep_search", "run_command"}
ALLOWED_MODELS = {"pro"}

BANNED_BUZZWORDS_RE = re.compile(
    r"(?:neuro[- ]?symbolic|epistemic|dialectical|sovereign|cognitive\s+mirror|"
    r"autonomous\s+intelligence\s+factory|two[- ]surface\s+zero[- ]bloat|"
    r"kingman(?:'s)?\s+queue?ing|simplified\s+technical\s+express|triangulation|"
    r"frontier\s+carbon)",
    re.IGNORECASE,
)


def test_agents_example_and_docs_token_budgets() -> None:
    assert AGENTS_EXAMPLE_MD.is_file()
    agents_text = AGENTS_EXAMPLE_MD.read_text(encoding="utf-8")
    assert len(agents_text) < 4500, f"AGENTS.example.md too large ({len(agents_text)} chars)"

    gate2_ns: dict[str, object] = {}
    tree = ast.parse(GATE2_PY.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "SYSTEM_PROMPT":
                    gate2_ns["SYSTEM_PROMPT"] = ast.literal_eval(node.value)
    sys_prompt = str(gate2_ns["SYSTEM_PROMPT"])
    assert len(sys_prompt) < 2500, f"Gate 2 SYSTEM_PROMPT too large ({len(sys_prompt)} chars)"


def test_subagents_and_skills_budgets_and_valid_frontmatter() -> None:
    agent_files = sorted(glob.glob(str(SUBAGENTS_DIR / "*" / "agent.md")))
    assert len(agent_files) == 4
    expected_agents = {"code-reviewer", "news-analyst", "repo-scout", "scope-checker"}
    found_agents: set[str] = set()

    for path_str in agent_files:
        p = Path(path_str)
        text = p.read_text(encoding="utf-8")
        assert len(text) < 2500, f"{p.name} exceeds 2500 chars ({len(text)})"

        match = re.search(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
        assert match, f"Missing YAML frontmatter in {p}"
        fm = yaml.safe_load(match.group(1))
        found_agents.add(str(fm["name"]))
        assert fm.get("model") in ALLOWED_MODELS, f"Invalid model in {p}: {fm.get('model')}"
        tools = set(fm.get("tools", []))
        assert tools == ALLOWED_NATIVE_TOOLS, f"Unexpected tools in {p}: {tools}"

    assert found_agents == expected_agents

    skill_files = sorted(glob.glob(str(SKILLS_DIR / "*" / "SKILL.md")))
    assert len(skill_files) == 3
    expected_skills = {"decision-log", "news-radar", "scheduled-worker"}
    found_skills: set[str] = set()

    for path_str in skill_files:
        p = Path(path_str)
        text = p.read_text(encoding="utf-8")
        assert len(text) < 3500, f"{p} exceeds 3500 chars ({len(text)})"
        match = re.search(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
        assert match, f"Missing YAML frontmatter in {p}"
        fm = yaml.safe_load(match.group(1))
        assert fm.get("description")
        found_skills.add(str(fm["name"]))

    assert found_skills == expected_skills


def test_hooks_and_mcp_plugin_configs_are_valid() -> None:
    hooks = json.loads(HOOKS_JSON.read_text(encoding="utf-8"))
    lifecycle = hooks["state-sync-lifecycle"]
    assert lifecycle["enabled"] is True
    assert lifecycle["SessionStart"][0]["command"] == "python3 -m src.state_sync --pull"
    assert lifecycle["Stop"][0]["command"] == "python3 -m src.state_sync --push"

    mcp_cfg = json.loads(MCP_CONFIG_JSON.read_text(encoding="utf-8"))
    server = mcp_cfg["mcpServers"]["personal-os-brain"]
    assert server["command"] == "python3"
    assert server["args"] == ["src/mcp_server.py"]


def test_fastmcp_docstrings_stay_compact() -> None:
    tree = ast.parse(MCP_SERVER_PY.read_text(encoding="utf-8"))
    doc_lengths: list[int] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                is_mcp_tool = (
                    (isinstance(dec, ast.Attribute) and dec.attr == "tool")
                    or (isinstance(dec, ast.Name) and dec.id == "tool")
                    or (
                        isinstance(dec, ast.Call)
                        and hasattr(dec.func, "attr")
                        and dec.func.attr == "tool"
                    )
                )
                if is_mcp_tool:
                    doc = ast.get_docstring(node) or ""
                    doc_lengths.append(len(doc))

    assert len(doc_lengths) == 7, f"Expected 7 FastMCP tools, found {len(doc_lengths)}"
    avg_len = sum(doc_lengths) / len(doc_lengths)
    assert avg_len < 150.0, f"Average docstring length {avg_len:.1f} exceeds 150 chars"
    assert max(doc_lengths) < 200, f"Max docstring length {max(doc_lengths)} exceeds 200 chars"


def test_docs_and_agents_plain_engineering_style() -> None:
    md_files = [
        README_MD,
        ARCH_MD,
        AGENTS_EXAMPLE_MD,
        *[Path(p) for p in glob.glob(str(SUBAGENTS_DIR / "*" / "agent.md"))],
        *[Path(p) for p in glob.glob(str(SKILLS_DIR / "*" / "SKILL.md"))],
    ]
    for path in md_files:
        text = path.read_text(encoding="utf-8")
        assert "\u2014" not in text, f"Found em-dash in {path}"
        assert "\u2013" not in text, f"Found en-dash in {path}"
        assert "\u2192" not in text and "\u2194" not in text, f"Found unicode arrow in {path}"
        bad = BANNED_BUZZWORDS_RE.search(text)
        assert not bad, f"Found banned buzzword '{bad.group(0)}' in {path}"
