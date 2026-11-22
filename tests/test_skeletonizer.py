"""
tests/test_skeletonizer.py — Unit & Performance Suite for src/skeletonizer.py.
"""

from __future__ import annotations

import time
from pathlib import Path

from src.skeletonizer import (
    PythonSkeletonizer,
    TypeScriptSkeletonizer,
    render_skeleton_markdown,
    skeletonize_directory,
    skeletonize_file,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_python_skeletonizer_basic_class_and_functions() -> None:
    code = '''"""Sample module description that is quite long and should be trimmed if exceeding limits."""

GLOBAL_FLAG: bool = True
MAX_RETRIES = 5

class ServiceManager:
    """Service lifecycle manager."""
    service_id: str
    timeout: float = 30.0

    def __init__(self, service_id: str) -> None:
        self.service_id = service_id

    def start(self, retry: int = 0) -> bool:
        return True

    async def fetch_status(self, *tags: str, **kwargs) -> dict[str, str]:
        return {}

    @property
    def is_healthy(self) -> bool:
        return True

    def _internal_helper(self) -> None:
        pass

def calculate_metric(val: float, factor: float = 1.0) -> float:
    return val * factor

def _private_func():
    pass
'''
    skel = PythonSkeletonizer(include_private=False)
    stub = skel.skeletonize_code(code)

    assert '"""Sample module description' in stub
    assert "GLOBAL_FLAG: bool = True" in stub
    assert "MAX_RETRIES = 5" in stub
    assert "class ServiceManager:" in stub
    assert "def __init__(self, service_id: str) -> None: ..." in stub
    assert "def start(self, retry: int = 0) -> bool: ..." in stub
    assert "async def fetch_status(self, *tags: str, **kwargs) -> dict[str, str]: ..." in stub
    assert "@property\n    def is_healthy(self) -> bool: ..." in stub
    assert "def calculate_metric(val: float, factor: float = 1.0) -> float: ..." in stub
    assert "_internal_helper" not in stub
    assert "_private_func" not in stub


def test_python_skeletonizer_include_private_and_syntax_resilience() -> None:
    code = """
class MyClass:
    def _hidden(self) -> None:
        pass

def _top_hidden():
    pass
"""
    skel = PythonSkeletonizer(include_private=True)
    stub = skel.skeletonize_code(code)
    assert "_hidden(self) -> None: ..." in stub
    assert "def _top_hidden(): ..." in stub

    bad_stub = PythonSkeletonizer().skeletonize_code("def broken_func(:\n    pass", filename="bad.py")
    assert "SyntaxError parsing bad.py" in bad_stub


def test_typescript_skeletonizer_signatures() -> None:
    ts_code = """
export interface UserFact {
    id: string;
    category: string;
    fact_key: string;
    confidence: number;
    updated_at: string;
    extra_field: boolean;
}

export type DomainType = "finance" | "career" | "engineering";

export async function processUpdate(req: Request, mode: string = "fast"): Promise<Response> {
    return new Response("OK");
}

export const API_VERSION: string = "v1.0";
"""
    stub = TypeScriptSkeletonizer().skeletonize_code(ts_code)
    assert "export interface UserFact { id: string; category: string; fact_key: string; confidence: number; updated_at: string; ... }" in stub
    assert 'export type DomainType = "finance" | "career" | "engineering";' in stub
    assert 'export function processUpdate(req: Request, mode: string = "fast"): Promise<Response>;' in stub
    assert "export const API_VERSION: string;" in stub


def test_skeletonize_directory_budget_and_markdown(tmp_path: Path) -> None:
    for i in range(5):
        py_file = tmp_path / f"mod_{i}.py"
        py_file.write_text(
            f"class Worker{i}:\n    def run(self, arg: int = {i}) -> bool:\n        return True\n",
            encoding="utf-8",
        )

    skeletons = skeletonize_directory(tmp_path, max_tokens=30)
    assert len(skeletons) >= 1
    last_key = list(skeletons.keys())[-1]
    assert "[Truncated by token budget]" in skeletons[last_key] or len(skeletons) < 5

    md = render_skeleton_markdown({"src/mod.py": "def foo() -> int: ...", "src/types.ts": "export type X = string;"})
    assert "#### `src/mod.py`" in md
    assert "```python\ndef foo() -> int: ...\n```" in md


def test_skeletonizer_performance_sla() -> None:
    target = REPO_ROOT / "src" / "mcp_server.py"
    assert target.is_file()

    t0 = time.perf_counter()
    stub = skeletonize_file(target, include_private=False)
    dt_ms = (time.perf_counter() - t0) * 1000

    assert dt_ms < 25.0, f"Parsing exceeded 25ms SLA: took {dt_ms:.2f}ms"
    assert "def query_hybrid_memory" in stub
    assert "def verify_capacity_slack" in stub
    assert "def check_runway_gate" in stub
