"""
src/autonomous/__init__.py — Personal OS Autonomous Operations Package.

Provides shared repository root resolution and safe YAML policy loading.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH: Path = REPO_ROOT / "state" / "autonomous_policy.yaml"
EXAMPLE_POLICY_PATH: Path = REPO_ROOT / "state.example" / "autonomous_policy.yaml"


def load_policy(path: Path | None = None) -> dict[str, Any]:
    """Safely load the autonomous operations policy YAML using yaml.safe_load."""
    if path is not None:
        target = Path(path)
    elif DEFAULT_POLICY_PATH.exists():
        target = DEFAULT_POLICY_PATH
    else:
        target = EXAMPLE_POLICY_PATH

    if not target.exists():
        return {}
    try:
        with target.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


__all__ = ["REPO_ROOT", "DEFAULT_POLICY_PATH", "EXAMPLE_POLICY_PATH", "load_policy"]
