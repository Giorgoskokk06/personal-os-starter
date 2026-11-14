#!/usr/bin/env python3
"""
src/state_sync.py — Optimistic Concurrency Control (OCC) State Synchronization Engine.
Handles bidirectional sync between local disk (state/*.yaml, state/*.md)
and Cloud-Primary Hot State (public.executive_state).
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import yaml
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

load_dotenv(REPO_ROOT / ".env")

logger = logging.getLogger("state_sync")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [state_sync] %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

STATE_DIR = REPO_ROOT / "state"

DEFAULT_STATE_MAP = {
    "current_priorities": "current_priorities.yaml",
    "pillar_metrics": "pillar_metrics.yaml",
    "decision_log": "DECISION_LOG.md",
    "agent_prompts_bundle": "RECENT_SESSIONS.md",
}

STATE_KEY_ALIASES = {
    "recent_sessions": "agent_prompts_bundle",
}

VALID_UPDATED_BY = {
    "cli_agent",
    "fastmcp_tool",
    "github_action",
    "manual_sync",
}


def compute_sha256(content: str) -> str:
    """Computes SHA-256 hex digest for a string content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class StateSync:
    """Bidirectional OCC state synchronizer between local state/ files and PostgreSQL."""

    def __init__(
        self,
        supabase_url: Optional[str] = None,
        supabase_key: Optional[str] = None,
        state_dir: Optional[Path] = None,
        state_map: Optional[Dict[str, str]] = None,
    ):
        self.state_dir = Path(state_dir or STATE_DIR)
        self.metadata_file = self.state_dir / ".sync_metadata.json"
        self.state_map = state_map or dict(DEFAULT_STATE_MAP)

        self.supabase_url = (supabase_url or os.environ.get("SUPABASE_URL", "")).rstrip("/")
        self.supabase_key = (
            supabase_key
            or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
            or os.environ.get("SUPABASE_KEY", "")
        )

        if not self.supabase_url or not self.supabase_key:
            raise ValueError(
                "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_KEY) must be set."
            )

        self._headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._client: Optional[httpx.Client] = None
        self._rest_base_url: Optional[str] = None

    @property
    def rest_base_url(self) -> str:
        """Auto-detects whether PostgREST is mounted at /rest/v1 (cloud) or root (local)."""
        if self._rest_base_url is not None:
            return self._rest_base_url
        candidate = f"{self.supabase_url}/rest/v1"
        if "127.0.0.1" in self.supabase_url or "localhost" in self.supabase_url:
            try:
                http = self._get_http_client()
                resp = http.get(f"{candidate}/", timeout=1.0)
                if resp.status_code == 404 or "PGRST125" in resp.text:
                    self._rest_base_url = self.supabase_url
                    return self._rest_base_url
            except Exception:
                pass
        self._rest_base_url = candidate
        return self._rest_base_url

    def _get_http_client(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(timeout=10.0, headers=self._headers)
        return self._client

    def close(self) -> None:
        if self._client and not self._client.is_closed:
            self._client.close()

    def load_metadata(self) -> Dict[str, Any]:
        """Loads sync metadata tracking local version & checksums."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to read metadata file, resetting: {e}")
        return {"schema_version": "1.0", "keys": {}}

    def save_metadata(self, metadata: Dict[str, Any]) -> None:
        """Persists sync metadata atomically."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        tmp_file = self.metadata_file.with_suffix(".tmp")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            tmp_file.replace(self.metadata_file)
        except Exception as e:
            logger.error(f"Failed to persist sync metadata: {e}")
            if tmp_file.exists():
                tmp_file.unlink()

    def pull(self, key_filter: Optional[str] = None) -> Dict[str, Any]:
        """Pulls state from Cloud (public.executive_state) down to local files."""
        start_time = time.perf_counter()
        http = self._get_http_client()
        resolved_filter = STATE_KEY_ALIASES.get(key_filter, key_filter) if key_filter else None

        query_url = f"{self.rest_base_url}/executive_state?select=*"
        if resolved_filter:
            query_url += f"&state_key=eq.{resolved_filter}"

        resp = http.get(query_url)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch executive_state: HTTP {resp.status_code} - {resp.text}")

        rows = resp.json()
        metadata = self.load_metadata()
        meta_keys = metadata.setdefault("keys", {})

        updated_keys: List[str] = []
        unchanged_keys: List[str] = []
        backed_up_conflicts: List[str] = []
        self.state_dir.mkdir(parents=True, exist_ok=True)

        for row in rows:
            state_key = row["state_key"]
            if state_key not in self.state_map:
                continue

            filename = self.state_map[state_key]
            filepath = self.state_dir / filename

            remote_content = row["content"]
            remote_checksum = row["checksum"]
            remote_version = row["version"]
            remote_updated_by = row["updated_by"]
            remote_updated_at = row["updated_at"]

            local_content = filepath.read_text(encoding="utf-8") if filepath.exists() else None
            local_checksum = compute_sha256(local_content) if local_content is not None else None

            if local_checksum == remote_checksum:
                unchanged_keys.append(state_key)
                meta_keys[state_key] = {
                    "version": remote_version,
                    "checksum": remote_checksum,
                    "updated_by": remote_updated_by,
                    "updated_at": remote_updated_at,
                    "last_synced_at": datetime.now(timezone.utc).isoformat(),
                }
                continue

            if local_content is not None:
                last_synced_checksum = meta_keys.get(state_key, {}).get("checksum")
                if last_synced_checksum and local_checksum != last_synced_checksum:
                    backup_filename = f"{filepath.name}.conflict_{int(time.time())}"
                    (self.state_dir / backup_filename).write_text(local_content, encoding="utf-8")
                    backed_up_conflicts.append(backup_filename)

            filepath.write_text(remote_content, encoding="utf-8")
            updated_keys.append(state_key)
            meta_keys[state_key] = {
                "version": remote_version,
                "checksum": remote_checksum,
                "updated_by": remote_updated_by,
                "updated_at": remote_updated_at,
                "last_synced_at": datetime.now(timezone.utc).isoformat(),
            }

        self.save_metadata(metadata)
        total_elapsed = (time.perf_counter() - start_time) * 1000

        return {
            "status": "success",
            "action": "pull",
            "updated_keys": updated_keys,
            "unchanged_keys": unchanged_keys,
            "backed_up_conflicts": backed_up_conflicts,
            "total_elapsed_ms": round(total_elapsed, 2),
        }

    def push(
        self,
        key_filter: Optional[str] = None,
        updated_by: str = "cli_agent",
        expected_version_override: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Pushes local state files up to Cloud using Optimistic Concurrency Control."""
        if updated_by not in VALID_UPDATED_BY:
            raise ValueError(f"Invalid updated_by '{updated_by}'. Must be one of {VALID_UPDATED_BY}")

        start_time = time.perf_counter()
        http = self._get_http_client()
        metadata = self.load_metadata()
        meta_keys = metadata.setdefault("keys", {})

        resolved_filter = STATE_KEY_ALIASES.get(key_filter, key_filter) if key_filter else None
        keys_to_push = [resolved_filter] if resolved_filter else list(self.state_map.keys())

        pushed_keys: List[str] = []
        conflicts: List[Dict[str, Any]] = []

        for state_key in keys_to_push:
            filename = self.state_map.get(state_key)
            if not filename:
                continue

            filepath = self.state_dir / filename
            if not filepath.exists():
                continue

            content = filepath.read_text(encoding="utf-8")
            checksum = compute_sha256(content)

            if expected_version_override is not None:
                expected_version = expected_version_override
            elif "version" in meta_keys.get(state_key, {}):
                expected_version = meta_keys[state_key]["version"]
            else:
                chk_resp = http.get(
                    f"{self.rest_base_url}/executive_state?select=version&state_key=eq.{state_key}"
                )
                expected_version = (
                    chk_resp.json()[0]["version"]
                    if chk_resp.status_code == 200 and chk_resp.json()
                    else 1
                )

            rpc_url = f"{self.rest_base_url}/rpc/upsert_executive_state_occ"
            payload = {
                "p_state_key": state_key,
                "p_content": content,
                "p_checksum": checksum,
                "p_expected_version": expected_version,
                "p_updated_by": updated_by,
            }

            resp = http.post(rpc_url, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(
                    f"RPC upsert_executive_state_occ failed for {state_key}: HTTP {resp.status_code} - {resp.text}"
                )

            rpc_result = resp.json()
            if not rpc_result or not isinstance(rpc_result, list):
                raise RuntimeError(f"Unexpected RPC return format for {state_key}: {rpc_result}")

            row = rpc_result[0]
            success = row.get("success", False)
            returned_version = row.get("new_version")

            if success:
                meta_keys[state_key] = {
                    "version": returned_version,
                    "checksum": checksum,
                    "updated_by": updated_by,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "last_synced_at": datetime.now(timezone.utc).isoformat(),
                }
                pushed_keys.append(state_key)
            else:
                conflicts.append({
                    "state_key": state_key,
                    "expected_version": expected_version,
                    "remote_version": returned_version,
                    "reason": "Remote state has advanced. Push blocked to prevent data loss.",
                })

        self.save_metadata(metadata)
        total_elapsed = (time.perf_counter() - start_time) * 1000
        status = "success" if not conflicts else ("partial" if pushed_keys else "conflict")

        return {
            "status": status,
            "action": "push",
            "pushed_keys": pushed_keys,
            "conflicts": conflicts,
            "total_elapsed_ms": round(total_elapsed, 2),
        }


def build_executive_hud(state_dir: Optional[Path] = None) -> str:
    """Constructs a compact Executive HUD from local state files."""
    sdir = Path(state_dir or STATE_DIR)
    priorities_path = sdir / "current_priorities.yaml"
    metrics_path = sdir / "pillar_metrics.yaml"
    decision_path = sdir / "DECISION_LOG.md"

    committed = 12.0
    hard_cap = 15.0
    pool = 20.0
    max_rho = 0.75
    pillar_b_focus = "Open-source documentation polish and CI test coverage"

    if priorities_path.exists():
        try:
            pdata = yaml.safe_load(priorities_path.read_text(encoding="utf-8")) or {}
            cap = pdata.get("capacity_model", {})
            committed = float(cap.get("committed_deep_work_hours", committed))
            hard_cap = float(cap.get("hard_deep_work_cap_hours", hard_cap))
            pool = float(cap.get("discretionary_pool_hours", pool))
            max_rho = float(cap.get("max_utilization_rho", max_rho))
            active_sprint = pdata.get("active_sprint", {})
            pb = active_sprint.get("pillar_b_open_source") or active_sprint.get("pillar_b_career") or {}
            if pb.get("focus"):
                pillar_b_focus = str(pb["focus"]).strip()[:95]
        except Exception:
            pass

    slack = round(max(0.0, hard_cap - committed), 1)
    rho = round(committed / max(pool, 1.0), 3)

    current_runway = 4500.0
    target_runway = 10000.0
    hw_unlocked = False
    if metrics_path.exists():
        try:
            mdata = yaml.safe_load(metrics_path.read_text(encoding="utf-8")) or {}
            fin = mdata.get("financial_shield", {})
            current_runway = float(fin.get("current_runway_eur", current_runway))
            target_runway = float(fin.get("target_runway_eur", target_runway))
            hw_unlocked = bool(fin.get("hardware_unlock_gate_open", current_runway >= target_runway))
        except Exception:
            pass

    deficit = round(max(0.0, target_runway - current_runway), 0)
    gate_str = "OPEN" if hw_unlocked else "LOCKED"

    latest_dec = "N/A"
    if decision_path.exists():
        try:
            dtext = decision_path.read_text(encoding="utf-8")
            headers = re.findall(r"^##\s+(\[DEC-[^\]]+\]\s+[^\n]+)", dtext, re.MULTILINE)
            if headers:
                latest_dec = headers[-1].strip()[:95]
        except Exception:
            pass

    return (
        "> **EXECUTIVE HUD (Zero-Token SSoT)**\n"
        f"> - **Financial Shield:** `{int(current_runway)} EUR / {int(target_runway)} EUR` "
        f"(Deficit: `{int(deficit)} EUR` | Hardware Gate: `{gate_str}`)\n"
        f"> - **Kingman Capacity:** `{committed}h / {hard_cap}h` Deep Work "
        f"(`rho = {rho} <= {max_rho}` | Queuing Slack: `{slack}h`)\n"
        f"> - **OSS / Study Focus:** {pillar_b_focus}\n"
        f"> - **Latest Decision:** {latest_dec}"
    )


def pull_state(key: Optional[str] = None) -> Dict[str, Any]:
    """Helper function to pull state programmatically."""
    sync = StateSync()
    try:
        return sync.pull(key_filter=key)
    finally:
        sync.close()


def push_state(
    key: Optional[str] = None,
    updated_by: str = "cli_agent",
    expected_version: Optional[int] = None,
) -> Dict[str, Any]:
    """Helper function to push state programmatically."""
    sync = StateSync()
    try:
        return sync.push(
            key_filter=key,
            updated_by=updated_by,
            expected_version_override=expected_version,
        )
    finally:
        sync.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Personal OS OCC State Synchronization Engine")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pull", action="store_true", help="Pull state from Cloud to local disk")
    group.add_argument("--push", action="store_true", help="Push state from local disk to Cloud")
    group.add_argument("--hud", action="store_true", help="Print local Executive HUD")

    parser.add_argument("--key", type=str, default=None, help="Sync specific state key only")
    parser.add_argument(
        "--updated-by",
        type=str,
        default="cli_agent",
        choices=list(VALID_UPDATED_BY),
        help="Client identifier for OCC audit log",
    )
    parser.add_argument("--version", type=int, default=None, help="Explicit expected OCC version")
    args = parser.parse_args()

    if args.hud:
        print(build_executive_hud())
        return

    sync = StateSync()
    try:
        if args.pull:
            res = sync.pull(key_filter=args.key)
        else:
            res = sync.push(
                key_filter=args.key,
                updated_by=args.updated_by,
                expected_version_override=args.version,
            )
        print(json.dumps(res, indent=2))
        if res.get("conflicts"):
            sys.exit(1)
    finally:
        sync.close()


if __name__ == "__main__":
    main()
