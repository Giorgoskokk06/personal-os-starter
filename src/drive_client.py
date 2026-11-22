"""
src/drive_client.py — Sanitized Google Drive Artifact Sync & Public Share Link Resolver.

Provides:
- Path-traversal-safe external filename sanitization (`sanitize_local_filename`).
- Pure-Python resolver for public Gemini Share URLs (`decode_gemini_share_rpc`,
  `resolve_gemini_share_url`) without headless browsers.
- Lazy-initialized Google Drive API v3 client (`DriveClient`) using OAuth 2.0 refresh
  tokens or service accounts supplied exclusively through environment variables.
"""

from __future__ import annotations

import json
import logging
import mimetypes
import os
import re
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from src.security.sanitizer import sanitize_local_filename

logger = logging.getLogger(__name__)

GEMINI_SHARE_URL_RE = re.compile(
    r"(?:https?://)?(?:(?:www\.)?gemini\.google\.com/share/|g\.co/(?:gemini|bard)/share/|share\.gemini\.google/(?:share/)?)([A-Za-z0-9_-]{6,})",
    re.IGNORECASE,
)


def extract_gemini_share_url(text: str) -> Optional[str]:
    """Extract a public Gemini Share URL from arbitrary text if present."""
    if not text:
        return None
    match = GEMINI_SHARE_URL_RE.search(str(text))
    if not match:
        return None
    raw = match.group(0)
    return raw if raw.lower().startswith(("http://", "https://")) else f"https://{raw}"


def _try_parse_json(s: str) -> Any:
    try:
        return json.loads(s)
    except Exception:
        return None


def _is_title_model_node(v: Any) -> bool:
    return (
        isinstance(v, list)
        and len(v) >= 8
        and v[0] is True
        and isinstance(v[1], str)
        and len(v[1].strip()) > 0
        and isinstance(v[5], list)
        and isinstance(v[7], list)
    )


def _is_prompt_node(v: Any) -> bool:
    return (
        isinstance(v, list)
        and len(v) >= 5
        and isinstance(v[0], list)
        and len(v[0]) > 0
        and isinstance(v[0][0], str)
        and len(v[0][0].strip()) > 0
        and v[1] == 2
        and isinstance(v[4], str)
    )


def _looks_like_shared_prose(s: str) -> bool:
    t = s.strip()
    if len(t) < 25:
        return False
    if t.lower().startswith(("http://", "https://")):
        return False
    if "googleusercontent.com" in t or "data:image" in t or "boq_gemini" in t:
        return False
    if re.match(r"^[A-Za-z0-9+/=_-]{40,}$", t):
        return False

    words = [w for w in re.split(r"\s+", t) if w]
    if len(words) < 4 or max(len(w) for w in words) > 160:
        return False

    letters = sum(1 for ch in t if ch.isalpha())
    if letters / len(t) < 0.35:
        return False
    structural = sum(1 for ch in t if ch in '[]{}"\\')
    if structural / len(t) > 0.08:
        return False
    return True


def _dedupe_texts_ordered(texts: List[str]) -> List[str]:
    kept: List[str] = []
    for i, t in enumerate(texts):
        if not t:
            continue
        if any(i != j and len(o) > len(t) and t in o for j, o in enumerate(texts)):
            continue
        if any(t in k or k in t for k in kept):
            continue
        kept.append(t)
    return kept


def decode_gemini_share_rpc(raw_body: str, share_id: str = "") -> Optional[Dict[str, Any]]:
    """Decode the batchexecute RPC response from `ujx1Bf` into a structured transcript."""
    stripped = re.sub(r"^\)\]\}'[^\n]*\r?\n?", "", str(raw_body or ""))
    frames: List[List[Any]] = []
    for raw_line in stripped.splitlines():
        line = raw_line.strip()
        if not line.startswith("["):
            continue
        parsed = _try_parse_json(line)
        if isinstance(parsed, list):
            frames.append(parsed)

    best_events: Optional[List[Dict[str, Any]]] = None
    best_score = 0
    explicit_title = ""

    for frame in frames:
        for entry in frame:
            if not isinstance(entry, list) or len(entry) < 3 or entry[0] != "wrb.fr":
                continue
            inner_raw = entry[2]
            inner = _try_parse_json(inner_raw) if isinstance(inner_raw, str) else inner_raw
            if not isinstance(inner, list):
                continue

            c0 = inner[0] if (len(inner) > 0 and isinstance(inner[0], list)) else None
            meta_node = c0[2] if (c0 and len(c0) > 2 and isinstance(c0[2], list)) else None
            if meta_node and len(meta_node) > 1 and isinstance(meta_node[1], str) and meta_node[1].strip():
                explicit_title = meta_node[1].strip()

            events: List[Dict[str, Any]] = []

            def _walk(v: Any, path: List[int], depth: int) -> None:
                if depth > 60:
                    return
                if isinstance(v, str):
                    t = v.strip()
                    if path == [0, 2, 1] or (explicit_title and t == explicit_title):
                        return
                    if _looks_like_shared_prose(t):
                        events.append({"type": "text", "text": t, "path": path})
                    return
                if not isinstance(v, list):
                    return
                if _is_title_model_node(v):
                    events.append({"type": "meta", "title": v[1].strip(), "path": path})
                    return
                if _is_prompt_node(v):
                    events.append({"type": "prompt", "text": v[0][0].strip(), "path": path})
                    return
                for idx, child in enumerate(v):
                    _walk(child, path + [idx], depth + 1)

            _walk(inner, [], 0)

            score = sum(
                3 if e["type"] == "prompt" else (2 if e["type"] == "text" else 4)
                for e in events
            )
            if score > best_score:
                best_score = score
                best_events = events

    if not best_events or best_score < 2:
        return None

    title = explicit_title
    if not title:
        metas = [e for e in best_events if e["type"] == "meta"]
        if metas:
            metas.sort(key=lambda x: len(x["title"]), reverse=True)
            title = metas[0]["title"]

    content_events = [e for e in best_events if e["type"] in ("prompt", "text")]
    content_events.sort(key=lambda x: x["path"])

    exchanges: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    for e in content_events:
        if e["type"] == "prompt":
            cur = {"prompt": e["text"], "texts": []}
            exchanges.append(cur)
        else:
            if cur is None:
                cur = {"prompt": None, "texts": []}
                exchanges.append(cur)
            cleaned_txt = re.sub(r",\s*AI generated\s*$", "", e["text"], flags=re.IGNORECASE).strip()
            cur["texts"].append(cleaned_txt)

    cleaned_exchanges = []
    for ex in exchanges:
        deduped = _dedupe_texts_ordered([t for t in ex["texts"] if t])
        if ex["prompt"] or deduped:
            cleaned_exchanges.append({"prompt": ex["prompt"], "texts": deduped})

    if not cleaned_exchanges:
        return None

    blocks: List[str] = []
    for idx, ex in enumerate(cleaned_exchanges):
        parts: List[str] = []
        if len(cleaned_exchanges) > 1:
            parts.append(f"### Turn {idx + 1}")
        if ex["prompt"]:
            parts.append(f"User: {ex['prompt']}")
        if ex["texts"]:
            parts.append(f"Gemini: {'\n\n'.join(ex['texts'])}")
        blocks.append("\n\n".join(parts))

    header_parts = [f"# {title}"] if title else []
    transcript = "\n\n---\n\n".join(header_parts + blocks)
    resolved_title = title or (
        cleaned_exchanges[0]["prompt"][:80] if cleaned_exchanges[0]["prompt"] else "Gemini Shared Conversation"
    )
    return {
        "title": resolved_title,
        "transcript": transcript,
        "turnCount": len(cleaned_exchanges),
        "shareId": share_id,
    }


def resolve_gemini_share_url(
    raw_url: str,
    timeout: float = 8.0,
    http_post: Optional[Callable[..., Any]] = None,
    http_get: Optional[Callable[..., Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Fetch and decode a public Gemini Share URL in pure Python."""
    import httpx

    try:
        share_id = ""
        direct_match = re.search(r"/share/([A-Za-z0-9_-]{6,})", raw_url, re.IGNORECASE)
        if direct_match:
            share_id = direct_match.group(1)
        else:
            get_fn = http_get or httpx.get
            page_resp = get_fn(raw_url, follow_redirects=False, timeout=timeout)
            loc = page_resp.headers.get("location") or str(getattr(page_resp, "url", ""))
            loc_match = re.search(r"/share/([A-Za-z0-9_-]{6,})", loc, re.IGNORECASE)
            if loc_match:
                share_id = loc_match.group(1)
            else:
                fb_match = re.search(r"/([A-Za-z0-9_-]{8,})(?:\?.*)?$", raw_url)
                if not fb_match:
                    return None
                share_id = fb_match.group(1)

        rpc_params = urllib.parse.urlencode({
            "rpcids": "ujx1Bf",
            "source-path": f"/share/{share_id}",
            "bl": "boq_gemini-web-uiserver_20261028.12_p0",
            "hl": "en",
            "_reqid": "12345",
            "rt": "c",
        })
        f_req = json.dumps([
            [
                ["ujx1Bf", json.dumps([None, share_id, [4]]), None, "1"],
                ["ujx1Bf", json.dumps([None, share_id]), None, "2"],
            ]
        ])
        rpc_url = f"https://gemini.google.com/_/BardChatUi/data/batchexecute?{rpc_params}"
        body_str = urllib.parse.urlencode({"f.req": f_req})
        headers = {
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Origin": "https://gemini.google.com",
            "Referer": f"https://gemini.google.com/share/{share_id}",
        }
        post_fn = http_post or httpx.post
        rpc_resp = post_fn(rpc_url, content=body_str, headers=headers, timeout=timeout)
        if getattr(rpc_resp, "status_code", 500) != 200:
            return None
        return decode_gemini_share_rpc(rpc_resp.text, share_id=share_id)
    except Exception as exc:
        logger.warning("resolve_gemini_share_url failed for %s: %s", raw_url, exc)
        return None


class DriveClient:
    """Optional Google Drive API v3 client using OAuth 2.0 refresh tokens or service accounts."""

    def __init__(self, service_account_json: Optional[str] = None) -> None:
        self.service_account_json = service_account_json or os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "")
        self.service: Any = None
        self._init_service()

    def _init_service(self) -> None:
        try:
            from googleapiclient.discovery import build

            refresh_token = os.environ.get("GOOGLE_REFRESH_TOKEN", "").strip()
            client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
            client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()

            if refresh_token and client_id and client_secret:
                from google.oauth2.credentials import Credentials

                creds = Credentials(
                    token=None,
                    refresh_token=refresh_token,
                    token_uri="https://oauth2.googleapis.com/token",
                    client_id=client_id,
                    client_secret=client_secret,
                    scopes=["https://www.googleapis.com/auth/drive"],
                )
                self.service = build("drive", "v3", credentials=creds)
                return

            if self.service_account_json:
                from google.oauth2 import service_account

                if os.path.exists(self.service_account_json):
                    creds = service_account.Credentials.from_service_account_file(
                        self.service_account_json,
                        scopes=["https://www.googleapis.com/auth/drive"],
                    )
                else:
                    info = json.loads(self.service_account_json)
                    creds = service_account.Credentials.from_service_account_info(
                        info,
                        scopes=["https://www.googleapis.com/auth/drive"],
                    )
                self.service = build("drive", "v3", credentials=creds)
                return
        except Exception as exc:
            logger.info("DriveClient running in offline/unconfigured mode: %s", exc)

    def ensure_folder_path(self, folder_path: str, parent_id: Optional[str] = None) -> str:
        """Ensure a nested folder hierarchy exists in Drive and return the leaf folder ID."""
        if not self.service:
            raise RuntimeError("DriveClient is not authenticated.")

        parts = [p.strip() for p in str(folder_path).replace("\\", "/").split("/") if p.strip()]
        if not parts:
            raise ValueError("folder_path must not be empty")

        current_parent = parent_id
        for part in parts:
            safe_part = part.replace("\\", "\\\\").replace("'", "\\'")
            q_parts = [
                f"name = '{safe_part}'",
                "mimeType = 'application/vnd.google-apps.folder'",
                "trashed = false",
            ]
            if current_parent:
                q_parts.append(f"'{current_parent}' in parents")

            res = (
                self.service.files()
                .list(
                    q=" and ".join(q_parts),
                    fields="files(id, name)",
                    pageSize=5,
                    supportsAllDrives=True,
                    includeItemsFromAllDrives=True,
                )
                .execute()
            )
            found = res.get("files", [])
            if found:
                current_parent = found[0]["id"]
            else:
                meta: Dict[str, Any] = {
                    "name": part,
                    "mimeType": "application/vnd.google-apps.folder",
                }
                if current_parent:
                    meta["parents"] = [current_parent]
                created = (
                    self.service.files()
                    .create(body=meta, fields="id, name", supportsAllDrives=True)
                    .execute()
                )
                current_parent = created["id"]

        return str(current_parent)

    def upload_artifact(
        self,
        local_path: Path | str,
        folder_name: str = "POS_Exports",
        custom_name: Optional[str] = None,
        mime_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Upload or update a local file in Google Drive with safe filename sanitization."""
        if not self.service:
            raise RuntimeError("DriveClient is not authenticated.")

        path_obj = Path(local_path).resolve()
        if not path_obj.exists() or not path_obj.is_file():
            raise FileNotFoundError(f"Local artifact not found: {path_obj}")

        target_name = sanitize_local_filename(custom_name or path_obj.name, default=path_obj.name)
        guessed_mime, _ = mimetypes.guess_type(str(path_obj))
        effective_mime = mime_type or guessed_mime or "application/octet-stream"

        folder_id = self.ensure_folder_path(folder_name)
        safe_name = target_name.replace("\\", "\\\\").replace("'", "\\'")
        q = f"name = '{safe_name}' and '{folder_id}' in parents and trashed = false"
        existing = (
            self.service.files()
            .list(
                q=q,
                fields="files(id, name)",
                pageSize=5,
                supportsAllDrives=True,
                includeItemsFromAllDrives=True,
            )
            .execute()
            .get("files", [])
        )

        from googleapiclient.http import MediaFileUpload

        media = MediaFileUpload(str(path_obj), mimetype=effective_mime, resumable=True)
        fields = "id, name, mimeType, webViewLink, webContentLink, parents"

        if existing:
            file_id = existing[0]["id"]
            res = (
                self.service.files()
                .update(
                    fileId=file_id,
                    body={"name": target_name},
                    media_body=media,
                    fields=fields,
                    supportsAllDrives=True,
                )
                .execute()
            )
            updated_existing = True
        else:
            res = (
                self.service.files()
                .create(
                    body={"name": target_name, "parents": [folder_id]},
                    media_body=media,
                    fields=fields,
                    supportsAllDrives=True,
                )
                .execute()
            )
            updated_existing = False

        fid = res.get("id", "")
        web_link = res.get("webViewLink") or f"https://drive.google.com/file/d/{fid}/view"
        return {
            "file_id": fid,
            "name": res.get("name", target_name),
            "folder_id": folder_id,
            "folder_name": folder_name,
            "webViewLink": web_link,
            "webContentLink": res.get("webContentLink", ""),
            "updated_existing": updated_existing,
        }
