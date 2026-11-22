"""
tests/test_drive_client_sanitized.py — Tests for filename sanitization, Drive upload, and share RPC decoding.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.drive_client import (
    DriveClient,
    decode_gemini_share_rpc,
    extract_gemini_share_url,
    resolve_gemini_share_url,
)
from src.security.sanitizer import sanitize_local_filename


def test_sanitize_local_filename_blocks_traversal_and_slashes() -> None:
    assert sanitize_local_filename("LAW 3850/2010") == "LAW 3850_2010"
    evil = sanitize_local_filename("..//..\\\\evil\x00.pdf")
    assert "/" not in evil and "\\" not in evil and "\x00" not in evil and ".." not in evil
    traversal = sanitize_local_filename("../../etc/passwd")
    assert "/" not in traversal and "\\" not in traversal and ".." not in traversal
    assert sanitize_local_filename("   ...   ") == "document.pdf"
    assert sanitize_local_filename("") == "document.pdf"


def test_extract_and_decode_gemini_share_rpc() -> None:
    assert extract_gemini_share_url("Check https://gemini.google.com/share/abc123def456") == "https://gemini.google.com/share/abc123def456"
    assert extract_gemini_share_url("No link here") is None

    prompt_node = [["How does Reciprocal Rank Fusion blend vector and FTS ranks?"], 2, None, None, "turn_1"]
    answer_prose = "Reciprocal Rank Fusion sums 1 / (k + rank) across retrieval lists without linear score normalization."
    inner_payload = [
        [None, None, [None, "Hybrid RAG RRF Overview"]],
        [prompt_node, answer_prose],
    ]
    wrb_frame = [["wrb.fr", "ujx1Bf", json.dumps(inner_payload)]]
    raw_rpc = ")]}'\n\n" + json.dumps(wrb_frame) + "\n"

    decoded = decode_gemini_share_rpc(raw_rpc, share_id="abc123def456")
    assert decoded is not None
    assert decoded["title"] == "Hybrid RAG RRF Overview"
    assert decoded["turnCount"] == 1
    assert "Reciprocal Rank Fusion" in decoded["transcript"]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = raw_rpc
    resolved = resolve_gemini_share_url(
        "https://gemini.google.com/share/abc123def456",
        http_post=lambda *a, **kw: mock_resp,
    )
    assert resolved is not None
    assert resolved["shareId"] == "abc123def456"


def test_drive_upload_artifact_sanitizes_custom_name(tmp_path: Path) -> None:
    client = DriveClient.__new__(DriveClient)
    mock_service = MagicMock()
    client.service = mock_service

    files_res = mock_service.files.return_value
    files_res.list.return_value.execute.side_effect = [
        {"files": [{"id": "fld_exports", "name": "POS_Exports"}]},
        {"files": []},
    ]
    files_res.create.return_value.execute.return_value = {
        "id": "file_123",
        "name": "Report 2026_11.pdf",
        "webViewLink": "https://drive.google.com/file/d/file_123/view",
    }

    sample = tmp_path / "sample.pdf"
    sample.write_bytes(b"%PDF-1.4 synthetic")

    fake_media = MagicMock()
    with patch.dict("sys.modules", {"googleapiclient": MagicMock(), "googleapiclient.http": MagicMock(MediaFileUpload=MagicMock(return_value=fake_media))}):
        res = client.upload_artifact(sample, folder_name="POS_Exports", custom_name="Report 2026/11.pdf")

    assert res["file_id"] == "file_123"
    assert res["name"] == "Report 2026_11.pdf"
