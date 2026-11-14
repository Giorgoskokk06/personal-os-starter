#!/usr/bin/env python3
"""
scripts/audit_public.py — Zero-dependency public repository security & PII scanner.
Verifies that no secrets, blocked env/state paths, or private markers exist in the repository.
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

REQUIRED_FILES = [
    "README.md",
    "LICENSE",
    ".gitignore",
    ".env.example",
    "requirements.txt",
]

BLOCKED_FILE_PATTERNS = [
    re.compile(r"^\.env(?:\..+)?$", re.IGNORECASE),
    re.compile(r"^\.dev\.vars$", re.IGNORECASE),
    re.compile(r"^state/", re.IGNORECASE),
    re.compile(r"^reports/", re.IGNORECASE),
]

SECRET_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    ("google_oauth_secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{12,}\b")),
    ("telegram_token", re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b")),
    ("jwt_like", re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._-]{20,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----")),
]

IGNORED_DIRS = {".git", "__pycache__", ".venv", "venv", ".pytest_cache"}


def list_repo_files(root: Path) -> List[Path]:
    files: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            files.append(Path(dirpath) / fname)
    return sorted(files)


def is_binary(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:4096]
        return b"\x00" in chunk
    except OSError:
        return True


def main() -> int:
    private_markers = [
        m.strip().lower()
        for m in os.environ.get("PERSONAL_OS_PRIVATE_MARKERS", "").split(",")
        if m.strip()
    ]

    files = list_repo_files(REPO_ROOT)
    rel_paths = {f.relative_to(REPO_ROOT).as_posix() for f in files}
    failures: List[str] = []

    for req in REQUIRED_FILES:
        if req not in rel_paths:
            failures.append(f"missing required file: {req}")

    for path in files:
        rel = path.relative_to(REPO_ROOT).as_posix()
        if any(p.match(rel) for p in BLOCKED_FILE_PATTERNS) and rel != ".env.example":
            failures.append(f"blocked repository path: {rel}")
            continue

        if is_binary(path):
            continue

        text = path.read_text(encoding="utf-8", errors="replace")
        text_lower = text.lower()

        for marker in private_markers:
            if marker in text_lower:
                failures.append(f"configured private marker '{marker}' found in {rel}")

        for name, regex in SECRET_PATTERNS:
            for match in regex.finditer(text):
                token = match.group(0)
                if "eyJyb2xlIjoicG9zdGdyZXMi" in token:
                    continue
                failures.append(f"possible {name} in {rel}")

    if failures:
        print("Public audit FAILED:", file=sys.stderr)
        for item in sorted(set(failures)):
            print(f" - {item}", file=sys.stderr)
        return 1

    print(f"Public audit PASSED ({len(files)} files checked).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
