"""Gate 1: Fast zero-LLM heuristic filter for trivial messages, secret leaks, and duplicates."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ConversationTurn:
    """Single prompt/response exchange inside a conversation thread."""

    prompt: str
    response: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "prompt": self.prompt,
            "response": self.response,
            "timestamp": self.timestamp,
        }


@dataclass
class ConversationThread:
    """Ordered turns grouped into a conversation session."""

    thread_hash: str
    source_file: str
    started_at: str
    ended_at: str
    turns: List[ConversationTurn] = field(default_factory=list)

    @property
    def turn_count(self) -> int:
        return len(self.turns)

    @property
    def combined_prompt(self) -> str:
        return " \n".join(t.prompt for t in self.turns if t.prompt).strip()

    @property
    def full_dialogue(self) -> str:
        parts: List[str] = []
        for turn in self.turns:
            if turn.prompt:
                parts.append(f"User: {turn.prompt}")
            if turn.response:
                parts.append(f"Assistant: {turn.response}")
        return "\n\n".join(parts)


def compute_thread_hash(started_at: str, first_prompt: str) -> str:
    """Compute a deterministic SHA-256 hash from start timestamp and normalized first prompt."""
    norm_prompt = re.sub(r"\s+", " ", (first_prompt or "")).strip().lower()
    raw = f"{started_at}_{norm_prompt}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


TRIVIAL_PATTERNS = [
    re.compile(r"\b(weather|forecast|temperature)\b", re.IGNORECASE),
    re.compile(r"\b(what\s+time\s+is\s+it|current\s+time)\b", re.IGNORECASE),
    re.compile(r"\b(convert\b|meters?\s+to\s+feet|celsius\s+to\s+fahrenheit|km\s+to\s+miles)\b", re.IGNORECASE),
    re.compile(r"^\s*(translate|how\s+to\s+say)\b", re.IGNORECASE),
    re.compile(
        r"^\s*(hi|hello|hey|ok|okay|thanks?|thx|cool|yes|no|bye|ping|test)\s*([!.,?]?\s*)$",
        re.IGNORECASE,
    ),
    re.compile(r"\b(set\s+(an\s+)?alarm|set\s+timer|reminder)\b", re.IGNORECASE),
]

SECRET_LEAK_RE = re.compile(
    r"(?:\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bAKIA[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9_-]{20,}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def is_trivial_single_turn(prompt: str) -> bool:
    """Return True when a single-turn message matches common low-signal patterns."""
    text = prompt.strip()
    if len(text.split()) < 3:
        return True
    return any(pattern.search(text) for pattern in TRIVIAL_PATTERNS)


def evaluate_gate1(
    thread: ConversationThread,
    existing_hashes: Optional[Dict[str, int]] = None,
    min_prompt_length: int = 40,
) -> Tuple[bool, Optional[str]]:
    """
    Evaluate deterministic Gate 1 rules with zero LLM calls:
    1. Reject prompts shorter than min_prompt_length chars.
    2. Reject single-turn trivial greetings, lookups, or one-word inputs.
    3. Reject messages containing credential or private-key patterns.
    4. Reject threads already stored with >= the current turn count.
    """
    combined_prompt = thread.combined_prompt
    if len(combined_prompt) < min_prompt_length:
        return False, f"Prompt length ({len(combined_prompt)}) < {min_prompt_length} chars"

    if thread.turn_count == 1 and is_trivial_single_turn(combined_prompt):
        return False, "Single-turn trivial pattern match"

    full_probe = f"{combined_prompt}\n{thread.full_dialogue}"
    if SECRET_LEAK_RE.search(full_probe):
        return False, "Secret or private key pattern detected"

    if existing_hashes and thread.thread_hash in existing_hashes:
        existing_count = existing_hashes[thread.thread_hash]
        if thread.turn_count <= existing_count:
            return False, f"Already ingested with {existing_count} turns (current: {thread.turn_count})"

    return True, None


def filter_threads_gate1(
    threads: List[ConversationThread],
    existing_hashes: Optional[Dict[str, int]] = None,
    min_prompt_length: int = 40,
) -> Tuple[List[ConversationThread], List[Tuple[ConversationThread, str]]]:
    """Split threads into (passed_threads, rejected_threads_with_reason)."""
    passed: List[ConversationThread] = []
    rejected: List[Tuple[ConversationThread, str]] = []

    for thread in threads:
        keep, reason = evaluate_gate1(
            thread,
            existing_hashes=existing_hashes,
            min_prompt_length=min_prompt_length,
        )
        if keep:
            passed.append(thread)
        else:
            rejected.append((thread, reason or "Gate 1 rejected"))

    return passed, rejected
