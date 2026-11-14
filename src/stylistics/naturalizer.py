#!/usr/bin/env python3
"""
src/stylistics/naturalizer.py — Technical Style Linter & Prose Simplifier.

Provides:
1. Regex-based boilerplate cliché scrubbing (English & Greek) for verbose or repetitive phrasing.
2. Burstiness & sentence length variance calculation (Coefficient of Variation, Barabasi Burstiness).
3. Type-Token Ratio (TTR) for vocabulary diversity estimation.
4. Voice normalization into formal RFC/technical prose or embedded systems telemetry voice.
5. Comprehensive text audit report (style_risk_score, burstiness metrics, detected markers, recommendations).
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Pattern, Tuple

# Common abbreviations that should NOT trigger a sentence split
ABBREVIATIONS_EL = {
    "π.χ.", "δηλ.", "κ.λπ.", "κ.α.", "κ.ο.κ.", "σελ.", "τόμ.", "αρ.", "υπ.", "καθ.", "δρ.",
}
ABBREVIATIONS_EN = {
    "e.g.", "i.e.", "etc.", "vs.", "fig.", "tab.", "eq.", "ref.", "dr.", "prof.", "al.",
    "approx.", "vol.", "no.",
}
ALL_ABBREVIATIONS = ABBREVIATIONS_EL | ABBREVIATIONS_EN

CLICHE_RULES_EL: List[Tuple[Pattern[str], str, str]] = [
    (
        re.compile(r"\bαξίζει\s+να\s+(?:σημειωθεί|τονιστεί|αναφερθεί)(?:\s+ότι)?\b", re.IGNORECASE),
        "",
        "Remove verbose filler 'αξίζει να σημειωθεί/τονιστεί'",
    ),
    (
        re.compile(r"\bείναι\s+σημαντικό\s+να\s+(?:τονιστεί|σημειωθεί|αναφερθεί)(?:\s+ότι)?\b", re.IGNORECASE),
        "",
        "Remove verbose filler 'είναι σημαντικό να τονιστεί'",
    ),
    (
        re.compile(r"\b(?:συνοψίζοντας|εν\s+κατακλείδι|εν\s+συνόψει)(?:\s*,)?\b", re.IGNORECASE),
        "",
        "Remove generic summary transition",
    ),
    (
        re.compile(r"\bδιαδραματίζει\s+(?:καθοριστικό|κομβικό|κεντρικό|κρίσιμο)\s+ρόλο\b", re.IGNORECASE),
        "επηρεάζει άμεσα",
        "Replace verbose phrasing 'διαδραματίζει καθοριστικό ρόλο'",
    ),
    (
        re.compile(r"\bαποτελεί\s+(?:θεμέλιο\s+λίθο|ακρογωνιαίο\s+λίθο)\b", re.IGNORECASE),
        "είναι βασικό στοιχείο",
        "Replace cliché metaphor 'θεμέλιος λίθος'",
    ),
    (
        re.compile(r"\bκαθίσταται\s+σαφές\s+ότι\b", re.IGNORECASE),
        "προκύπτει ότι",
        "Simplify verbose phrasing",
    ),
    (
        re.compile(r"\bστο\s+σύγχρονο\s+(?:τοπίο|κόσμο|περιβάλλον)\b", re.IGNORECASE),
        "στην πράξη",
        "Remove introductory filler",
    ),
    (
        re.compile(r"\bπρος\s+αυτή\s+την\s+κατεύθυνση(?:\s*,)?\b", re.IGNORECASE),
        "έτσι,",
        "Simplify transitional phrasing",
    ),
]

CLICHE_RULES_EN: List[Tuple[Pattern[str], str, str]] = [
    (
        re.compile(r"\bit\s+is\s+worth\s+noting\s+that\b", re.IGNORECASE),
        "",
        "Purge 'it is worth noting that'",
    ),
    (
        re.compile(r"\bit\s+is\s+important\s+to\s+(?:note|remember|highlight)\s+that\b", re.IGNORECASE),
        "",
        "Purge 'it is important to note that'",
    ),
    (
        re.compile(r"\b(?:in\s+conclusion|in\s+summary|to\s+summarize)(?:\s*,)?\b", re.IGNORECASE),
        "",
        "Purge generic conclusion transition",
    ),
    (
        re.compile(r"\b(?:furthermore|moreover)(?:\s*,)?\b", re.IGNORECASE),
        "also,",
        "Replace stiff transition",
    ),
    (
        re.compile(r"\bdelve(?:\s+deeply)?\s+into\b", re.IGNORECASE),
        "examine",
        "Replace verbose verb 'delve into'",
    ),
    (
        re.compile(r"\bplays\s+a\s+(?:pivotal|vital|crucial|key)\s+role\s+in\b", re.IGNORECASE),
        "directly affects",
        "Replace boilerplate phrasing 'plays a pivotal role'",
    ),
    (
        re.compile(r"\bstands\s+as\s+a\s+testament\s+to\b", re.IGNORECASE),
        "demonstrates",
        "Replace boilerplate phrasing 'stands as a testament'",
    ),
    (
        re.compile(r"\ba\s+crucial\s+aspect\s+of\b", re.IGNORECASE),
        "key to",
        "Simplify filler 'a crucial aspect of'",
    ),
    (
        re.compile(r"\bmultifaceted\b", re.IGNORECASE),
        "complex",
        "Replace overused buzzword 'multifaceted'",
    ),
    (
        re.compile(r"\bit\s+can\s+be\s+observed\s+that\b", re.IGNORECASE),
        "was observed that",
        "Use direct technical observation",
    ),
    (
        re.compile(r"\ba\s+cornerstone\s+of\b", re.IGNORECASE),
        "essential for",
        "Replace cliché metaphor 'cornerstone'",
    ),
    (
        re.compile(r"\bfosters\s+a\b", re.IGNORECASE),
        "supports",
        "Replace buzzword 'fosters'",
    ),
    (
        re.compile(r"\bit\s+is\s+crucial\s+to\b", re.IGNORECASE),
        "it is necessary to",
        "Use direct technical necessity",
    ),
    (
        re.compile(r"\bin\s+today's\s+(?:fast-paced\s+)?world\b", re.IGNORECASE),
        "in practice",
        "Purge throat-clearing intro",
    ),
    (
        re.compile(r"\bunderscores\s+the\s+importance\s+of\b", re.IGNORECASE),
        "highlights",
        "Simplify overused verb 'underscores'",
    ),
]


@dataclass
class NaturalnessAuditReport:
    """Detailed audit metrics of technical prose conciseness and cadence variance."""

    char_count: int
    word_count: int
    sentence_count: int
    avg_sentence_length: float
    sentence_length_std: float
    coefficient_of_variation: float  # CV = sigma / mu (Burstiness proxy)
    barabasi_burstiness: float       # B = (sigma - mu) / (sigma + mu), in [-1, 1]
    type_token_ratio: float          # TTR (Vocabulary diversity)
    cliches_detected_count: int
    cliches_detected: List[Dict[str, str]]
    style_risk_score: float          # Heuristic boilerplate & uniformity score [0.0 - 1.0]
    passes_style_gate: bool          # True if style_risk_score < 0.25, CV >= 0.40, and 0 cliches
    recommendations: List[str]


class TextNaturalizer:
    """
    Core style linter and prose simplifier for technical RFCs and telemetry logs.
    Performs boilerplate cliché scrubbing, sentence-length variance analysis, and voice normalization.
    """

    def __init__(self, mode: str = "rfc_technical"):
        """
        :param mode: 'rfc_technical' (impersonal RFC/specification prose)
                     or 'systems_telemetry' (embedded/systems diagnostic voice)
        """
        self.mode = mode

    def split_sentences(self, text: str) -> List[str]:
        """Splits text into sentences safely without breaking on decimals or abbreviations."""
        if not text or not text.strip():
            return []

        protected = re.sub(
            r"(\d+)\.(\d+)",
            lambda m: m.group(1) + "§DEC§" + m.group(2),
            text,
        )

        for abbr in ALL_ABBREVIATIONS:
            safe_abbr = abbr.replace(".", "§DOT§")
            pattern = re.compile(re.escape(abbr), re.IGNORECASE)
            protected = pattern.sub(safe_abbr, protected)

        raw_splits = re.split(r"(?<=[.!?;])\s+", protected)

        sentences: List[str] = []
        for s in raw_splits:
            restored = s.replace("§DEC§", ".").replace("§DOT§", ".").strip()
            if restored:
                sentences.append(restored)

        return sentences

    def count_words(self, text: str) -> List[str]:
        """Extracts word tokens from text, filtering pure punctuation."""
        return re.findall(r"\b[\w\u0370-\u03FF-]+\b", text)

    def compute_metrics(self, text: str) -> Dict[str, Any]:
        """Computes statistical metrics (burstiness, CV, TTR) on the input text."""
        sentences = self.split_sentences(text)
        if not sentences:
            return {
                "word_count": 0,
                "sentence_count": 0,
                "avg_sentence_length": 0.0,
                "sentence_length_std": 0.0,
                "coefficient_of_variation": 0.0,
                "barabasi_burstiness": -1.0,
                "type_token_ratio": 0.0,
            }

        sentence_lengths = [len(self.count_words(s)) for s in sentences]
        sentence_lengths = [length for length in sentence_lengths if length > 0] or [1]

        n = len(sentence_lengths)
        mu = sum(sentence_lengths) / n
        sigma = (
            math.sqrt(sum((length - mu) ** 2 for length in sentence_lengths) / (n - 1))
            if n > 1
            else 0.0
        )

        cv = (sigma / mu) if mu > 0 else 0.0
        burstiness = ((sigma - mu) / (sigma + mu)) if (sigma + mu) > 0 else -1.0

        all_words = self.count_words(text.lower())
        total_words = len(all_words)
        unique_words = len(set(all_words))
        ttr = (unique_words / total_words) if total_words > 0 else 0.0

        return {
            "word_count": total_words,
            "sentence_count": n,
            "avg_sentence_length": round(mu, 2),
            "sentence_length_std": round(sigma, 2),
            "coefficient_of_variation": round(cv, 3),
            "barabasi_burstiness": round(burstiness, 3),
            "type_token_ratio": round(ttr, 3),
        }

    def detect_cliches(self, text: str) -> List[Dict[str, str]]:
        """Identifies verbose boilerplate cliché patterns present in the text."""
        detected: List[Dict[str, str]] = []
        for pattern, replacement, desc in CLICHE_RULES_EL:
            for match in pattern.finditer(text):
                detected.append({
                    "matched_text": match.group(0),
                    "suggested_replacement": replacement,
                    "description": desc,
                    "lang": "el",
                })

        for pattern, replacement, desc in CLICHE_RULES_EN:
            for match in pattern.finditer(text):
                detected.append({
                    "matched_text": match.group(0),
                    "suggested_replacement": replacement,
                    "description": desc,
                    "lang": "en",
                })

        return detected

    def purge_cliches(self, text: str) -> Tuple[str, int]:
        """Deterministically scrubs all blocklisted boilerplate clichés."""
        cleaned = text
        changes_count = 0

        for pattern, replacement, _ in CLICHE_RULES_EL + CLICHE_RULES_EN:
            new_text, count = pattern.subn(replacement, cleaned)
            if count > 0:
                cleaned = new_text
                changes_count += count

        cleaned = re.sub(r"\s*,\s*,+", ",", cleaned)
        cleaned = re.sub(r"(?<=[.!?;])\s*,\s*", " ", cleaned)
        cleaned = re.sub(r"^[,\s]+", "", cleaned)
        cleaned = re.sub(r"[ \t]+", " ", cleaned)
        cleaned = re.sub(r"\n\s*[,.]\s*\n", "\n\n", cleaned)

        cleaned = re.sub(
            r"(^|[.!?;]\s+)([a-z\u03B1-\u03C9])",
            lambda m: m.group(1) + m.group(2).upper(),
            cleaned,
        )

        return cleaned.strip(), changes_count

    def apply_voice_naturalization(self, text: str) -> str:
        """Converts colloquial 1st-person plural phrasing to objective technical/RFC voice."""
        res = text
        if self.mode in ("rfc_technical", "academic_technical"):
            transformations = [
                (re.compile(r"\bμετρήσαμε\b", re.IGNORECASE), "μετρήθηκε"),
                (re.compile(r"\bκαταγράψαμε\b", re.IGNORECASE), "καταγράφηκε"),
                (re.compile(r"\bυπολογίσαμε\b", re.IGNORECASE), "υπολογίστηκε"),
                (re.compile(r"\bδιαπιστώσαμε\b", re.IGNORECASE), "διαπιστώθηκε"),
                (re.compile(r"\bεφαρμόσαμε\b", re.IGNORECASE), "εφαρμόστηκε"),
                (re.compile(r"\bit\s+was\s+observed\s+that\s+there\s+is\b", re.IGNORECASE), "was recorded"),
                (re.compile(r"\bwe\s+measured\b", re.IGNORECASE), "was measured"),
                (re.compile(r"\bwe\s+calculated\b", re.IGNORECASE), "was calculated"),
                (re.compile(r"\bwe\s+benchmarked\b", re.IGNORECASE), "was benchmarked"),
            ]
            for pattern, replacement in transformations:
                res = pattern.sub(replacement, res)

        elif self.mode == "systems_telemetry":
            transformations = [
                (re.compile(r"\bthe\s+system\s+diverges\b", re.IGNORECASE), "the state estimator diverged"),
                (re.compile(r"\bwe\s+observed\s+latency\b", re.IGNORECASE), "telemetry recorded latency"),
                (re.compile(r"\bwe\s+sampled\s+jitter\b", re.IGNORECASE), "profiler sampled jitter"),
            ]
            for pattern, replacement in transformations:
                res = pattern.sub(replacement, res)

        return res

    def naturalize(self, text: str) -> str:
        """Runs full pipeline: boilerplate scrub + technical voice normalization."""
        if not text:
            return ""
        cleaned, _ = self.purge_cliches(text)
        return self.apply_voice_naturalization(cleaned)

    def audit(self, text: str) -> NaturalnessAuditReport:
        """Runs comprehensive style audit assessing burstiness, TTR, and boilerplate risk."""
        metrics = self.compute_metrics(text)
        cliches = self.detect_cliches(text)
        cliche_count = len(cliches)

        cv = metrics["coefficient_of_variation"]
        ttr = metrics["type_token_ratio"]
        word_count = metrics["word_count"]

        risk = 0.10
        risk += min(0.50, cliche_count * 0.15)

        if cv < 0.30 and word_count > 40:
            risk += 0.30
        elif cv < 0.45 and word_count > 40:
            risk += 0.15
        elif cv >= 0.60:
            risk -= 0.10

        if ttr < 0.35 and word_count > 60:
            risk += 0.15
        elif ttr > 0.55:
            risk -= 0.05

        risk = max(0.0, min(1.0, round(risk, 2)))

        recs: List[str] = []
        if cliche_count > 0:
            recs.append(f"Detected {cliche_count} boilerplate phrasing marker(s). Run purge_cliches() to scrub.")
        if cv < 0.45 and word_count > 40:
            recs.append(f"Low sentence-length variance (CV = {cv} < 0.45). Mix concise statements (4-7 words) with detailed clauses.")
        if metrics["avg_sentence_length"] > 28.0:
            recs.append(f"High average sentence length ({metrics['avg_sentence_length']} words). Split long clauses.")
        if ttr < 0.40 and word_count > 50:
            recs.append(f"Low vocabulary diversity (TTR = {ttr}). Use more specific technical terminology.")

        if not recs:
            recs.append("Text exhibits balanced sentence cadence and zero detected boilerplate markers.")

        passes_gate = risk < 0.25 and (cv >= 0.40 or word_count <= 40) and cliche_count == 0

        return NaturalnessAuditReport(
            char_count=len(text),
            word_count=metrics["word_count"],
            sentence_count=metrics["sentence_count"],
            avg_sentence_length=metrics["avg_sentence_length"],
            sentence_length_std=metrics["sentence_length_std"],
            coefficient_of_variation=metrics["coefficient_of_variation"],
            barabasi_burstiness=metrics["barabasi_burstiness"],
            type_token_ratio=metrics["type_token_ratio"],
            cliches_detected_count=cliche_count,
            cliches_detected=cliches,
            style_risk_score=risk,
            passes_style_gate=passes_gate,
            recommendations=recs,
        )


def naturalize_text(text: str, mode: str = "rfc_technical") -> str:
    """Simplifies text by stripping boilerplate phrasing and enforcing objective technical voice."""
    return TextNaturalizer(mode=mode).naturalize(text)


def audit_text_naturalness(text: str, mode: str = "rfc_technical") -> Dict[str, Any]:
    """Runs a technical style audit and returns a dictionary of metrics and style risk score."""
    return asdict(TextNaturalizer(mode=mode).audit(text))


def purge_style_cliches(text: str) -> str:
    """Removes blocklisted boilerplate phrasing and verbose transitions."""
    res, _ = TextNaturalizer().purge_cliches(text)
    return res


def purge_ai_cliches(text: str) -> str:
    """Backward-compatible alias for purge_style_cliches."""
    return purge_style_cliches(text)


def compute_burstiness_metrics(text: str) -> Dict[str, Any]:
    """Computes sentence length distribution and burstiness metrics."""
    return TextNaturalizer().compute_metrics(text)


def main() -> int:
    parser = argparse.ArgumentParser(description="Technical Prose Simplifier & Style Linter")
    parser.add_argument("input_path", nargs="?", help="Path to text or markdown file (or stdin)")
    parser.add_argument("--mode", choices=["rfc_technical", "systems_telemetry"], default="rfc_technical")
    parser.add_argument("--clean", action="store_true", help="Output simplified technical prose")
    parser.add_argument("--json", action="store_true", help="Output audit report as JSON")
    args = parser.parse_args()

    if args.input_path and Path(args.input_path).exists():
        content = Path(args.input_path).read_text(encoding="utf-8")
    else:
        if sys.stdin.isatty():
            parser.print_help()
            return 1
        content = sys.stdin.read()

    naturalizer = TextNaturalizer(mode=args.mode)

    if args.clean:
        sys.stdout.write(naturalizer.naturalize(content) + "\n")
        return 0

    report = naturalizer.audit(content)
    if args.json:
        print(json.dumps(asdict(report), indent=2, ensure_ascii=False))
    else:
        print("=== TECHNICAL STYLE & CADENCE AUDIT REPORT ===")
        print(f"Words: {report.word_count} | Sentences: {report.sentence_count}")
        print(f"Avg Sentence Length: {report.avg_sentence_length} words (sigma = {report.sentence_length_std})")
        print(f"Burstiness (CV): {report.coefficient_of_variation} (Target: >= 0.45)")
        print(f"Barabasi Burstiness: {report.barabasi_burstiness} (Target: >= -0.20)")
        print(f"Type-Token Ratio: {report.type_token_ratio}")
        print(f"Cliches Detected: {report.cliches_detected_count}")
        print(f"Style Risk Score: {int(report.style_risk_score * 100)}% (Passes Style Gate: {report.passes_style_gate})")
        print("\nRecommendations:")
        for r in report.recommendations:
            print(f" - {r}")

    return 0 if report.passes_style_gate else 2


if __name__ == "__main__":
    sys.exit(main())
