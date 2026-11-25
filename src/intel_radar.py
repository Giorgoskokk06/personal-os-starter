#!/usr/bin/env python3
"""
src/intel_radar.py - Multi-Perspective Macro & Geopolitical Signal Filter.

Filters out alarmist clickbait and doom-scrolling via:
- 6 diverse global source clusters (wire, macro rates, energy/maritime, tech/semicon, EU policy, emerging/state framing)
- 4-tier anti-panic assessment (NOISE_CLICKBAIT, CONTROLLED_TENSION, HIGH_SIGNAL_STRUCTURAL, CRITICAL_ESCALATION)
- Negation-aware & word-boundary stem scoring (e.g. "no escalation" and "ceasefire talks" do not trigger panic)
- XXE/DTD rejection, 1MB payload cap, BiDi/control char sanitization, parallel ThreadPoolExecutor fetching
- Honest source attribution ([LIVE ...] vs [ARCHIVE FALLBACK - not current news])
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import html
import json
import logging
from pathlib import Path
import re
import sys
import unicodedata
from typing import Any, Dict, List, Optional, Tuple, Union
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

logger = logging.getLogger("intel_radar")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [intel_radar] %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

MAX_PAYLOAD_BYTES = 1_000_000
STATE_BASELINE_PATH = REPO_ROOT / "state" / "geopolitical_baseline.yaml"
EXAMPLE_BASELINE_PATH = REPO_ROOT / "state.example" / "geopolitical_baseline.yaml"
BASELINE_PATH = STATE_BASELINE_PATH if STATE_BASELINE_PATH.exists() else EXAMPLE_BASELINE_PATH

_INVISIBLE_CHARS_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\u061c\ufeff\U000e0000-\U000e007f\x00-\x1f\x7f-\x9f]"
)

DEFAULT_KNOWN_ACRONYMS = {
    "EU", "NATO", "ECB", "FED", "OPEC", "OECD", "IMF", "BIS", "WTO", "UN",
    "UNCLOS", "BRENT", "LNG", "TTF", "CDS", "GDP", "CPI", "FX", "AI", "GPU",
    "TSMC", "EUV", "US", "UK", "BRICS", "SWIFT", "IMEC",
}

DEFAULT_NEGATORS = [
    "no", "not", "never", "without", "denies", "denied", "denying",
    "rules out", "ruled out", "rule out", "avoids", "averted", "halts", "unlikely",
]

DEFAULT_DEESCALATORY_PHRASES = [
    "ceasefire talks", "peace talks", "de-escalation", "deescalation",
    "diplomatic resolution", "truce agreement", "stand down", "talks advance", "talks resume",
]

DEFAULT_CRITICAL_INDICATORS = [
    "general mobilization", "call-up of reserves", "call up of reserves",
    "airspace closed", "closed airspace", "embassy evacuation", "evacuation of embassy",
    "capital controls", "bank holiday", "declaration of war", "nuclear strike",
    "naval blockade", "maritime blockade", "strait closed", "mass casualties", "shot down",
]

DEFAULT_ALARMIST_KEYWORDS = [
    "war", "ww3", "world war 3", "world war iii", "imminent invasion",
    "total war", "breaking war", "armageddon", "war footing", "apocalyptic",
    "escalation imminent", "escalation", "bombshell", "bloodbath",
    "shocking", "catastrophic", "panic", "chaos", "ultimatum", "alarm",
    "collapse", "strike now",
]

DEFAULT_STRUCTURAL_INDICATORS = [
    "cds", "bond yield", "spread", "bund", "treasury", "lng", "brent", "ttf",
    "opec", "sanctions", "interest rate", "inflation", "defense budget",
    "bilateral trade", "unclos", "maritime", "freight", "ecb", "fed",
    "procurement", "supply chain", "semiconductor", "foundry", "export control",
    "dual-use", "treaty", "tariff", "ceasefire", "diplomatic",
]


def _strip_accents(text: str) -> str:
    """Normalize text by stripping combining diacritics and lowercasing."""
    if not text:
        return ""
    normalized = unicodedata.normalize("NFD", text)
    stripped = "".join(c for c in normalized if unicodedata.category(c) != "Mn")
    return stripped.lower().strip()


def sanitize_headline(title: str) -> str:
    """
    Neutralize format injections, control/BiDi smuggling, and prompt injections:
    - strips C0/C1 control and invisible BiDi/tag characters
    - collapses whitespace
    - escapes markdown link delimiters ([ ]) and leading heading prefixes (#)
    - truncates to 200 characters
    """
    if not title:
        return ""
    s = unicodedata.normalize("NFKC", str(title))
    s = _INVISIBLE_CHARS_RE.sub("", s)
    s = " ".join(s.split())
    s = s.replace("[", "\\[").replace("]", "\\]")
    if s.startswith("#"):
        s = "\\" + s
    return s[:200].strip()


def _clean_html_text(raw_html: str) -> str:
    """Strip HTML tags and unescape entities."""
    if not raw_html:
        return ""
    clean = re.sub(r"<[^>]+>", " ", raw_html)
    clean = html.unescape(clean)
    return " ".join(clean.split()).strip()


def load_geopolitical_baseline(path: Optional[Union[Path, str]] = None) -> Dict[str, Any]:
    """
    Load baseline config from state/geopolitical_baseline.yaml, falling back to
    state.example/geopolitical_baseline.yaml and then built-in defaults.
    """
    candidates = [Path(path)] if path else [STATE_BASELINE_PATH, EXAMPLE_BASELINE_PATH]
    for target_path in candidates:
        if target_path.exists():
            try:
                with open(target_path, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                    if isinstance(data, dict):
                        return data
            except Exception as exc:
                logger.warning("Failed to parse %s: %s. Trying fallback.", target_path, exc)

    return {
        "schema_version": "4.0",
        "engine": "Personal OS Multi-Perspective Macro & Geopolitical Signal Filter",
        "profile_relevance_weights": {
            "energy_inflation_macro": 0.30,
            "maritime_logistics_corridors": 0.25,
            "semiconductor_supply_chain": 0.25,
            "european_industrial_policy": 0.20,
        },
        "historical_doctrines": {
            "government_debt_market_pricing": {
                "id": "government_debt_market_pricing",
                "title": "Capital Market Risk Pricing vs. Media Sensationalism (Market Reality Check)",
                "year": "1990-2026",
                "summary": "Government bond spreads, CDS, and FX implied volatility reprice structural risk earlier than headlines.",
                "game_theory_reality": "Flat credit spreads and commodity curves indicate rhetorical noise rather than acute disruption.",
                "red_line_trigger": "Sustained >25 bps spread widening paired with >5% commodity/freight repricing.",
                "keywords": ["spread", "bond yield", "cds", "ecb", "fed", "inflation"],
            },
            "maritime_chokepoint_elasticity": {
                "id": "maritime_chokepoint_elasticity",
                "title": "Maritime Chokepoints & Freight Elasticity",
                "year": "1956-2026",
                "summary": "Localized chokepoint friction causes vessel rerouting without collapsing global trade unless blockaded.",
                "game_theory_reality": "Shipping networks absorb route changes via freight rates and insurance adjustments.",
                "red_line_trigger": "Verified strait closure or formal naval blockade.",
                "keywords": ["suez", "hormuz", "red sea", "maritime", "shipping", "freight"],
            },
        },
        "source_clusters": {},
        "critical_indicators": DEFAULT_CRITICAL_INDICATORS,
        "alarmist_keywords": DEFAULT_ALARMIST_KEYWORDS,
        "negators": DEFAULT_NEGATORS,
        "deescalatory_phrases": DEFAULT_DEESCALATORY_PHRASES,
        "known_acronyms": list(DEFAULT_KNOWN_ACRONYMS),
        "structural_indicators": DEFAULT_STRUCTURAL_INDICATORS,
    }


def _is_token_negated(tokens: List[str], target_idx: int, negators: List[str], window: int = 3) -> bool:
    """
    Check if a negator appears within ~3 tokens before target_idx.
    Supports single-word negators (e.g. 'no', 'not') and multi-word negators (e.g. 'rules out').
    """
    start_idx = max(0, target_idx - window)
    preceding = tokens[start_idx:target_idx]
    for i, tok in enumerate(preceding):
        for neg in negators:
            neg_norm = _strip_accents(neg)
            if not neg_norm:
                continue
            if " " in neg_norm or "-" in neg_norm:
                n_words = neg_norm.replace("-", " ").split()
                if preceding[i : i + len(n_words)] == n_words:
                    return True
            else:
                if tok == neg_norm or (len(neg_norm) >= 4 and tok.startswith(neg_norm)):
                    return True
    return False


def _token_matches_word_or_stem(token: str, pat_word: str) -> bool:
    """
    Match token against pattern word using word boundaries for short tokens (<= 4 chars)
    to avoid false positives (e.g., 'war' matching 'forward' or 'warning').
    """
    if len(pat_word) <= 4:
        return token == pat_word or token == f"{pat_word}s"
    return token == pat_word or token.startswith(pat_word)


def _find_matches_with_negation(
    tokens: List[str],
    patterns: List[str],
    negators: List[str],
    window: int = 3,
    max_skip: int = 2,
) -> Tuple[List[str], List[str]]:
    """
    Match word-boundary/stem patterns against a token stream while respecting negation boundaries.
    Returns: (matched_active_patterns, matched_negated_patterns)
    """
    active_matches: List[str] = []
    negated_matches: List[str] = []

    for pat in patterns:
        pat_norm = _strip_accents(pat)
        if not pat_norm:
            continue

        pat_words = pat_norm.replace("-", " ").split()
        if len(pat_words) == 1:
            stem = pat_words[0]
            for idx, tok in enumerate(tokens):
                if _token_matches_word_or_stem(tok, stem):
                    if _is_token_negated(tokens, idx, negators, window=window):
                        if pat not in negated_matches:
                            negated_matches.append(pat)
                    else:
                        if pat not in active_matches:
                            active_matches.append(pat)
                    break
        else:
            for i, tok in enumerate(tokens):
                if _token_matches_word_or_stem(tok, pat_words[0]):
                    curr_idx = i
                    matched_phrase = True
                    for next_word in pat_words[1:]:
                        found = False
                        for step in range(1, max_skip + 2):
                            if curr_idx + step < len(tokens):
                                if _token_matches_word_or_stem(tokens[curr_idx + step], next_word):
                                    curr_idx = curr_idx + step
                                    found = True
                                    break
                        if not found:
                            matched_phrase = False
                            break

                    if matched_phrase:
                        if _is_token_negated(tokens, i, negators, window=window):
                            if pat not in negated_matches:
                                negated_matches.append(pat)
                        else:
                            if pat not in active_matches:
                                active_matches.append(pat)
                        break

    return active_matches, negated_matches


def resolve_claim_or_url(
    claim_or_url: str,
    offline: bool = False,
    timeout: float = 3.0,
) -> Tuple[str, Optional[str]]:
    """
    If input is a URL:
    - Online: safely fetch page <title> (capped at 1MB, timeout 3s).
    - Offline (or fetch fails): derive text cleanly from URL slug.
    """
    raw_text = claim_or_url.strip()
    if not re.match(r"^https?://", raw_text, re.IGNORECASE):
        return raw_text, None

    url = raw_text
    parsed = urllib.parse.urlparse(url)

    if not offline:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Personal-OS-IntelRadar/4.0 (Macro & Geopolitical Signal Filter; Linux x86_64)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw_bytes = resp.read(MAX_PAYLOAD_BYTES)
                html_text = raw_bytes.decode("utf-8", errors="replace")
                m = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
                if m:
                    extracted = sanitize_headline(_clean_html_text(m.group(1)))
                    if extracted:
                        return extracted, f"Page title fetched from URL ({url})"
        except Exception as exc:
            logger.debug("URL page title fetch failed for %s: %s. Falling back to slug.", url, exc)

    path_segments = [p for p in parsed.path.strip("/").split("/") if p]
    slug = path_segments[-1] if path_segments else parsed.netloc
    slug = re.sub(r"\.[a-zA-Z0-9]+$", "", slug)
    slug_text = re.sub(r"[-_+]+", " ", slug).strip() or parsed.netloc
    derived = sanitize_headline(slug_text)
    return derived, f'Derived text from URL slug: "{derived}"'


def calculate_panic_vs_signal(text: str, baseline: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Compute panic_score (0-100), structural_score (0-100), and 4-tier verdict:
    - CRITICAL_ESCALATION
    - NOISE_CLICKBAIT
    - CONTROLLED_TENSION
    - HIGH_SIGNAL_STRUCTURAL

    Applies word-boundary/stem matching, negation windowing (~3 tokens),
    de-escalatory phrase dampening (e.g. 'ceasefire talks', 'de-escalation'),
    and known-acronym shout filtering.
    """
    if baseline is None:
        baseline = load_geopolitical_baseline()

    norm_text = _strip_accents(text)
    tokens = re.findall(r"[\w]+", norm_text)

    critical_indicators = baseline.get("critical_indicators", DEFAULT_CRITICAL_INDICATORS)
    alarmist_keywords = baseline.get("alarmist_keywords", DEFAULT_ALARMIST_KEYWORDS)
    structural_indicators = baseline.get("structural_indicators", DEFAULT_STRUCTURAL_INDICATORS)
    negators = baseline.get("negators", DEFAULT_NEGATORS)
    deescalatory_phrases = baseline.get("deescalatory_phrases", DEFAULT_DEESCALATORY_PHRASES)
    known_acronyms_list = baseline.get("known_acronyms", list(DEFAULT_KNOWN_ACRONYMS))
    known_acronyms = set(known_acronyms_list).union(DEFAULT_KNOWN_ACRONYMS)

    # 1. Critical indicators (with negation)
    matched_critical, negated_critical = _find_matches_with_negation(
        tokens, critical_indicators, negators, window=3
    )

    # 2. De-escalatory phrases (ceasefire talks, de-escalation, etc.)
    matched_deescalation: List[str] = []
    for phrase in deescalatory_phrases:
        p_norm = _strip_accents(phrase)
        if p_norm and re.search(r"\b" + re.escape(p_norm) + r"\b", norm_text):
            matched_deescalation.append(phrase)

    # Prevent substring "escalation" from firing falsely on "de-escalation"
    effective_alarmist = list(alarmist_keywords)
    if "de-escalation" in norm_text or "deescalation" in norm_text:
        effective_alarmist = [k for k in effective_alarmist if _strip_accents(k) != "escalation"]

    # 3. Alarmist keywords (with negation)
    matched_alarmist, negated_alarmist = _find_matches_with_negation(
        tokens, effective_alarmist, negators, window=3
    )

    # 4. Structural indicators (word-boundary aware)
    matched_structural: List[str] = []
    for st in structural_indicators:
        st_norm = _strip_accents(st)
        if not st_norm:
            continue
        if " " in st_norm or "-" in st_norm:
            if re.search(r"\b" + re.escape(st_norm) + r"\b", norm_text):
                matched_structural.append(st)
        else:
            if any(_token_matches_word_or_stem(tok, st_norm) for tok in tokens):
                matched_structural.append(st)

    # 5. Sensational formatting check (ignoring known financial/institutional acronyms)
    exclamation_count = text.count("!")
    raw_words = text.split()
    caps_words = []
    for w in raw_words:
        clean_w = re.sub(r"^[^\w]+|[^\w]+$", "", w)
        if clean_w.isupper() and len(clean_w) >= 2 and clean_w not in known_acronyms:
            caps_words.append(clean_w)

    # 6. Panic score
    panic_score = len(matched_alarmist) * 25
    if exclamation_count >= 1:
        panic_score += min(exclamation_count * 5, 15)
    if caps_words:
        panic_score += min(len(caps_words) * 10, 20)
    if negated_alarmist or negated_critical:
        panic_score = max(0, panic_score - 20)
    if matched_deescalation:
        panic_score = max(0, panic_score - 25)
    panic_score = min(max(panic_score, 0), 100)
    if not matched_alarmist and exclamation_count == 0 and not caps_words:
        panic_score = 5

    # 7. Structural score
    structural_score = len(matched_structural) * 30
    if matched_deescalation:
        structural_score += 20
    if re.search(r"\d+(\.\d+)?\s*(%|€|\$|bps|bbl|mwh)", norm_text) or re.search(r"\b\d+\b", norm_text):
        structural_score += 15
    structural_score = min(max(structural_score, 0), 100)
    if not matched_structural and not matched_deescalation:
        structural_score = 10

    # 8. Determine 4-Tier Verdict & Engineering/Portfolio Posture
    if matched_critical:
        verdict = "CRITICAL_ESCALATION"
        panic_score = max(panic_score, 85)
        structural_score = max(structural_score, 85)
        posture = (
            "CRITICAL ESCALATION - OPERATIONAL RESILIENCE POSTURE:\n"
            "* Official Channels Only: Monitor primary central-bank, maritime-authority, and civil-advisory feeds; ignore unverified social feeds.\n"
            "* Capital & Liquidity Shield: Freeze discretionary infrastructure or hardware capital commitments and preserve liquid buffers.\n"
            "* Telemetry Discipline: Cap news checks to at most 2 scheduled briefings per day to protect engineering execution focus."
        )
    elif panic_score >= 60 and structural_score < 45:
        verdict = "NOISE_CLICKBAIT"
        posture = (
            "Engineering & Portfolio Posture: No action required - sensational headline framing without "
            "structural market repricing. Keep weekly workload within buffer limits (rho <= 0.75) "
            "and focus on scheduled engineering deliverables."
        )
    elif structural_score >= 50 and panic_score < 45:
        verdict = "HIGH_SIGNAL_STRUCTURAL"
        posture = (
            "Engineering & Portfolio Posture: Structural signal detected - monitor government 10Y spreads, "
            "Brent/TTF energy curves, and semiconductor supply lead times. Adjust cloud/hardware capex "
            "assumptions only if multi-week market repricing persists."
        )
    else:
        verdict = "CONTROLLED_TENSION"
        posture = (
            "Engineering & Portfolio Posture: No action required - headline volatility without structural "
            "market repricing. Maintain steady deep-work cadence and zero reactive portfolio churn."
        )

    return {
        "panic_score": panic_score,
        "structural_score": structural_score,
        "verdict": verdict,
        "matched_alarmist": matched_alarmist,
        "matched_structural": matched_structural,
        "matched_critical": matched_critical,
        "negated_matches": negated_alarmist + negated_critical,
        "deescalatory_matches": matched_deescalation,
        "engineering_portfolio_posture": posture,
    }


def match_historical_context(text: str, baseline: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Match input text against structural/historical baselines.
    Guarantees at least top-2 relevant baselines are returned for context grounding.
    """
    if baseline is None:
        baseline = load_geopolitical_baseline()

    doctrines = baseline.get("historical_doctrines", {})
    norm_text = _strip_accents(text)

    scored_doctrines: List[Tuple[float, Dict[str, Any]]] = []
    relevance_weights = baseline.get("profile_relevance_weights", {})

    for doc_id, doc in doctrines.items():
        score = 0.0
        for kw in doc.get("keywords", []):
            kw_norm = _strip_accents(kw)
            if not kw_norm:
                continue
            if " " in kw_norm or "-" in kw_norm:
                if kw_norm in norm_text:
                    score += 12.0
            elif re.search(r"\b" + re.escape(kw_norm) + r"\b", norm_text):
                score += 8.0

        title_norm = _strip_accents(doc.get("title", ""))
        for token in [t for t in title_norm.split() if len(t) >= 4]:
            if token in norm_text:
                score += 3.0

        if "energy" in doc_id or "government" in doc_id:
            score += relevance_weights.get("energy_inflation_macro", 0.30) * 10.0
        if "maritime" in doc_id:
            score += relevance_weights.get("maritime_logistics_corridors", 0.25) * 10.0
        if "semiconductor" in doc_id:
            score += relevance_weights.get("semiconductor_supply_chain", 0.25) * 10.0
        if "european" in doc_id:
            score += relevance_weights.get("european_industrial_policy", 0.20) * 10.0

        scored_doctrines.append((score, doc))

    scored_doctrines.sort(key=lambda x: x[0], reverse=True)
    matched = [d for s, d in scored_doctrines if s > 0]
    for _, d in scored_doctrines:
        if len(matched) >= 2:
            break
        if d not in matched:
            matched.append(d)

    return matched[:3]


def build_dialectical_matrix(
    topic_or_claim: str,
    fetched_items: Optional[Union[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]] = None,
    baseline: Optional[Dict[str, Any]] = None,
    offline: bool = False,
) -> Dict[str, Any]:
    """
    Construct a multi-perspective signal breakdown:
    - Signal assessment (4-tier anti-panic classification)
    - Institutional & Transatlantic Policy Desk (Thesis)
    - Counter-Narrative / Emerging & State Framing (Antithesis - tagged strictly as posture)
    - Global Capital Markets & Commodities (Market Reality Check)
    - Structural/Historical Continuity
    - Incentives summary
    - Engineering & Portfolio Posture
    """
    if baseline is None:
        baseline = load_geopolitical_baseline()

    effective_claim, url_note = resolve_claim_or_url(topic_or_claim, offline=offline)
    signal_assessment = calculate_panic_vs_signal(effective_claim, baseline)
    matched_doctrines = match_historical_context(effective_claim, baseline)
    norm_claim = _strip_accents(effective_claim)

    flat_items: List[Dict[str, Any]] = []
    if isinstance(fetched_items, dict):
        for c_k, c_list in fetched_items.items():
            for it in c_list:
                item_copy = dict(it)
                item_copy.setdefault("cluster", c_k)
                flat_items.append(item_copy)
    elif isinstance(fetched_items, list):
        flat_items = list(fetched_items)

    policy_live = [
        it for it in flat_items
        if it.get("cluster") in {"european_policy_desk", "global_wire", "tech_semiconductor_supply"}
    ]
    counter_live = [it for it in flat_items if it.get("cluster") == "emerging_global_south"]
    markets_live = [
        it for it in flat_items
        if it.get("cluster") in {"macro_rates_markets", "energy_maritime_chokepoints"}
    ]

    def _render_live_subblock(items: List[Dict[str, Any]]) -> str:
        if not items:
            return ""
        lines = ["**Related Headlines:**"]
        for it in items[:2]:
            badge = (
                "[ARCHIVE FALLBACK - not current news]"
                if it.get("is_fallback", True)
                else f"[LIVE {it.get('pubDate', '')}]"
            )
            lines.append(f"- {badge} **{it.get('source', 'Source')}:** [{it.get('title')}]({it.get('link')})")
        lines.append("")
        return "\n".join(lines)

    if any(k in norm_claim for k in ["semiconductor", "chip", "tsmc", "export", "foundry", "euv", "gpu"]):
        p_thesis_static = (
            "* Regulatory & Supply Resilience: Allied export frameworks focus on leading-edge lithography "
            "and advanced AI packaging controls while subsidizing domestic fab diversification.\n"
            "* Infrastructure Redundancy: Telecom and cloud operators accelerate multi-path subsea cable "
            "and regional compute redundancy."
        )
        p_antithesis_static = (
            "* Alternative Localization Narrative: State-aligned commentators portray technology restrictions "
            "as catalysts for domestic mature-node self-sufficiency and alternative equipment supply chains."
        )
        p_markets_static = (
            "* Capital Market Reality Check: Track semiconductor equipment order backlogs, HBM spot pricing, "
            "and cloud lead times (check: 10Y spreads, Brent, TTF, SOX/foundry guidance - if flat, no acute shock)."
        )
    elif any(k in norm_claim for k in ["red sea", "hormuz", "suez", "brent", "ttf", "lng", "shipping", "maritime"]):
        p_thesis_static = (
            "* Maritime Security & Escort Protocols: Multilateral naval coalitions prioritize freedom of "
            "navigation under UNCLOS and defensive escort coverage for commercial shipping.\n"
            "* Storage & Grid Buffers: European gas reserves and LNG terminal diversity mitigate transit delays."
        )
        p_antithesis_static = (
            "* Asymmetric Corridor Leverage: Regional and non-Western actors leverage transit chokepoint "
            "risk and alternative overland/commodity corridors to extract diplomatic concessions."
        )
        p_markets_static = (
            "* Commodity & Freight Reality Check: Monitor Brent crude, Dutch TTF gas, and container/tanker "
            "war-risk premia (check: 10Y government spreads, Brent, TTF - if flat, markets are not pricing disruption)."
        )
    else:
        p_thesis_static = (
            "* Institutional Framing: Emphasis on treaty compliance, multilateral de-escalation channels, "
            "fiscal predictability, and cross-border industrial resilience.\n"
            "* Policy Continuity: Structural alignment across central-bank disinflation targets and grid/infrastructure capex."
        )
        p_antithesis_static = (
            "* Counter-Narrative & State Framing: Competing regional blocs use assertive media rhetoric "
            "for domestic signaling and bilateral negotiating leverage (read strictly as posture, not fact)."
        )
        p_markets_static = (
            "* Market Reality Check: Institutional capital filters rhetorical noise via government 10Y bond spreads, "
            "FX implied volatility, Brent crude, and TTF gas (if flat, markets are not pricing structural conflict)."
        )

    def _combine_perspective(live_txt: str, static_txt: str) -> str:
        parts = []
        if live_txt:
            parts.append(live_txt.strip())
        parts.append("**Doctrinal baseline framing (not live analysis):**")
        parts.append(static_txt.strip())
        return "\n\n".join(parts)

    p_thesis = _combine_perspective(_render_live_subblock(policy_live), p_thesis_static)
    p_antithesis = _combine_perspective(_render_live_subblock(counter_live), p_antithesis_static)
    p_markets = _combine_perspective(_render_live_subblock(markets_live), p_markets_static)

    cui_bono = (
        "1. Attention-Driven Media Platforms: Maximize clicks and ad impressions through alarmist headline framing.\n"
        "2. Domestic Political Messaging: Rally constituencies and deflect attention from inflation or fiscal trade-offs.\n"
        "3. State-Aligned Messaging Apparatus: Signal deterrence baselines and test diplomatic red lines externally.\n"
        "4. Hedging & Volatility Desks: Monetize short-term retail overreaction when underlying fundamentals remain flat."
    )

    return {
        "claim": topic_or_claim,
        "effective_claim": effective_claim,
        "url_source_note": url_note,
        "signal_assessment": signal_assessment,
        "perspective_policy_institutional": p_thesis,
        "perspective_counter_narrative": p_antithesis,
        "perspective_global_markets": p_markets,
        "historical_continuity": matched_doctrines,
        "cui_bono_incentives": cui_bono,
        "engineering_portfolio_posture": signal_assessment["engineering_portfolio_posture"],
        "fetched_items": flat_items,
    }


def _fetch_single_feed(
    feed: Dict[str, Any],
    c_key: str,
    max_per_source: int,
    timeout: float,
) -> List[Dict[str, Any]]:
    """Safely fetch and parse items from a single RSS/Atom feed with 1MB cap and XXE/DTD rejection."""
    feed_name = feed.get("name", "Unknown Feed")
    feed_url = feed.get("url", "")
    if not feed_url:
        return []

    items_out: List[Dict[str, Any]] = []
    try:
        req = urllib.request.Request(
            feed_url,
            headers={
                "User-Agent": "Personal-OS-IntelRadar/4.0 (Macro & Geopolitical Signal Filter; Linux x86_64)",
                "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            xml_bytes = resp.read(MAX_PAYLOAD_BYTES + 1)

        if len(xml_bytes) > MAX_PAYLOAD_BYTES:
            logger.warning("Rejecting payload from %s: exceeds 1MB cap.", feed_name)
            return []

        lower_bytes = xml_bytes.lower()
        if b"<!doctype" in lower_bytes or b"<!entity" in lower_bytes:
            logger.warning("Rejecting payload from %s: DTD/ENTITY declaration detected.", feed_name)
            return []

        root = ET.fromstring(xml_bytes)
        items = root.findall(".//item")
        if not items:
            items = root.findall(".//{http://www.w3.org/2005/Atom}entry")

        for el in items[:max_per_source]:
            title_el = el.find("title") if el.find("title") is not None else el.find("{http://www.w3.org/2005/Atom}title")
            link_el = el.find("link") if el.find("link") is not None else el.find("{http://www.w3.org/2005/Atom}link")
            pub_el = (
                el.find("pubDate")
                if el.find("pubDate") is not None
                else (el.find("{http://www.w3.org/2005/Atom}updated") or el.find("{http://www.w3.org/2005/Atom}published"))
            )
            desc_el = (
                el.find("description")
                if el.find("description") is not None
                else el.find("{http://www.w3.org/2005/Atom}summary")
            )

            raw_title = _clean_html_text(title_el.text if title_el is not None and title_el.text else "")
            title_text = sanitize_headline(raw_title)

            link_text = ""
            if link_el is not None:
                link_text = link_el.text or link_el.get("href", "")

            pub_text = pub_el.text.strip() if pub_el is not None and pub_el.text else ""
            if not pub_text:
                pub_text = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

            desc_text = sanitize_headline(_clean_html_text(desc_el.text if desc_el is not None and desc_el.text else ""))

            if title_text:
                items_out.append({
                    "title": title_text,
                    "link": link_text,
                    "pubDate": pub_text,
                    "source": feed_name,
                    "summary": desc_text,
                    "cluster": c_key,
                    "is_fallback": False,
                })
    except ET.ParseError as exc:
        logger.warning("XML parse error from feed %s (%s): %s. Falling back.", feed_name, feed_url, exc)
        return []
    except Exception as exc:
        logger.debug("Feed %s (%s) fetch failed: %s. Falling back.", feed_name, feed_url, exc)
        return []

    return items_out


def fetch_multi_source_headlines(
    clusters: Optional[List[str]] = None,
    max_per_source: int = 3,
    timeout: float = 3.0,
    offline: bool = False,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Fetch RSS/Atom XML items concurrently across the 6 global clusters using ThreadPoolExecutor:
    - bounded by per-feed timeout and 1MB payload cap
    - strict XML XXE/DTD rejection before parsing
    - honest [LIVE ...] vs [ARCHIVE FALLBACK - not current news] tagging
    """
    baseline = load_geopolitical_baseline()
    available_clusters = baseline.get("source_clusters", {})

    target_clusters = clusters if clusters else list(available_clusters.keys())
    results: Dict[str, List[Dict[str, Any]]] = {}

    if offline:
        for c_key in target_clusters:
            c_data = available_clusters.get(c_key, {})
            cluster_items: List[Dict[str, Any]] = []
            for fb in c_data.get("offline_fallbacks", [])[:max_per_source]:
                item = dict(fb)
                item["cluster"] = c_key
                item["is_fallback"] = True
                if not item.get("pubDate"):
                    item["pubDate"] = "Wed, 25 Nov 2026 08:00:00 GMT"
                item["title"] = sanitize_headline(item.get("title", ""))
                cluster_items.append(item)
            results[c_key] = cluster_items
        return results

    feed_tasks: List[Tuple[str, Dict[str, Any]]] = []
    for c_key in target_clusters:
        c_data = available_clusters.get(c_key, {})
        for feed in c_data.get("feeds", []):
            feed_tasks.append((c_key, feed))

    cluster_items_map: Dict[str, List[Dict[str, Any]]] = {c: [] for c in target_clusters}

    if feed_tasks:
        max_workers = min(16, len(feed_tasks))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_info = [
                (c_key, executor.submit(_fetch_single_feed, feed, c_key, max_per_source, timeout))
                for (c_key, feed) in feed_tasks
            ]
            for c_key, fut in future_to_info:
                try:
                    cluster_items_map[c_key].extend(fut.result())
                except Exception as exc:
                    logger.debug("Feed fetch future failed for cluster %s: %s", c_key, exc)

    for c_key in target_clusters:
        c_data = available_clusters.get(c_key, {})
        cluster_items = cluster_items_map.get(c_key, [])
        if not cluster_items:
            for fb in c_data.get("offline_fallbacks", [])[:max_per_source]:
                item = dict(fb)
                item["cluster"] = c_key
                item["is_fallback"] = True
                if not item.get("pubDate"):
                    item["pubDate"] = "Wed, 25 Nov 2026 08:00:00 GMT"
                item["title"] = sanitize_headline(item.get("title", ""))
                cluster_items.append(item)
        results[c_key] = cluster_items[:max_per_source]

    return results


def render_radar_briefing_markdown(
    headlines_by_cluster: Dict[str, List[Dict[str, Any]]],
    baseline: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Render a concise (< 400 words) multi-perspective briefing across all 6 global clusters
    with explicit LIVE vs ARCHIVE FALLBACK counts and an Engineering & Portfolio Posture.
    """
    if baseline is None:
        baseline = load_geopolitical_baseline()

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_live = sum(
        1 for items in headlines_by_cluster.values() for it in items if not it.get("is_fallback", True)
    )
    total_fallback = sum(
        1 for items in headlines_by_cluster.values() for it in items if it.get("is_fallback", True)
    )

    def _fmt(it: Dict[str, Any]) -> str:
        badge = (
            "[ARCHIVE FALLBACK - not current news]"
            if it.get("is_fallback", True)
            else f"[LIVE {it.get('pubDate', '')}]"
        )
        return f"- **{it.get('source', 'Source')}:** [{it.get('title')}]({it.get('link')}) {badge}"

    md: List[str] = [
        "# PERSONAL OS INTEL RADAR - MULTI-PERSPECTIVE BRIEFING",
        f"*Generated: {now_str} | Capacity Guard: rho <= 0.75 (Zero Doom-Scrolling)*",
        f"*Source Coverage: {total_live} LIVE, {total_fallback} ARCHIVE FALLBACK*",
        "",
        "### 1. Macro, Rates & Government Bond Markets (Market Reality Check)",
    ]

    macro_items = headlines_by_cluster.get("macro_rates_markets", [])
    if macro_items:
        for it in macro_items[:2]:
            md.append(_fmt(it))
    else:
        md.append("- *Government credit spreads and policy expectations remain range-bound.* [ARCHIVE FALLBACK - not current news]")
    md.append("- **Market Reality Check:** Verify 10Y Treasury/Bund spreads, Brent crude, and TTF gas - flat curves indicate headline noise rather than kinetic pricing.")
    md.append("")

    md.append("### 2. Energy & Maritime Chokepoints")
    for it in headlines_by_cluster.get("energy_maritime_chokepoints", [])[:2]:
        md.append(_fmt(it))
    md.append("")

    md.append("### 3. Tech & Semiconductor Supply Chain")
    for it in headlines_by_cluster.get("tech_semiconductor_supply", [])[:2]:
        md.append(_fmt(it))
    md.append("")

    md.append("### 4. European Policy vs. Global Wire & Emerging Desk")
    for it in headlines_by_cluster.get("european_policy_desk", [])[:1]:
        md.append(_fmt(it))
    for it in headlines_by_cluster.get("global_wire", [])[:1]:
        md.append(_fmt(it))
    for it in headlines_by_cluster.get("emerging_global_south", [])[:2]:
        suffix = " *(State-aligned outlet: read as official posture, not verified fact)*" if "state media" in str(it.get("source", "")).lower() else ""
        md.append(f"{_fmt(it)}{suffix}")
    md.append("")

    md.append("### 5. Engineering & Portfolio Posture")
    md.append("- **Posture:** No action required - headline volatility without structural market repricing.")
    md.append("- **Execution Guard:** Maintain deep-work cadence (rho <= 0.75); zero reactive capex or doom-scrolling.")

    return "\n".join(md)


def render_triangulation_markdown(matrix: Dict[str, Any]) -> str:
    """Render the 4-tier evaluation of a claim or URL in clean Markdown."""
    claim = matrix.get("claim", "")
    url_note = matrix.get("url_source_note")
    sig = matrix.get("signal_assessment", {})
    verdict = sig.get("verdict", "CONTROLLED_TENSION")
    p_score = sig.get("panic_score", 0)
    s_score = sig.get("structural_score", 0)
    matched_alarmist = ", ".join(sig.get("matched_alarmist", [])) or "None"
    matched_structural = ", ".join(sig.get("matched_structural", [])) or "None"
    matched_critical = ", ".join(sig.get("matched_critical", [])) or "None"

    badge_map = {
        "CRITICAL_ESCALATION": "**[CRITICAL_ESCALATION]**",
        "HIGH_SIGNAL_STRUCTURAL": "**[HIGH_SIGNAL_STRUCTURAL]**",
        "NOISE_CLICKBAIT": "**[NOISE_CLICKBAIT]**",
        "CONTROLLED_TENSION": "**[CONTROLLED_TENSION]**",
    }
    badge = badge_map.get(verdict, "**[CONTROLLED_TENSION]**")

    md: List[str] = [
        "# PERSONAL OS - MULTI-PERSPECTIVE SIGNAL ANALYSIS",
        "",
        f"**Claim / Topic:** *\"{claim}\"*  ",
    ]
    if url_note:
        md.append(f"**URL Context:** *{url_note}*  ")
    md.extend([
        f"**Signal Verdict:** {badge}  ",
        f"**Panic Score:** `{p_score}/100` | **Structural Score:** `{s_score}/100`  ",
        f"**Critical Indicators:** *{matched_critical}* | **Alarmist Terms:** *{matched_alarmist}* | **Structural Indicators:** *{matched_structural}*  ",
        "",
        "---",
        "",
        "### 1. Institutional & Policy Perspective (Thesis)",
        matrix.get("perspective_policy_institutional", ""),
        "",
        "### 2. Counter-Narrative & State-Aligned Framing (Antithesis)",
        matrix.get("perspective_counter_narrative", ""),
        "",
        "### 3. Global Capital Markets & Commodities (Market Reality Check)",
        matrix.get("perspective_global_markets", ""),
        "",
        "---",
        "",
        "### 4. Structural & Historical Baselines",
    ])
    for doc in matrix.get("historical_continuity", []):
        md.append(f"- **{doc.get('title', 'Baseline')} ({doc.get('year', '')}):**")
        md.append(f"  - *Summary:* {doc.get('summary', '')}")
        md.append(f"  - *Game-Theory Reality:* {doc.get('game_theory_reality', '')}")
        md.append(f"  - *Red-Line Trigger:* {doc.get('red_line_trigger', '')}")
    md.extend([
        "",
        "### 5. Incentives & Cui Bono",
        matrix.get("cui_bono_incentives", ""),
        "",
        "---",
        "",
        matrix.get("engineering_portfolio_posture", ""),
    ])
    return "\n".join(md)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Personal OS Multi-Perspective Macro & Geopolitical Signal Filter"
    )
    parser.add_argument("--briefing", action="store_true", help="Generate and print 6-cluster radar briefing")
    parser.add_argument("--triangulate", type=str, metavar="CLAIM", help="Run multi-perspective signal check on topic, headline, or URL")
    parser.add_argument("--offline", action="store_true", help="Run strictly offline using curated baseline data")
    parser.add_argument("--json", action="store_true", help="Output structured JSON")
    args = parser.parse_args(argv)

    baseline = load_geopolitical_baseline()

    if args.triangulate:
        fetched_headlines = None
        if not args.offline:
            try:
                fetched_headlines = fetch_multi_source_headlines(offline=False, max_per_source=2, timeout=2.5)
            except Exception as exc:
                logger.debug("Live headlines fetch for signal analysis failed: %s", exc)

        matrix = build_dialectical_matrix(
            args.triangulate,
            fetched_items=fetched_headlines,
            baseline=baseline,
            offline=args.offline,
        )
        if args.json:
            print(json.dumps(matrix, ensure_ascii=False, indent=2))
        else:
            print(render_triangulation_markdown(matrix))
    else:
        use_offline = args.offline or (not args.briefing)
        headlines = fetch_multi_source_headlines(offline=use_offline)
        if args.json:
            print(json.dumps(headlines, ensure_ascii=False, indent=2))
        else:
            print(render_radar_briefing_markdown(headlines, baseline=baseline))

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
