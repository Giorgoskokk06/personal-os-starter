"""Self-contained unit tests for the Technical Style Linter & Prose Simplifier."""

from src.stylistics.naturalizer import TextNaturalizer, purge_style_cliches


def test_purge_style_cliches_removes_english_and_greek_markers() -> None:
    sample = (
        "It is worth noting that hybrid search plays a pivotal role in retrieval. "
        "Αξίζει να σημειωθεί ότι η μέθοδος διαδραματίζει καθοριστικό ρόλο."
    )
    cleaned = purge_style_cliches(sample)
    assert "worth noting" not in cleaned.lower()
    assert "pivotal role" not in cleaned.lower()
    assert "αξίζει να σημειωθεί" not in cleaned.lower()
    assert "διαδραματίζει καθοριστικό ρόλο" not in cleaned.lower()


def test_burstiness_and_decimal_protection() -> None:
    nat = TextNaturalizer()
    text = "Latency hit 2.83 ms on P50. Short check. Another longer technical sentence about pgvector halfvec indexing."
    sentences = nat.split_sentences(text)
    assert len(sentences) == 3
    assert "2.83 ms" in sentences[0]
    metrics = nat.compute_metrics(text)
    assert metrics["sentence_count"] == 3
    assert metrics["coefficient_of_variation"] > 0.0


def test_voice_naturalization_rfc_mode() -> None:
    nat = TextNaturalizer(mode="rfc_technical")
    out = nat.naturalize("We measured 2.83 ms P50 RPC latency and we calculated the tail variance.")
    assert "was measured" in out
    assert "was calculated" in out


def test_audit_report_flags_cliche_rich_text() -> None:
    nat = TextNaturalizer()
    verbose_draft = (
        "In today's fast-paced world, it is worth noting that this multifaceted system "
        "stands as a testament to engineering. In conclusion, it fosters a robust pipeline."
    )
    report = nat.audit(verbose_draft)
    assert report.cliches_detected_count >= 4
    assert report.passes_style_gate is False
    assert report.style_risk_score > 0.25
