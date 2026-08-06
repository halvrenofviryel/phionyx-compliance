"""W1.2 — tests for the renderer."""
from __future__ import annotations

import sys
from pathlib import Path

# tests-in-monorepo style
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def test_sample_inputs_validates_against_schema():
    from phionyx_compliance import sample_inputs, load_template

    inputs = sample_inputs("eu-ai-act-article-13")
    t = load_template("eu-ai-act-article-13")
    # Every required schema field is present in the sample inputs
    for f in t.required_fields:
        assert f in inputs, f"sample_inputs missing required field: {f}"


def test_render_article_13_sample_end_to_end():
    from phionyx_compliance import render, load_template, sample_inputs

    t = load_template("eu-ai-act-article-13")
    inputs = sample_inputs("eu-ai-act-article-13")
    output = render(t, inputs)

    # No unresolved placeholders
    assert "{{" not in output, "rendered output has unresolved placeholders"
    assert "}}" not in output

    # Canonical disclaimer present at head AND tail
    assert "Evidence-oriented mapping" in output
    assert "Reminder." in output

    # Sample markers visible
    assert "[SAMPLE]" in output, "sample inputs should be tagged [SAMPLE]"

    # Chain-derived synthetic values rendered
    assert "trace-e2dd588aaf4d4c97" in output
    assert "155" in output  # envelope count
    # chain_valid_label — sample mode verifies NOTHING, so it must not
    # display a verified posture (P0.4).
    assert "RECORDED only — nothing was verified" in output
    assert "✓ valid" not in output

    # Verdict distribution table rendered
    assert "| Verdict | Count |" in output
    assert "`pass`" in output

    # Framework addendum text from disclaimer.md was concatenated into tail
    assert "Regulation (EU) 2024/1689" in output


def test_render_missing_required_raises():
    from phionyx_compliance import render, load_template

    t = load_template("eu-ai-act-article-13")
    incomplete = {"provider_name": "Test"}  # most required fields missing
    try:
        render(t, incomplete)
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        msg = str(exc)
        assert "missing required input" in msg
        assert "trace_id" in msg  # at least one of the missing keys


def test_verdict_distribution_table_format():
    from phionyx_compliance.renderer import render_verdict_distribution_table

    table = render_verdict_distribution_table({"pass": 50, "reject": 2, "regenerate": 1})
    assert "| Verdict | Count |" in table
    assert "|---|---:|" in table
    # Sort by count desc; pass should be first
    lines = table.splitlines()
    assert "pass" in lines[2]
    assert "50" in lines[2]


def test_chain_valid_label_helpers():
    """Legacy positional callers get the HASH-level reading, never a
    signature-level one — nothing on that call path verified a signature."""
    from phionyx_compliance.renderer import render_chain_valid_label, render_chain_integrity_summary

    label_ok = render_chain_valid_label(True)
    assert label_ok == "⚠ HASH_VERIFIED only — signatures NOT verified"
    assert "broken at envelope 7" in render_chain_valid_label(False, broken_at=7)

    ok = render_chain_integrity_summary(envelope_count=10, valid=True, broken_at=None, reason=None)
    assert "HASH_VERIFIED" in ok
    # A hash-chain walk is NOT a signature check — the legacy path must
    # not claim one.
    assert "Ed25519 signatures verify" not in ok
    assert "Signatures were **NOT** verified" in ok

    broken = render_chain_integrity_summary(envelope_count=10, valid=False, broken_at=5, reason="hash mismatch")
    assert "INVALID" in broken
    assert "broken at envelope 5" in broken
    assert "hash mismatch" in broken
