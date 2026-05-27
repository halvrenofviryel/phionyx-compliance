"""v0.7.0 W2 acceptance — F4 reasoning surface + F8 retrieval block
surfaced through the EU AI Act Article 13 template.

The W2 acceptance criterion (from V0_7_0_KICKOFF_2026_05_26.md):
    "F14 report template can surface 'knowledge sources consulted'
     for evidence"

These tests verify:
  1. The new mapping.yaml entries resolve via the derived dispatch.
  2. The renderer produces correct tables for populated envelopes.
  3. The renderer produces graceful empty-state lines for windows that
     contain no F4 / F8 evidence (pre-v0.7.0 producers).
  4. The end-to-end rendered template contains §3.3 'Knowledge sources
     and retrieval evidence' with the new sub-headings.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def _f4_f8_envelope(turn_index: int = 1, with_retrieval: bool = True) -> dict:
    """Synthesize a v0.7.0 W2-compliant envelope with reasoning + retrieval populated."""
    env: dict = {
        "schema_id": "phionyx.governed_response_envelope.v0.2",
        "subject": {
            "kind": "agent_self_claim",
            "turn_index": turn_index,
            "timestamp_utc": f"2026-05-27T14:30:0{turn_index}+00:00",
            "decision": "pass",
        },
        "reasoning": {
            "runtime_decision": "release",
            "decision_reason": "test fixture",
            "rationale_summary": "test rationale",
            "knowledge_sources_consulted": [
                {"kind": "retrieval_corpus", "ref": "eur-lex-ai-act-2024-1689"},
                {"kind": "static_doc", "ref": "internal-glossary/annex-iii.md"},
            ],
            "constraints_acknowledged": [
                {"kind": "policy", "ref": "regulatory_disclosure", "satisfied": True},
            ],
        },
        "integrity": {"current": f"h{turn_index}", "previous": "GENESIS", "key_id": "key-1"},
    }
    if with_retrieval:
        env["retrieval"] = {
            "status": "active",
            "store_id": "vector://eur-lex-2024",
            "corpus": {
                "name": "eur-lex-ai-act-2024-1689",
                "version": "2026-05-07-digital-omnibus-merge",
                "language": "en",
            },
            "similarity_threshold": 0.78,
            "documents": [
                {"id": "eur-lex/2024-1689/art-9", "role": "admitted", "score": 0.91, "hash": "sha256:c0"},
                {"id": "council-2026-05-07", "role": "cited", "score": 0.83, "hash": "sha256:c1"},
            ],
        }
    return env


def _pre_v0_7_envelope(turn_index: int = 1) -> dict:
    """Envelope from a producer that has not yet flipped to F4/F8 emission."""
    return {
        "schema_id": "phionyx.governed_response_envelope.v0.2",
        "subject": {
            "kind": "agent_self_claim",
            "turn_index": turn_index,
            "timestamp_utc": f"2026-05-15T10:00:0{turn_index}+00:00",
            "decision": "pass",
        },
        "integrity": {"current": f"h{turn_index}", "previous": "GENESIS", "key_id": "key-1"},
    }


# ── Renderer-level tests ──────────────────────────────────────────────

def test_knowledge_sources_table_populated():
    from phionyx_compliance import ChainView
    from phionyx_compliance.renderer import render_knowledge_sources_summary_table

    chain = ChainView.from_envelopes("t-1", [_f4_f8_envelope(1), _f4_f8_envelope(2)])
    out = render_knowledge_sources_summary_table(chain=chain)

    # Both envelopes populate knowledge_sources_consulted with the same shape,
    # so we expect 4× retrieval_corpus / 0× ... no wait, each has 2 entries:
    # 1× retrieval_corpus + 1× static_doc. So aggregated: 2× retrieval_corpus, 2× static_doc.
    assert "| Source type | Count |" in out
    assert "`retrieval_corpus`" in out
    assert "`static_doc`" in out
    assert "2 of 2 envelopes surfaced" in out


def test_knowledge_sources_table_empty_window():
    from phionyx_compliance import ChainView
    from phionyx_compliance.renderer import render_knowledge_sources_summary_table

    chain = ChainView.from_envelopes("t-2", [_pre_v0_7_envelope(1)])
    out = render_knowledge_sources_summary_table(chain=chain)

    # Graceful empty-state for pre-v0.7.0 producer
    assert "No `reasoning.knowledge_sources_consulted` populated" in out
    assert "either the producer is pre-v0.7.0" in out


def test_retrieval_corpus_table_populated():
    from phionyx_compliance import ChainView
    from phionyx_compliance.renderer import render_retrieval_corpus_summary_table

    chain = ChainView.from_envelopes("t-3", [_f4_f8_envelope(1), _f4_f8_envelope(2)])
    out = render_retrieval_corpus_summary_table(chain=chain)

    # Same corpus across both envelopes — distinct count = 1
    assert "| Corpus name | Version | Language |" in out
    assert "eur-lex-ai-act-2024-1689" in out
    assert "2026-05-07-digital-omnibus-merge" in out
    assert "en" in out
    # Distinct, not duplicated
    assert out.count("eur-lex-ai-act-2024-1689") == 1


def test_retrieval_corpus_table_empty_window():
    from phionyx_compliance import ChainView
    from phionyx_compliance.renderer import render_retrieval_corpus_summary_table

    # F4 populated but NOT retrieval
    chain = ChainView.from_envelopes(
        "t-4", [_f4_f8_envelope(1, with_retrieval=False)]
    )
    out = render_retrieval_corpus_summary_table(chain=chain)

    assert "No `retrieval.corpus` populated" in out


def test_retrieval_event_count():
    from phionyx_compliance import ChainView
    from phionyx_compliance.renderer import render_retrieval_event_count

    # 2 with retrieval + 1 without
    chain = ChainView.from_envelopes(
        "t-5",
        [
            _f4_f8_envelope(1),  # retrieval populated
            _f4_f8_envelope(2),  # retrieval populated
            _f4_f8_envelope(3, with_retrieval=False),  # no retrieval block
        ],
    )
    out = render_retrieval_event_count(chain=chain)

    assert out == "2"


# ── Mapping-level test ────────────────────────────────────────────────

def test_mapping_resolves_f4_f8_derived_fields():
    """The EU AI Act Article 13 mapping.yaml routes the three new derived
    fields to the correct renderer functions."""
    from phionyx_compliance import ChainView, load_template, resolve_inputs

    chain = ChainView.from_envelopes(
        "t-6", [_f4_f8_envelope(1), _f4_f8_envelope(2)]
    )
    t = load_template("eu-ai-act-article-13")
    inputs = resolve_inputs(t, chain)

    assert "knowledge_sources_summary_table" in inputs
    assert "| Source type | Count |" in inputs["knowledge_sources_summary_table"]

    assert "retrieval_corpus_summary_table" in inputs
    assert "eur-lex-ai-act-2024-1689" in inputs["retrieval_corpus_summary_table"]

    assert "retrieval_event_count" in inputs
    assert inputs["retrieval_event_count"] == "2"


# ── End-to-end template render test ───────────────────────────────────

def test_eu_ai_act_template_renders_f4_f8_section():
    """The fully rendered EU AI Act Article 13 report contains the
    §3.3 'Knowledge sources and retrieval evidence' section, and the
    section is populated with the F4/F8 evidence from the chain."""
    from phionyx_compliance import ChainView, load_template, resolve_inputs
    from phionyx_compliance.renderer import render, sample_inputs

    chain = ChainView.from_envelopes(
        "t-7", [_f4_f8_envelope(1), _f4_f8_envelope(2)]
    )
    t = load_template("eu-ai-act-article-13")

    # Combine resolved chain inputs with sample operator inputs so the
    # report can fully render without operator placeholders blocking.
    chain_inputs = resolve_inputs(t, chain)
    inputs = {**sample_inputs("eu-ai-act-article-13"), **chain_inputs}

    md = render(t, inputs)

    # Section heading present
    assert "### 3.3 Knowledge sources and retrieval evidence" in md
    # F4 sub-heading + populated content
    assert "Knowledge sources consulted (typed):" in md
    assert "`retrieval_corpus`" in md
    assert "`static_doc`" in md
    # F8 sub-heading + populated content
    assert "Retrieval corpora observed:" in md
    assert "eur-lex-ai-act-2024-1689" in md
    # Retrieval event count surfaced
    assert "Envelopes with `retrieval.documents` populated | 2" in md
    # Article 13(3)(c) cross-reference
    assert "Article 13(3)(c)" in md


def test_eu_ai_act_template_renders_empty_window():
    """The rendered report still contains the §3.3 section even when no
    envelope populated F4/F8 — but with graceful empty-state copy."""
    from phionyx_compliance import ChainView, load_template, resolve_inputs
    from phionyx_compliance.renderer import render, sample_inputs

    chain = ChainView.from_envelopes("t-8", [_pre_v0_7_envelope(1)])
    t = load_template("eu-ai-act-article-13")

    chain_inputs = resolve_inputs(t, chain)
    inputs = {**sample_inputs("eu-ai-act-article-13"), **chain_inputs}

    md = render(t, inputs)

    assert "### 3.3 Knowledge sources and retrieval evidence" in md
    assert "No `reasoning.knowledge_sources_consulted` populated" in md
    assert "No `retrieval.corpus` populated" in md
    # The retrieval_event_count for a pre-v0.7.0 window is 0
    assert "Envelopes with `retrieval.documents` populated | 0" in md
