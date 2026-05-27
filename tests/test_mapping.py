"""W1.3 — tests for mapping resolver (4-category rule semantics)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def _synthetic_chain():
    """Build a small ChainView with envelopes that hit each filter / aggregator."""
    from phionyx_compliance import ChainView

    envelopes = [
        {
            "schema_id": "phionyx.governed_response_envelope.v0.2",
            "subject": {
                "kind": "agent_self_claim",
                "turn_index": 0,
                "timestamp_utc": "2026-05-26T10:00:00+00:00",
                "decision": "pass",
                "tool_descriptor_hash": "sha256:abc",
                "descriptor_change_detected": False,
                "anomaly_flag": False,
            },
            "integrity": {"current": "h0", "previous": "GENESIS", "key_id": "key-1"},
        },
        {
            "schema_id": "phionyx.governed_response_envelope.v0.2",
            "subject": {
                "kind": "agent_self_claim",
                "turn_index": 1,
                "timestamp_utc": "2026-05-26T10:01:00+00:00",
                "decision": "reject",
                "tool_descriptor_hash": "sha256:def",
                "descriptor_change_detected": True,
                "anomaly_flag": False,
            },
            "integrity": {"current": "h1", "previous": "h0", "key_id": "key-1"},
        },
        {
            "schema_id": "phionyx.governed_response_envelope.v0.2",
            "subject": {
                "kind": "tool_call",
                "turn_index": 2,
                "timestamp_utc": "2026-05-26T10:02:00+00:00",
                "decision": "pass",
                "tool_descriptor_hash": "sha256:abc",
                "descriptor_change_detected": False,
                "anomaly_flag": True,
            },
            "integrity": {"current": "h2", "previous": "h1", "key_id": "key-1"},
        },
    ]
    return ChainView.from_envelopes("trace-test-abc", envelopes)


def test_resolve_chain_derived_count_filter():
    """tool_call_count filters on schema_id; claim_count filters on subject.kind."""
    from phionyx_compliance import load_template, resolve_inputs

    chain = _synthetic_chain()
    t = load_template("eu-ai-act-article-13")
    inputs = resolve_inputs(t, chain)

    assert inputs["envelope_count"] == 3
    # tool_call_count filters by schema_id only → all 3 envelopes match
    assert inputs["tool_call_count"] == 3
    # claim_count filters by subject.kind == "agent_self_claim" → 2 envelopes
    assert inputs["claim_count"] == 2


def test_resolve_chain_derived_aggregators():
    """verdict_distribution / distinct / first_or_varies / descriptor_change_count."""
    from phionyx_compliance import load_template, resolve_inputs

    chain = _synthetic_chain()
    t = load_template("eu-ai-act-article-13")
    inputs = resolve_inputs(t, chain)

    # verdict_distribution: count_by_field on subject.decision
    assert inputs["verdict_distribution"] == {"pass": 2, "reject": 1}

    # distinct: distinct count of subject.tool_descriptor_hash
    assert inputs["distinct_descriptor_count"] == 2  # sha256:abc, sha256:def

    # first_or_varies: all envelopes have key_id="key-1" → returns "key-1"
    assert inputs["signing_key_id"] == "key-1"

    # descriptor_change_count: filter on descriptor_change_detected=True → 1
    assert inputs["descriptor_change_count"] == 1

    # anomaly_count: filter on anomaly_flag=True → 1
    assert inputs["anomaly_count"] == 1


def test_resolve_canonical_and_derived():
    """Canonical disclaimers + derived helper functions all resolve."""
    from phionyx_compliance import load_template, resolve_inputs

    chain = _synthetic_chain()
    t = load_template("eu-ai-act-article-13")
    inputs = resolve_inputs(t, chain)

    # Canonical disclaimers
    assert "evidence-oriented" in inputs["disclaimer_head"].lower()
    assert "qualified auditor must review" in inputs["disclaimer_tail"].lower()

    # Derived chain_valid_label (chain is valid in synthetic)
    assert inputs["chain_valid_label"] == "✓ valid"

    # Derived verdict_distribution_table is a markdown table
    assert "| Verdict | Count |" in inputs["verdict_distribution_table"]

    # Derived template_version reads from template_metadata.template_version
    assert inputs["template_version"] == "1.0.0"


def test_resolve_operator_supplied_default_and_override():
    """Operator-supplied fields fall back to placeholder; override wins."""
    from phionyx_compliance import load_template, resolve_inputs

    chain = _synthetic_chain()
    t = load_template("eu-ai-act-article-13")

    # No override → placeholder used
    inputs = resolve_inputs(t, chain, operator_inputs=None)
    assert "[OPERATOR" in inputs["provider_name"]

    # Override → operator value wins
    inputs = resolve_inputs(t, chain, operator_inputs={"provider_name": "Test Co. Ltd."})
    assert inputs["provider_name"] == "Test Co. Ltd."


def test_end_to_end_render_from_chain():
    """ChainView → resolve_inputs → render produces a complete markdown."""
    from phionyx_compliance import load_template, resolve_inputs, render

    chain = _synthetic_chain()
    t = load_template("eu-ai-act-article-13")
    inputs = resolve_inputs(t, chain, operator_inputs={
        "provider_name": "Real-Looking Co.",
        "system_identifier": "RLC-Agent-v1",
        "intended_purpose": "Process customer queries within scope.",
    })
    markdown = render(t, inputs)

    # No unresolved placeholders
    assert "{{" not in markdown
    assert "}}" not in markdown

    # Real-looking inputs surfaced
    assert "Real-Looking Co." in markdown
    assert "RLC-Agent-v1" in markdown

    # Trace ID + envelope count
    assert "trace-test-abc" in markdown
    assert "Envelopes in window | 3" in markdown

    # Verdict distribution
    assert "`pass`" in markdown
    assert "`reject`" in markdown

    # Canonical disclaimer at head AND tail
    assert "Evidence-oriented mapping" in markdown
    assert "Reminder." in markdown
