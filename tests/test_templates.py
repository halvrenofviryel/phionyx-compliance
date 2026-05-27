"""W1.2 — tests for template loader."""
from __future__ import annotations

import sys
from pathlib import Path

# tests-in-monorepo style
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def test_list_templates_includes_article_13():
    from phionyx_compliance.templates import list_templates

    names = list_templates()
    assert "eu-ai-act-article-13" in names


def test_load_template_article_13():
    from phionyx_compliance.templates import load_template

    t = load_template("eu-ai-act-article-13")
    assert t.name == "eu-ai-act-article-13"
    assert t.version == "1.0.0"
    assert "EU AI Act" in t.framework
    # Schema sanity
    assert "trace_id" in t.required_fields
    assert "provider_name" in t.required_fields
    assert "disclaimer_head" in t.required_fields
    # Template content sanity
    assert "{{disclaimer_head}}" in t.template_md
    assert "Article 13" in t.template_md
    # Disclaimer addendum loaded
    assert "EU AI Act" in t.disclaimer_addendum


def test_template_field_categorisation():
    from phionyx_compliance.templates import load_template

    t = load_template("eu-ai-act-article-13")
    op = t.operator_supplied_fields
    ch = t.chain_derived_fields

    # All operator + chain fields should be required (per schema)
    for f in op + ch:
        assert f in t.required_fields, f"{f} not in required schema fields"

    # No overlap: a field cannot be both operator-supplied AND chain-derived
    assert not (set(op) & set(ch))

    # The known operator-supplied fields are present
    assert "intended_purpose" in op
    assert "declared_limitations" in op
    assert "provider_name" in op

    # The known chain-derived fields are present
    assert "trace_id" in ch
    assert "envelope_count" in ch
    assert "verdict_distribution" in ch


def test_unknown_template_raises():
    from phionyx_compliance.templates import load_template

    try:
        load_template("does-not-exist")
        raise AssertionError("expected FileNotFoundError")
    except FileNotFoundError as exc:
        assert "does-not-exist" in str(exc)
