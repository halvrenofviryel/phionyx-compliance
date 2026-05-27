"""W1.5 — cross-template parity tests.

Every template shipped with phionyx-compliance must:
  - load without error,
  - have a complete schema/template/mapping/disclaimer/README set,
  - render its --sample without any unresolved {{placeholder}},
  - carry the canonical disclaimer head AND tail in the render.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


# Order matters less than completeness; pytest discovers all 4 via list_templates
EXPECTED_TEMPLATES = {
    "eu-ai-act-article-13",
    "nist-ai-rmf-1",
    "iso-iec-42001",
    "owasp-agentic-ai-v1",
}


def test_list_templates_shows_all_four():
    from phionyx_compliance import list_templates

    names = set(list_templates())
    assert names == EXPECTED_TEMPLATES, f"expected {EXPECTED_TEMPLATES}, got {names}"


def test_each_template_loads_cleanly():
    from phionyx_compliance import load_template

    for name in EXPECTED_TEMPLATES:
        t = load_template(name)
        assert t.version == "1.0.0", f"{name}: version != 1.0.0 → {t.version}"
        assert t.framework, f"{name}: framework metadata missing"
        assert t.required_fields, f"{name}: schema has no required fields"
        assert t.disclaimer_addendum, f"{name}: disclaimer.md is empty"


def test_each_template_renders_sample_without_unresolved_placeholders():
    from phionyx_compliance import load_template, sample_inputs, render

    for name in EXPECTED_TEMPLATES:
        t = load_template(name)
        inputs = sample_inputs(name)
        out = render(t, inputs)
        # No {{...}} survives
        assert "{{" not in out, f"{name}: rendered output has unresolved {{placeholder}}"
        # Canonical disclaimer head AND tail present
        assert "Evidence-oriented mapping" in out, f"{name}: head disclaimer missing"
        assert "Reminder." in out, f"{name}: tail disclaimer missing"
        # No "compliant" / "certified" / "meets the requirements of" language
        for forbidden in ("certified compliance", "meets the requirements of"):
            assert forbidden not in out, f"{name}: forbidden language {forbidden!r} present"


def test_each_sample_has_sample_tags_on_operator_supplied():
    """Every template's --sample output must visibly mark synthetic
    values so reviewers cannot mistake a sample for a real assessment."""
    from phionyx_compliance import load_template, sample_inputs, render

    for name in EXPECTED_TEMPLATES:
        t = load_template(name)
        inputs = sample_inputs(name)
        out = render(t, inputs)
        assert "[SAMPLE]" in out, f"{name}: no [SAMPLE] tag in render"


def test_each_template_has_required_files():
    """Each template directory has the 5 canonical files."""
    from phionyx_compliance.templates import _TEMPLATES_ROOT, _kebab_to_snake

    required = ["template.md", "schema.json", "mapping.yaml", "disclaimer.md", "README.md"]
    for name in EXPECTED_TEMPLATES:
        tdir = _TEMPLATES_ROOT / _kebab_to_snake(name)
        for fname in required:
            assert (tdir / fname).exists(), f"{name}/{fname} missing"
