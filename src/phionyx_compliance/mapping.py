"""Mapping resolver — projects an envelope chain through a template's
mapping.yaml rules to produce the inputs dict the renderer consumes.

W1.3 — implements the 4-category rule semantics declared in mapping.yaml:
  - operator_supplied: pulled from operator_inputs or rule's placeholder
  - chain_derived:     computed by walking ChainView.envelopes (filter,
                       aggregator, field)
  - derived:           dispatched to a renderer helper function or to
                       template metadata
  - canonical:         constant from the phionyx_compliance package
"""
from __future__ import annotations

from typing import Any

from .chain_view import ChainView
from . import renderer as _renderer_module
from .renderer import (
    render_chain_integrity_summary,
    render_chain_valid_label,
    render_generated_at_iso,
    render_human_oversight_summary,
    render_reproduction_command,
    render_verdict_distribution_table,
    render_verification_command,
)
from .templates import Template


def resolve_inputs(
    template: Template,
    chain: ChainView,
    operator_inputs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve the template's mapping.yaml against a chain view.

    Two passes:
      Pass 1: operator_supplied, chain_derived, canonical (no dependencies)
      Pass 2: derived (may read pass-1 values via the renderer helpers)

    Returns a dict suitable for render(template, inputs).
    """
    operator_inputs = operator_inputs or {}
    rules = (template.mapping or {}).get("inputs", {})
    result: dict[str, Any] = {}

    # Pass 1
    for field_name, rule in rules.items():
        category = rule.get("category")
        if category == "operator_supplied":
            result[field_name] = operator_inputs.get(
                field_name, rule.get("placeholder", "")
            )
        elif category == "chain_derived":
            result[field_name] = _resolve_chain_rule(rule, chain)
        elif category == "canonical":
            result[field_name] = _resolve_canonical(rule)

    # Pass 2 (derived)
    for field_name, rule in rules.items():
        if rule.get("category") == "derived":
            result[field_name] = _resolve_derived_rule(
                rule, chain, result, template
            )

    return result


# ── Pass 1 helpers ─────────────────────────────────────────────────

def _resolve_chain_rule(rule: dict, chain: ChainView) -> Any:
    source = rule.get("source", "")
    filter_rule = rule.get("filter") or {}
    aggregator = rule.get("aggregator")
    field = rule.get("field")

    # Simple direct sources
    if source == "chain.trace_id":
        return chain.trace_id
    if source == "chain.envelope_count":
        return chain.envelope_count
    if source == "chain.verify_result.valid":
        return chain.verify_result.valid
    if source == "chain.envelopes[0].timestamp_utc":
        return _envelope_timestamp(chain.envelopes[0]) if chain.envelopes else ""
    if source == "chain.envelopes[-1].timestamp_utc":
        return _envelope_timestamp(chain.envelopes[-1]) if chain.envelopes else ""

    # Aggregations over chain.envelopes
    if source == "chain.envelopes":
        envelopes = chain.envelopes
        if filter_rule:
            envelopes = [e for e in envelopes if _matches_filter(e, filter_rule)]
        if aggregator == "count":
            return len(envelopes)
        if aggregator == "count_by_field" and field:
            counts: dict[str, int] = {}
            for e in envelopes:
                v = _get_field(e, field)
                if v is not None:
                    counts[str(v)] = counts.get(str(v), 0) + 1
            return counts
        if aggregator == "distinct" and field:
            values = {_get_field(e, field) for e in envelopes if _get_field(e, field) is not None}
            return len(values)
        if aggregator == "first_or_varies" and field:
            values = {_get_field(e, field) for e in envelopes if _get_field(e, field) is not None}
            if not values:
                return ""
            if len(values) == 1:
                return next(iter(values))
            return "<varies>"

    # Revocation list (placeholder until v0.6.0+)
    if source == "chain.revoked_keys_referenced":
        return len(chain.revoked_keys_referenced) if aggregator == "count" else chain.revoked_keys_referenced

    return f"<unsupported source: {source!r}>"


def _resolve_canonical(rule: dict) -> Any:
    source = rule.get("source", "")
    # Lazy imports to avoid circulars
    from . import CANONICAL_DISCLAIMER_HEAD, CANONICAL_DISCLAIMER_TAIL

    if source == "phionyx_compliance.CANONICAL_DISCLAIMER_HEAD":
        return CANONICAL_DISCLAIMER_HEAD
    if source == "phionyx_compliance.CANONICAL_DISCLAIMER_TAIL":
        return CANONICAL_DISCLAIMER_TAIL
    return ""


# ── Pass 2 helpers ─────────────────────────────────────────────────

def _resolve_derived_rule(
    rule: dict,
    chain: ChainView,
    so_far: dict,
    template: Template,
) -> Any:
    function = rule.get("function")
    source = rule.get("source")

    if function == "render_chain_valid_label":
        return render_chain_valid_label(
            chain.verify_result.valid, chain.verify_result.broken_at
        )
    if function == "render_verification_command":
        return render_verification_command(chain.trace_id)
    if function == "render_verdict_distribution_table":
        return render_verdict_distribution_table(so_far.get("verdict_distribution") or {})
    if function == "render_chain_integrity_summary":
        return render_chain_integrity_summary(
            envelope_count=chain.envelope_count,
            valid=chain.verify_result.valid,
            broken_at=chain.verify_result.broken_at,
            reason=chain.verify_result.reason,
        )
    if function == "render_human_oversight_summary":
        # Heuristic: count envelopes whose subject.kind matches a known
        # HITL indicator. The exact field name is forward-compatible
        # with HITL envelope additions in v0.7.0.
        hitl_count = sum(
            1 for e in chain.envelopes
            if _get_field(e, "subject.kind") in {"hitl_invocation", "human_review"}
        )
        return render_human_oversight_summary(hitl_count)
    if function == "render_generated_at_iso":
        return render_generated_at_iso()
    if function == "render_reproduction_command":
        return render_reproduction_command(chain.trace_id, template.name)

    if source == "template_metadata.template_version":
        return template.version

    # Generic dispatch by function name — picks up template-specific
    # renderer helpers (e.g. OWASP per-threat status functions) without
    # requiring mapping.py to hard-code each one.
    if function and hasattr(_renderer_module, function):
        helper = getattr(_renderer_module, function)
        hitl_count = sum(
            1 for e in chain.envelopes
            if _get_field(e, "subject.kind") in {"hitl_invocation", "human_review"}
        )
        kwargs = {
            **{k: v for k, v in so_far.items() if not isinstance(v, (list,))},
            "chain_valid": chain.verify_result.valid,
            "envelope_count": chain.envelope_count,
            "hitl_count": hitl_count,
        }
        try:
            return helper(**kwargs)
        except TypeError:
            # Helper has stricter signature; fall through to error
            pass

    return f"<unsupported derived: function={function!r} source={source!r}>"


# ── Envelope field accessors ───────────────────────────────────────

def _get_field(envelope: dict, dotted_path: str) -> Any:
    """Resolve a dotted path against an envelope dict.

    Examples:
        'subject.decision'                 → envelope['subject']['decision']
        'integrity.key_id'                  → envelope['integrity']['key_id']
        'subject.descriptor_change_detected' → envelope['subject']['descriptor_change_detected']
    """
    obj: Any = envelope
    for key in dotted_path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(key)
            if obj is None:
                return None
        else:
            return None
    return obj


def _matches_filter(envelope: dict, filter_rule: dict) -> bool:
    """All key/value pairs in the filter must match the envelope."""
    for key, expected in filter_rule.items():
        actual = _get_field(envelope, key)
        if actual != expected:
            return False
    return True


def _envelope_timestamp(envelope: dict) -> str:
    """Best-effort timestamp extraction from an envelope."""
    for path in (
        "subject.timestamp_utc",
        "subject.iso_time",
        "timestamp_utc",
        "iso_time",
        "integrity.timestamp_utc",
    ):
        v = _get_field(envelope, path)
        if v is not None:
            return str(v)
    return ""


__all__ = ["resolve_inputs"]
