"""Renderer for phionyx-compliance template substrate.

Two responsibilities:

1. Take a Template + a dict of inputs, validate inputs against the
   template's schema, and produce the rendered markdown by substituting
   {{placeholders}} in template.md.

2. Provide `sample_inputs(template_name)` that returns a complete,
   schema-valid synthetic input dictionary, so the renderer can be
   exercised end-to-end before W1.3 lands the real chain walker.

W1.2 scope: placeholder substitution + sample mode + a small set of
derived-field renderer helpers (verdict distribution table,
chain integrity summary, ...).

W1.3 scope (not in this file): the chain walker that reads
~/.phionyx/mcp_audit/<trace>/ and produces the inputs dict using the
template's mapping.yaml.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .templates import Template, load_template


def render(template: Template, inputs: dict[str, Any]) -> str:
    """Substitute {{placeholders}} in template.md with values from inputs.

    Raises:
        ValueError: if a required schema field is missing from inputs.
    """
    missing = [k for k in template.required_fields if k not in inputs]
    if missing:
        raise ValueError(
            f"render({template.name!r}): missing required input(s): {sorted(missing)}"
        )

    # Convert all inputs to string form for substitution. dict-typed
    # inputs (e.g. verdict_distribution) need their derived-table form
    # supplied by callers; we render the raw dict's repr only as a
    # fallback.
    output = template.template_md
    placeholder_re = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in inputs:
            return match.group(0)  # leave unmatched placeholder; helps diagnostics
        v = inputs[key]
        if isinstance(v, (dict, list)):
            return str(v)
        return str(v)

    output = placeholder_re.sub(_replace, output)
    return output


def sample_inputs(template_name: str) -> dict[str, Any]:
    """Return a schema-valid synthetic input dict for the template.

    Routes by template name to per-template builders, all anchored on a
    common synthetic chain summary (155 envelopes, ✓ valid, etc.).
    """
    from . import CANONICAL_DISCLAIMER_HEAD, CANONICAL_DISCLAIMER_TAIL

    t = load_template(template_name)
    now_iso = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
    verdict_distribution = {"pass": 47, "regenerate": 1, "reject": 2, "auto_attest": 70, "n_a": 21}

    # Common synthetic chain summary shared across all 4 templates
    common: dict[str, Any] = {
        "trace_id": "trace-e2dd588aaf4d4c97",
        "window_start_iso": "2026-04-26T00:00:00+00:00",
        "window_end_iso": "2026-05-26T23:59:59+00:00",
        "envelope_count": 155,
        "chain_valid": True,
        "tool_call_count": 132,
        "claim_count": 51,
        "verdict_distribution": verdict_distribution,
        "verdict_distribution_table": render_verdict_distribution_table(verdict_distribution),
        "distinct_descriptor_count": 12,
        "descriptor_change_count": 0,
        "anomaly_count": 0,
        "signing_key_id": "key-sample-2026-05",
        "chain_valid_label": "✓ valid",
        "chain_integrity_summary": (
            "Chain validates at assessment time. 155 envelopes; no broken links; "
            "Ed25519 signatures verify against the producer's published public key. "
            "No mid-window key rotations or revocations."
        ),
        "human_oversight_summary": (
            "[SAMPLE] No HITL invocations recorded in this window. All gate "
            "verdicts resolved within the deterministic decision boundary; no "
            "human override events to report."
        ),
        "generated_at_iso": now_iso,
        "template_version": t.version,
        "reproduction_command": f"phionyx-compliance generate --trace trace-e2dd588aaf4d4c97 --template {t.name}",
        "disclaimer_head": CANONICAL_DISCLAIMER_HEAD,
        "disclaimer_tail": CANONICAL_DISCLAIMER_TAIL + "\n\n" + t.disclaimer_addendum,
        # F4 + F8 (v0.7.0 W2) — sample synthetic surfaces. Real chain
        # rendering replaces these via the derived-dispatch in mapping.py;
        # sample mode pre-fills so the standalone renderer test passes.
        "knowledge_sources_summary_table": (
            "| Source type | Count |\n"
            "|---|---:|\n"
            "| `retrieval_corpus` | 18 |\n"
            "| `tool_descriptor_clause` | 7 |\n"
            "| `static_doc` | 3 |\n"
            "\n"
            "*28 of 155 envelopes surfaced `reasoning.knowledge_sources_consulted` in this window.*"
        ),
        "retrieval_corpus_summary_table": (
            "| Corpus name | Version | Language |\n"
            "|---|---|---|\n"
            "| `eur-lex-ai-act-2024-1689` | `2026-05-07-digital-omnibus-merge` | `en` |\n"
            "| `internal-policy-corpus` | `2026-05-20` | `en` |"
        ),
        "retrieval_event_count": "18",
    }

    if template_name == "eu-ai-act-article-13":
        common.update(_sample_article_13())
    elif template_name == "nist-ai-rmf-1":
        common.update(_sample_nist_rmf())
    elif template_name == "iso-iec-42001":
        common.update(_sample_iso_42001())
    elif template_name == "owasp-agentic-ai-v1":
        common.update(_sample_owasp_agentic(verdict_distribution))
    return common


def _sample_article_13() -> dict[str, Any]:
    return {
        "provider_name": "[SAMPLE] Acme Holdings Inc.",
        "system_identifier": "[SAMPLE] AcmeAgent-v3.2",
        "intended_purpose": "[SAMPLE] Customer-service agent answering account-status questions within a regulated banking context.",
        "declared_limitations": "[SAMPLE] Cannot perform funds transfer; cannot access PII beyond declared scope; cannot operate outside business hours.",
        "out_of_scope_uses": "[SAMPLE] Investment advice; medical advice; legal interpretation.",
        "key_storage_location": "~/.phionyx/keys/",
        "key_storage_mode": "0600 (private) / 0644 (public), local filesystem",
        "worm_storage_status": "not configured (development default)",
        "anomaly_followup_instruction": "[SAMPLE] Each anomaly-flagged envelope is triaged by the on-call ML-platform engineer within 24 hours; mitigation logged in the project's incident response system.",
        "key_rotation_event_count": 0,
        "key_revocation_referenced_count": 0,
        "verification_command": "phionyx-compliance generate --trace trace-e2dd588aaf4d4c97 --template eu-ai-act-article-13",
    }


def _sample_nist_rmf() -> dict[str, Any]:
    return {
        "provider_name": "[SAMPLE] Acme Holdings Inc.",
        "system_identifier": "[SAMPLE] AcmeAgent-v3.2",
        "ai_use_case_category": "[SAMPLE] Customer service — account inquiry assistance (regulated banking).",
        "governance_policy_summary": "[SAMPLE] AI Governance Council reviews every model deployment; quarterly risk register update.",
        "roles_and_accountability": "[SAMPLE] Chief AI Officer owns risk acceptance; ML platform team owns operations; product owner accepts user-facing risk.",
        "risk_tolerance_statement": "[SAMPLE] Zero tolerance for funds-movement actions; low tolerance for PII disclosure; medium tolerance for response-time variation.",
        "intended_context": "[SAMPLE] Inbound chat in the consumer banking app, authenticated session only.",
        "ai_capabilities_scope": "[SAMPLE] Read account balance + transaction history; cannot write; cannot escalate outside the chat scope.",
        "identified_risks": "[SAMPLE] Hallucinated balance; misclassified intent; prompt-injection from upstream messages.",
        "out_of_chain_metrics": "[SAMPLE] User-reported satisfaction (CSAT), end-to-end latency p95, monthly cost-per-resolution.",
        "incident_response_procedure": "[SAMPLE] Anomaly → page on-call ML platform engineer → kill switch if confirmed → root-cause analysis within 48 hours.",
        "recovery_measures": "[SAMPLE] Roll back to previous model version via blue/green deployment; restore policy gate config from git.",
        "stakeholder_communication": "[SAMPLE] Incident summary to product owner within 4 hours; user-facing apology + 1-week status update.",
        "anomaly_followup_instruction": "[SAMPLE] Triaged by on-call ML platform engineer within 24 hours.",
    }


def _sample_iso_42001() -> dict[str, Any]:
    return {
        "aims_organisation": "[SAMPLE] Acme Holdings Ltd. — AI Operations division",
        "system_identifier": "[SAMPLE] AcmeAgent-v3.2",
        "life_cycle_stage": "[SAMPLE] Operation (Annex A.6 operational phase, post-validation)",
        "ai_policy_statement": "[SAMPLE] Top-management-approved AI policy v1.2 (2026-Q1): commitment to human oversight, evidence-based deployment, and quarterly review.",
        "aims_objectives": "[SAMPLE] (1) Zero unhandled incidents; (2) ≥ 95% gate-coverage on commit-class operations; (3) Quarterly anomaly review with documented resolution.",
        "risk_acceptance_criteria": "[SAMPLE] Accept anomaly rates ≤ 0.5% per assessment window; escalate ≥ 1.0% to management review.",
        "resources_allocated": "[SAMPLE] 2 FTE ML platform engineers; cloud budget allocation; access to managed KMS for signing keys.",
        "competence_assurance": "[SAMPLE] All AI operators complete annual AIMS competence training; on-call rotation requires a passing yearly assessment.",
        "operational_monitoring_procedures": "[SAMPLE] Real-time anomaly dashboard; weekly review of gate-verdict distribution; on-call alerted on anomaly_flag spike.",
        "user_facing_documentation": "[SAMPLE] In-app disclosure of AI use, limitations, and escalation path; FAQ published on the corporate website.",
        "transparency_artefacts_published": "[SAMPLE] Quarterly AI operations summary; this evidence report draft; key rotation log.",
        "anomaly_followup_instruction": "[SAMPLE] Triaged by on-call ML platform engineer; resolution captured in the AIMS internal-audit log.",
    }


def _sample_owasp_agentic(verdict_distribution: dict[str, int]) -> dict[str, Any]:
    return {
        "provider_name": "[SAMPLE] Acme Holdings Inc.",
        "system_identifier": "[SAMPLE] AcmeAgent-v3.2",
        "agent_topology": "[SAMPLE] Single-agent with MCP tool calls (no multi-agent supervisor)",
        "descriptor_approval_workflow": "[SAMPLE] Every new tool descriptor requires CISO + product owner sign-off; baseline hash recorded on approval.",
        "capability_profile_policy": "[SAMPLE] Each tool bound to a read-only or read-write profile; profile change requires re-approval.",
        "hitl_invocation_policy": "[SAMPLE] HITL triggered for: high-value transactions (>$X), low-confidence verdicts, anomaly-flag escalation.",
        "rate_limit_controls": "[SAMPLE] Token budget per session; per-tool QPS cap; circuit breaker on consecutive anomaly_flag=true envelopes.",
        "anomaly_followup_instruction": "[SAMPLE] Triaged by on-call ML platform engineer within 24 hours.",
        # OWASP per-threat statuses — computed by the renderer's helpers via mapping.py's
        # generic dispatch. We pre-fill them here for the sample so the render does not
        # depend on the mapping resolver path.
        "t1_memory_status":           render_t1_memory_status(),
        "t2_tool_misuse_status":      render_t2_tool_misuse_status(descriptor_change_count=0, tool_call_count=132),
        "t3_privilege_status":        render_t3_privilege_status(),
        "t4_resource_status":         render_t4_resource_status(),
        "t5_cascading_status":        render_t5_cascading_status(),
        "t6_intent_breaking_status":  render_t6_intent_breaking_status(verdict_distribution=verdict_distribution),
        "t7_misaligned_status":       render_t7_misaligned_status(anomaly_count=0),
        "t8_repudiation_status":      render_t8_repudiation_status(chain_valid=True, envelope_count=155),
        "t9_spoofing_status":         render_t9_spoofing_status(signing_key_id="key-sample-2026-05"),
        "t10_hitl_status":            render_t10_hitl_status(hitl_count=0),
    }


# ── Derived-field renderer helpers ─────────────────────────────────

def render_verdict_distribution_table(distribution: dict[str, int]) -> str:
    """Produce a markdown table from {verdict: count} dict."""
    if not distribution:
        return "_(no verdicts recorded in the window)_"
    lines = ["| Verdict | Count |", "|---|---:|"]
    for verdict, count in sorted(distribution.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| `{verdict}` | {count} |")
    return "\n".join(lines)


def render_chain_valid_label(valid: bool, broken_at: int | None = None) -> str:
    if valid:
        return "✓ valid"
    if broken_at is not None:
        return f"✗ broken at envelope {broken_at}"
    return "✗ broken"


def render_chain_integrity_summary(
    envelope_count: int,
    valid: bool,
    broken_at: int | None,
    reason: str | None,
) -> str:
    if valid:
        return (
            f"Chain validates at assessment time. {envelope_count} envelopes; "
            "no broken links; Ed25519 signatures verify against the producer's "
            "published public key."
        )
    return (
        f"Chain does NOT validate. {envelope_count} envelopes; broken at "
        f"envelope {broken_at}. Reason: {reason or '<not reported>'}. "
        "Auditor must treat any claims that depend on envelopes after the "
        "break point as unverified."
    )


def render_verification_command(trace_id: str) -> str:
    return (
        "python3 scripts/active/runtime_evidence_test_scenarios.py  "
        "# verifies chain via D1 + B1/B2 scenarios"
    )


def render_human_oversight_summary(hitl_count: int) -> str:
    if hitl_count == 0:
        return (
            "No HITL invocations recorded in this window. All gate verdicts "
            "resolved within the deterministic decision boundary; no human "
            "override events to report."
        )
    return (
        f"HITL invoked {hitl_count} time(s) in this window. Each invocation "
        "produces its own envelope in the chain with the human reviewer's "
        "decision and rationale recorded. Auditor should review each in turn."
    )


def render_generated_at_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


def render_reproduction_command(trace_id: str, template_name: str) -> str:
    return f"phionyx-compliance generate --trace {trace_id} --template {template_name}"


# ── OWASP Agentic AI v1.0 — per-threat coverage statuses ───────────

def render_t1_memory_status(*args, **kwargs) -> str:
    return "**Operator-required.** Memory-write provenance not yet recorded in the chain (F15 memory diff audit lands at v0.7.0 W3)."


def render_t2_tool_misuse_status(descriptor_change_count: int = 0, tool_call_count: int = 0, **kwargs) -> str:
    if descriptor_change_count == 0:
        return f"**Chain-derived — clean.** {tool_call_count} tool calls; 0 descriptor changes during the assessment window."
    return f"**Chain-derived — review needed.** {descriptor_change_count} descriptor-change events out of {tool_call_count} tool calls — auditor reviews each in turn."


def render_t3_privilege_status(*args, **kwargs) -> str:
    return "**Partial.** Capability profile policy is operator-supplied; chain records each tool call's permission scope when emitted by the server MCP."


def render_t4_resource_status(*args, **kwargs) -> str:
    return "**Operator-required.** Rate-limit and token-budget telemetry live outside the chain in the operator's monitoring stack."


def render_t5_cascading_status(*args, **kwargs) -> str:
    return "**Operator-required.** Downstream-effect tracking is operator-side; the chain records the agent's actions, not their downstream consequences."


def render_t6_intent_breaking_status(verdict_distribution: dict | None = None, **kwargs) -> str:
    verdicts = verdict_distribution or {}
    reject = verdicts.get("reject", 0)
    regen = verdicts.get("regenerate", 0)
    if reject == 0 and regen == 0:
        return "**Chain-derived — clean.** No `reject` or `regenerate` directives in the assessment window."
    return f"**Chain-derived.** {reject} `reject` + {regen} `regenerate` directives — these are the gate's record of intent-breaking attempts."


def render_t7_misaligned_status(anomaly_count: int = 0, **kwargs) -> str:
    if anomaly_count == 0:
        return "**Partial — clean.** 0 envelopes carry `anomaly_flag=true` during the assessment window; semantic validation of behaviour is operator-required."
    return f"**Partial — review needed.** {anomaly_count} envelopes carry `anomaly_flag=true`; operator's semantic-validation procedure resolves each."


def render_t8_repudiation_status(chain_valid: bool = True, envelope_count: int = 0, **kwargs) -> str:
    if chain_valid and envelope_count > 0:
        return f"**Chain-derived — direct coverage.** {envelope_count} envelopes; chain validates; every decision is signed and replayable."
    if not chain_valid:
        return "**Chain-derived — INTEGRITY FAILURE.** Chain does NOT validate at assessment time. Repudiation defence is compromised; the operator must investigate before the report is used."
    return "**Partial.** No envelopes in the assessment window — repudiation defence is theoretical until the chain accumulates evidence."


def render_t9_spoofing_status(signing_key_id: str = "", **kwargs) -> str:
    if signing_key_id == "<varies>":
        return "**Partial — review.** Multiple signing keys observed in the assessment window. Operator confirms each key is legitimate per the rotation log."
    if signing_key_id:
        return f"**Partial.** All envelopes signed under key `{signing_key_id}`; key-management posture per `docs/security/CRYPTOGRAPHIC_POSTURE_ROADMAP.md` is operator-required."
    return "**Partial.** No signing key observed in the chain (empty window)."


def render_t10_hitl_status(hitl_count: int = 0, **kwargs) -> str:
    if hitl_count == 0:
        return "**Chain-derived — clean.** No HITL invocations in the assessment window; control of HITL volume is operator policy."
    return f"**Chain-derived.** {hitl_count} HITL invocations recorded; operator's HITL-invocation policy resolves whether this volume is normal."


# ── F4 + F8 — knowledge sources and retrieval evidence (v0.7.0 W2) ──

def render_knowledge_sources_summary_table(chain=None, **kwargs) -> str:
    """Tally `reasoning.knowledge_sources_consulted` across the chain.

    Counts source_type values from each envelope's reasoning block when
    the producer populated it. Returns a markdown table grouped by
    source_type, with a footnote stating how many envelopes contributed.
    Returns a graceful empty-state line when no envelope populated the
    field — this is the expected reading for windows produced before
    F4 emission was enabled core-side.
    """
    if chain is None or not chain.envelopes:
        return "_No envelopes in the assessment window._"
    counts: dict[str, int] = {}
    envelopes_with_sources = 0
    for env in chain.envelopes:
        sources = (env.get("reasoning") or {}).get("knowledge_sources_consulted") or []
        if sources:
            envelopes_with_sources += 1
            for src in sources:
                if isinstance(src, dict):
                    # Schema field is `kind` (one of retrieval_corpus / memory_block /
                    # tool_output / tool_descriptor_clause / static_doc / system_prompt /
                    # external_api). Per `rge_v0_2.schema.json` $defs.reasoning.
                    t = str(src.get("kind") or "unknown")
                    counts[t] = counts.get(t, 0) + 1
    if not counts:
        return (
            "_No `reasoning.knowledge_sources_consulted` populated in this window — "
            "either the producer is pre-v0.7.0, or the producer surfaced no "
            "knowledge sources in this assessment window._"
        )
    lines = ["| Source type | Count |", "|---|---:|"]
    for t, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| `{t}` | {c} |")
    lines.append("")
    lines.append(
        f"*{envelopes_with_sources} of {chain.envelope_count} envelopes surfaced "
        f"`reasoning.knowledge_sources_consulted` in this window.*"
    )
    return "\n".join(lines)


def render_retrieval_corpus_summary_table(chain=None, **kwargs) -> str:
    """List distinct `retrieval.corpus` values observed in the chain.

    A producer that uses RAG populates retrieval.corpus with
    {name, version, language}. We surface the distinct (name, version,
    language) triples observed across the window so the auditor can
    confirm which corpora the system actually queried.
    """
    if chain is None or not chain.envelopes:
        return "_No envelopes in the assessment window._"
    seen: set[tuple] = set()
    corpora: list[dict] = []
    for env in chain.envelopes:
        c = (env.get("retrieval") or {}).get("corpus")
        if isinstance(c, dict) and c:
            key = (c.get("name"), c.get("version"), c.get("language"))
            if key not in seen:
                seen.add(key)
                corpora.append(c)
    if not corpora:
        return (
            "_No `retrieval.corpus` populated in this window — either no RAG "
            "events occurred, or the producer has not flipped its retrieval "
            "block from `reserved-for-v0.4.1-f8` to `active`._"
        )
    lines = ["| Corpus name | Version | Language |", "|---|---|---|"]
    for c in corpora:
        lines.append(
            f"| `{c.get('name', '') or '(unnamed)'}` "
            f"| `{c.get('version', '') or '—'}` "
            f"| `{c.get('language', '') or '—'}` |"
        )
    return "\n".join(lines)


def render_retrieval_event_count(chain=None, **kwargs) -> str:
    """Count envelopes whose retrieval.documents array is non-empty."""
    if chain is None or not chain.envelopes:
        return "0"
    n = sum(
        1
        for e in chain.envelopes
        if ((e.get("retrieval") or {}).get("documents") or [])
    )
    return str(n)


__all__ = [
    "render",
    "sample_inputs",
    "render_verdict_distribution_table",
    "render_chain_valid_label",
    "render_chain_integrity_summary",
    "render_verification_command",
    "render_human_oversight_summary",
    "render_generated_at_iso",
    "render_reproduction_command",
    "render_t1_memory_status",
    "render_t2_tool_misuse_status",
    "render_t3_privilege_status",
    "render_t4_resource_status",
    "render_t5_cascading_status",
    "render_t6_intent_breaking_status",
    "render_t7_misaligned_status",
    "render_t8_repudiation_status",
    "render_t9_spoofing_status",
    "render_t10_hitl_status",
    "render_knowledge_sources_summary_table",
    "render_retrieval_corpus_summary_table",
    "render_retrieval_event_count",
]
