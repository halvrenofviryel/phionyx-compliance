# phionyx-compliance — Design Notes

> **Audience:** Phionyx contributors implementing the W1.2-W1.5 work blocks of v0.7.0.
> **Status:** v0.1 (W1.1 boundary, 2026-05-26).

## 1. Two design constraints

1. **Templates are data, not code.** Adding a new framework (e.g. UK AI Bill once
   it lands) means dropping a new directory under `templates/<framework>/`. It
   does NOT mean editing the renderer. The renderer is one piece of code that
   knows how to read a `template.md` + `schema.json` + `mapping.yaml` and
   project an envelope chain through them.
2. **Every output is a draft.** The package never produces text that reads as
   a compliance statement. Every output carries the disclaimer at the head AND
   tail. Templates are written in the voice of *"based on the runtime evidence,
   the following observations apply ..."* — never *"the system complies with
   ..."*.

## 2. Template anatomy

```
templates/eu-ai-act-article-13/
├── template.md      # the markdown skeleton with {{placeholders}}
├── schema.json      # JSON Schema for the inputs the template reads
├── mapping.yaml     # how RGE v0.2 envelope fields map to the schema inputs
├── README.md        # framework-specific notes, version, sources
└── disclaimer.md    # framework-specific disclaimer addendum
```

### `template.md` example skeleton (Article 13)

```markdown
# Evidence Report Draft — EU AI Act Article 13 (Transparency)

**Disclaimer.** {{disclaimer.head}}

## 1. System under evaluation

- **Trace ID:** `{{trace_id}}`
- **Window:** {{window_start}} → {{window_end}}
- **Envelopes assessed:** {{envelope_count}}
- **Chain validity at assessment:** {{chain_valid}}

## 2. Transparency-relevant operations (Article 13(1))

The runtime evidence chain records {{tool_call_count}} tool calls during the
assessed window. For each, the envelope captures: tool descriptor hash, input
hash, output hash, the deterministic gate verdict, and the signed integrity
block.

{{tool_call_audit_table}}

## 3. Agent self-claims (composition with Article 13's user-information requirements)

The pipeline MCP recorded {{claim_count}} agent self-claims subject to
deterministic gate verification. Verdict distribution: {{verdict_distribution}}.

{{claim_audit_table}}

[... continues per the framework's specific obligations ...]

---

**Disclaimer (tail).** {{disclaimer.tail}}
```

### `schema.json` shape

Pydantic-derived JSON Schema (Draft 2020-12) for the data the template consumes:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "EUAIActArticle13ReportInputs",
  "type": "object",
  "required": ["trace_id", "window_start", "window_end", "envelope_count", "chain_valid"],
  "properties": {
    "trace_id": {"type": "string"},
    "window_start": {"type": "string", "format": "date-time"},
    "window_end": {"type": "string", "format": "date-time"},
    "envelope_count": {"type": "integer", "minimum": 0},
    "chain_valid": {"type": "boolean"},
    "tool_call_count": {"type": "integer", "minimum": 0},
    "tool_call_audit_table": {"type": "string"},
    "claim_count": {"type": "integer", "minimum": 0},
    "verdict_distribution": {"type": "object"},
    "claim_audit_table": {"type": "string"},
    "disclaimer": {
      "type": "object",
      "required": ["head", "tail"],
      "properties": {
        "head": {"type": "string"},
        "tail": {"type": "string"}
      }
    }
  }
}
```

### `mapping.yaml` shape

Declares how RGE v0.2 envelope fields are aggregated into the schema's inputs:

```yaml
# Each top-level key matches a schema property; the value is the rule
# the renderer applies to the envelope-chain iteration result.
trace_id:
  source: chain.trace_id

window_start:
  source: chain.envelopes[0].timestamp_utc

window_end:
  source: chain.envelopes[-1].timestamp_utc

envelope_count:
  source: chain.envelope_count

chain_valid:
  source: chain.verify_result.valid

tool_call_count:
  source: chain.envelopes
  filter: { schema_id: "phionyx.governed_response_envelope.v0.2" }
  count: true

tool_call_audit_table:
  source: chain.envelopes
  filter: { schema_id: "phionyx.governed_response_envelope.v0.2" }
  renderer: markdown_table
  columns:
    - { name: "Turn", source: "turn_index" }
    - { name: "Tool", source: "subject.tool_descriptor_hash[:12]" }
    - { name: "Decision", source: "subject.decision" }
    - { name: "Reason", source: "subject.decision_reason" }
    - { name: "Hash", source: "integrity.current[:16]" }
```

## 3. Renderer pseudocode

```python
def generate_report(
    template_name: str,
    chain_root: Path,
    trace_id: str,
    out: Path,
) -> ReportResult:
    template = load_template(template_name)
    chain = walk_chain(chain_root, trace_id)
    chain_view = ChainView.from_envelopes(chain)

    inputs = {}
    for schema_key, rule in template.mapping.items():
        inputs[schema_key] = apply_mapping_rule(rule, chain_view)

    # Inputs MUST validate against the schema; never render with a missing
    # required field.
    template.schema.model_validate(inputs)

    inputs["disclaimer"] = {
        "head": CANONICAL_HEAD_DISCLAIMER,
        "tail": CANONICAL_TAIL_DISCLAIMER + "\n" + template.framework_addendum,
    }

    markdown = template.render(inputs)
    out.write_text(markdown, encoding="utf-8")
    return ReportResult(
        out_path=out,
        envelope_count=inputs["envelope_count"],
        chain_valid=inputs["chain_valid"],
    )
```

## 4. CLI contract

```text
phionyx-compliance generate
  --trace <id>                     (required)
  --template <name>                (required; e.g. eu-ai-act-article-13)
  --chain-root <path>              (default ~/.phionyx/mcp_audit/)
  --out <path>                     (default reports/<DATE>-<trace>-<template>.md)
  --format markdown|json           (default markdown)
  --strict                         (refuse to render if chain_valid=false)

phionyx-compliance list-templates
  (prints available templates with framework name + version)

phionyx-compliance describe <template-name>
  (prints the template's framework, version, and the schema's required fields)
```

## 5. What this design deliberately rejects

- **No LLM in the renderer.** The renderer is pure data transformation. Determinism is load-bearing: same envelope chain + same template = same report. (A future v1.x may add an *optional* LLM-narrative-polish layer, gated behind `--llm-narrative` flag, but the canonical output remains data-driven.)
- **No PDF output in v0.7.0.** Markdown ships; PDF is a downstream conversion left to the operator (`pandoc paper.md -o paper.pdf`). v0.8.0 may add direct PDF if there's demand.
- **No "compliant" / "complies with" / "meets the requirements of" language anywhere.** Templates are reviewed for this language at every PR.
- **No silent fallback** when a required envelope field is missing — render fails loudly so the operator knows the chain is incomplete for the requested template.

## 6. Open design questions for W1.2

1. **Disclaimer location:** head + tail (current spec) vs. head + every section (more cautious) vs. tail only (operator's choice). Recommend head + tail; auditor sees the framing at both ends.
2. **Schema validation strictness:** refuse to render on validation failure (current spec) vs. render with `??` placeholders + a warnings section. Recommend strict for v0.7.0; the warnings-tolerant mode is v1.x.
3. **Multi-trace reports:** a single report spans one `trace_id`. Should v0.7.0 support multi-trace reports (e.g. "this report covers traces T1, T2, T3")? Recommend single-trace for v0.7.0; multi-trace is a v0.8.0 consideration if compliance officers ask.
4. **Template versioning:** how to handle Article 13's evolution (Digital Omnibus deferrals)? Recommend semver on each template: `eu-ai-act-article-13@1.0` ships at v0.7.0; subsequent template updates bump the version without breaking existing reports.

These resolve as W1.2 lands.

---

*Phionyx Research · 2026-05-26 · W1.1 boundary spec for v0.7.0 Compliance Evidence Pack.*
