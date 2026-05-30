# phionyx-compliance

> **Evidence-grade compliance report drafts from Phionyx RGE v0.2 audit chains.**
> AGPL-3.0 · Python 3.10+ · v0.1.1 (alpha) on PyPI

`phionyx-compliance` turns a signed envelope chain produced by `phionyx-core`,
`phionyx-mcp-server`, or any other Phionyx component into a framework-shaped
markdown draft report — suitable as input to a compliance officer or auditor's
review.

**It does not certify.** Reports are *evidence-oriented mappings*; a lawyer or
auditor must review before any use that implies legal posture.

**Where this sits in the stack:** `phionyx-compliance` is a **reporting adapter**.
It is one of several adapters that consume Phionyx envelope chains; it is not the
deterministic engine (`phionyx-core`, the SDK), the self-governance gate
(`phionyx-pipeline-mcp`), or the Evaluation Standard. See
[Composition with the Phionyx stack](#composition-with-the-phionyx-stack) below.

---

## Sixty-second usage

```bash
pip install phionyx-compliance
phionyx-compliance generate \
  --trace trace-e2dd588aaf4d4c97 \
  --template eu-ai-act-article-13 \
  --out reports/<DATE>-article-13-draft.md
```

What it does:

1. Reads the envelope chain at `~/.phionyx/mcp_audit/<trace_id>/` (or the
   path the operator passes via `--chain-root`).
2. Walks the chain and extracts the per-envelope evidence the chosen
   template requires.
3. Renders a markdown draft against the template's prompts and the
   chain's actual evidence.
4. Includes the canonical disclaimer at the head and tail of the
   document.

## Supported templates

All four framework templates ship in v0.1.1:

| Template | Framework | Status |
|---|---|---|
| `eu-ai-act-article-13` | EU AI Act, Article 13 (transparency) | shipped |
| `nist-ai-rmf-1` | NIST AI RMF 1.0 — MAP/MEASURE/MANAGE/GOVERN | shipped |
| `iso-iec-42001` | ISO/IEC 42001:2023 — Annex A controls subset | shipped |
| `owasp-agentic-ai-v1` | OWASP Agentic AI Threats v1.0 coverage | shipped |

Each template is a self-contained directory under `templates/<framework>/`:

```
templates/
└── eu-ai-act-article-13/
    ├── template.md          (markdown with {{placeholders}})
    ├── schema.json          (Pydantic JSON Schema for the data inputs)
    ├── mapping.yaml         (how envelope fields → template placeholders)
    └── README.md            (framework-specific notes + disclaimer text)
```

## Composition with the Phionyx stack

`phionyx-compliance` is **read-only** over the envelope chain. It does not
modify chain state, does not re-sign anything, and does not produce envelopes
of its own. The output is a markdown file plus an optional JSON-formatted
summary (`--format=json`).

Phionyx ships three distinct things, each with its own version line — this
package is a downstream **adapter** that consumes their output:

- **`phionyx-core`** (the SDK / deterministic-cognition engine, latest **v0.7.2**)
  — produces the signed audit chain this package reads. It is the reference
  implementation scoring **L3 + D3** on the Evaluation Standard. It is **not**
  claim-governance-rated.
- **`phionyx-pipeline-mcp`** (the self-claim gate, stable **v0.2.0** / alpha
  **v0.3.0a1**) — its self-claim gate envelopes feed the *"agent's own
  attestations"* section of every framework template. This is the component the
  Claim-Governance ladder (CG-L0…CG-L5) rates: v0.2.0 = CG-L2, alpha v0.3.0a1 =
  CG-L3 (opt-in/default-off).
- **`phionyx-mcp-server`** (the MCP trust boundary, **v0.1.0**) — its third-party
  tool-call envelopes feed the *"tool-call audit"* section.
- **`phionyx-eval-inspect`** (**v0.1.0**) — Inspect AI `.eval` exports include the
  same envelope chain; the compliance draft can cite the `.eval` log id as the
  reviewer-runnable evidence pointer.

**Evaluation Standard cross-ref:** the
[`phionyx-evaluation-standard`](https://github.com/halvrenofviryel/phionyx-evaluation-standard)
(released **v0.1.1 / v0.2.0**; **v0.3** is a draft) is the vendor-neutral spec
defining the **L0-L3** (evaluation maturity), **D0-D3** (determinism), and
**CG-L0…CG-L5** (claim-governance) scales. The CG ladder rates the **gate**
(`phionyx-pipeline-mcp`), not the SDK; `phionyx-core` is the reference
implementation on the L0-L3 / D0-D3 axes.

## Plugin command

The `phionyx-claude-code-plugin` provides `/phionyx:evidence-report`, which
shells out to this package and renders the draft inline in the Claude Code
chat. The plugin follows pattern-extraction discipline only — no Anthropic
plugin content is copied verbatim.

## Status

- **Scaffold.** Package skeleton, dependency pin to `phionyx-core` (v0.7.x line),
  CLI entry-point declared.
- **Template substrate.** First template: `eu-ai-act-article-13` v1.0.0.
  Renderer + CLI subcommands (`list-templates` / `describe` / `render-sample` /
  `generate --sample`).
- **Chain → inputs walker.** `ChainView.from_disk()` + `resolve_inputs()` (a
  four-category mapping resolver). Real `generate --trace <id>` works.
- **Plugin integration.** `/phionyx:evidence-report` slash command in the Claude
  Code plugin wraps the CLI.
- **Additional templates.** Three further framework templates at v1.0.0 each:
  - `nist-ai-rmf-1` (NIST AI RMF 1.0 — MAP/MEASURE/MANAGE/GOVERN)
  - `iso-iec-42001` (ISO/IEC 42001:2023 — AI Management System)
  - `owasp-agentic-ai-v1` (OWASP Agentic AI Threats v1.0 — threat coverage)
  with a cross-template parity test suite (`test_all_templates.py`).

All four framework templates are shipped in v0.1.1. The next milestone adds
reasoning-audit and RAG-audit sections to the evidence walker.

See `docs/DESIGN.md` for design notes.

## Disclaimer (canonical)

> *Reports produced by this package are evidence-oriented mappings, not legal
> compliance guarantees. A lawyer or auditor must review before any use that
> implies legal posture. Phionyx does not certify AI systems; it produces the
> evidence chains that certifications rely on.*

## License

AGPL-3.0-or-later. See `LICENSE`.

## Citing

If you use `phionyx-compliance` in academic or policy work, cite the parent
project: Abak, A. T. (2026). *Phionyx Research — Runtime Evidence Layer for
Agentic AI*. ORCID [0009-0002-3718-4010](https://orcid.org/0009-0002-3718-4010).
