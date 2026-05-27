# phionyx-compliance

> **Evidence-grade compliance report drafts from Phionyx RGE v0.2 audit chains.**
> AGPL-3.0 · Python 3.10+ · alpha (v0.7.0 cycle)

`phionyx-compliance` turns a signed envelope chain produced by `phionyx-core`,
`phionyx-mcp-server`, or any other Phionyx component into a framework-shaped
markdown draft report — suitable as input to a compliance officer or auditor's
review.

**It does not certify.** Reports are *evidence-oriented mappings*; a lawyer or
auditor must review before any use that implies legal posture.

---

## Sixty-second usage (target spec; lands at v0.7.0)

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

## Supported templates (v0.7.0 ship list)

| Template | Framework | Status |
|---|---|---|
| `eu-ai-act-article-13` | EU AI Act, Article 13 (transparency) | first to ship |
| `nist-ai-rmf-1` | NIST AI RMF 1.0 — MAP/MEASURE/MANAGE | second |
| `iso-iec-42001` | ISO/IEC 42001:2023 — Annex A controls subset | third |
| `owasp-agentic-ai-v1` | OWASP Agentic AI Threats v1.0 coverage | fourth |

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

This composes cleanly with:

- **`phionyx-pipeline-mcp`** — self-claim gate envelopes feed the *"agent's own
  attestations"* section of every framework template.
- **`phionyx-mcp-server`** — third-party tool-call envelopes feed the
  *"tool-call audit"* section.
- **`phionyx-eval-inspect`** — Inspect AI `.eval` exports include the same
  envelope chain; the compliance draft can cite the `.eval` log id as the
  reviewer-runnable evidence pointer.

## Plugin command (lands at v0.7.0 with F12++)

The `phionyx-claude-code-plugin` will gain `/phionyx:evidence-report` that
shells out to this package and renders the draft inline in the Claude Code
chat. Pattern preserves the v0.5.1 plugin extraction discipline (no Anthropic
plugin content copied verbatim).

## Status (2026-05-26)

- **W1.1 — scaffold landed.** Package skeleton, version pin to
  phionyx-core>=0.6.0, CLI entry-point declared.
- **W1.2 — template substrate landed.** First template: `eu-ai-act-article-13` v1.0.0. Renderer + CLI subcommands (list-templates / describe / render-sample / generate --sample). 15/15 tests.
- **W1.3 — chain → inputs walker landed.** `ChainView.from_disk()` + `resolve_inputs()` (4-category mapping resolver). Real `generate --trace <id>` works. 25/25 tests.
- **W1.4 — plugin integration landed.** `/phionyx:evidence-report` slash command in the Claude Code plugin wraps the CLI.
- **W1.5 — additional templates landed (this commit).** Three new framework templates at v1.0.0 each:
  - `nist-ai-rmf-1` (NIST AI RMF 1.0 — MAP/MEASURE/MANAGE/GOVERN)
  - `iso-iec-42001` (ISO/IEC 42001:2023 — AI Management System)
  - `owasp-agentic-ai-v1` (OWASP Agentic AI Threats v1.0 — threat coverage)
  Cross-template parity test suite (test_all_templates.py, 5 tests). **30/30 total tests pass.**

v0.7.0 W1 complete. W2 (F4 reasoning audit + F8 RAG audit) is the next milestone.

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
