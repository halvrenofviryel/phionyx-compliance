# Template: `eu-ai-act-article-13`

> **Framework:** EU AI Act, Article 13 (transparency)
> **Template version:** `1.0.0` (initial, 2026-05-26)
> **Status:** alpha — first framework template, lands at v0.7.0 W1.2.

## What this template produces

A markdown draft report structured against Article 13 transparency obligations. The draft separates:

- **operator-supplied** fields (intended purpose, declared limitations, key storage location, ...) — operator is the source of truth.
- **chain-derived** fields (envelope counts, verdict distribution, descriptor stability, ...) — auto-populated from the RGE v0.2 envelope chain (W1.3).
- **canonical** fields (disclaimers) — fixed constants from the `phionyx-compliance` package.
- **derived** fields (formatted tables, summary paragraphs) — computed by renderer helpers in `phionyx_compliance.renderer`.

## Article 13 obligations covered

| Article 13 sub-obligation | Section | Source of evidence |
|---|---|---|
| 13(1) Intended purpose communicated | §2 | operator-supplied |
| 13(1)(b) Performance characteristics | §3 | chain-derived |
| 13(2) Logging | §4 | chain-derived |
| 13(3) Third-party verifiability | §4 | chain-derived (Ed25519 + SHA-256 chain) |
| Article 14 (cross-ref, human oversight) | §5 | chain-derived (HITL) |
| Article 15 (cross-ref, cybersecurity) | §6 | mixed |
| Operator residual responsibilities | §7 | canonical text |

## What this template does NOT do

- Does NOT produce certification or compliance attestation — drafts only.
- Does NOT cover Article 13(1)(a) "characteristics and capabilities" (operator documentation).
- Does NOT cover accuracy/precision metrics beyond gate-verdict distribution — see `examples/benchmark/` (L8).
- Does NOT cover training-data information (Article 10 scope).
- Does NOT track Digital Omnibus deferrals — operator verifies current applicability.

## Files

```
templates/eu_ai_act_article_13/
├── template.md       # markdown skeleton with {{placeholders}}
├── schema.json       # JSON Schema for inputs
├── mapping.yaml      # how RGE v0.2 envelope fields → schema inputs
├── disclaimer.md     # framework-specific addendum
└── README.md         # this file
```

## Versioning

- **Major (1.x → 2.x):** placeholder renamed or removed (breaking).
- **Minor (1.0 → 1.1):** new placeholder (additive).
- **Patch (1.0.0 → 1.0.1):** prose only.

When Article 13 itself changes, template bumps and the previous version is preserved under `templates/eu_ai_act_article_13_v1_0_0/` for reproducibility.

## Sample render

W1.2 ships `--sample` mode:

```bash
phionyx-compliance generate --template eu-ai-act-article-13 --sample --out /tmp/sample.md
```

Output is a complete markdown document with canonical head/tail disclaimer and synthetic chain-derived values. Useful for reviewing the template shape; NOT a real assessment.
