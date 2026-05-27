# Template: `iso-iec-42001`

> **Framework:** ISO/IEC 42001:2023 (AI Management System)
> **Reference:** ISO/IEC 42001:2023 — AI management system
> **Template version:** `1.0.0` (W1.5, 2026-05-26)
> **Status:** alpha

## What this template produces

A markdown DRAFT structured against a subset of ISO/IEC 42001:2023's clauses and Annex A controls — specifically the controls most directly evidenced by the runtime envelope chain.

## ISO/IEC 42001 obligations covered

| Clause / control | Section | Source of evidence |
|---|---|---|
| Clause 5.2 (AI policy) | §2 | operator-supplied |
| Clause 6.2 (AIMS objectives) | §2 | operator-supplied |
| A.4 (resources, competence) | §3 | operator-supplied |
| A.6.2.7-A.6.2.9 (operations subset) | §4 | chain-derived |
| A.8 (interested-parties information) | §5 | operator-supplied |
| Audit trail (Clause 7.5, 9.1, A.6.2.4) | §6 | chain-derived |
| A.9.3 (human oversight) | §6.2 | chain-derived |

## What this template does NOT do

- Does NOT replace internal audit (Clause 9.2) — it is one input.
- Does NOT cover A.5 (impact assessment), A.7 (data management), A.9 (use of AI), or A.10 (third-party relationships) — those require evidence outside the chain.
- Does NOT establish conformity — a notified body awards certification, not Phionyx.

## Files

```
templates/iso_iec_42001/
├── template.md / schema.json / mapping.yaml / disclaimer.md / README.md
```

## Sample render

```bash
phionyx-compliance generate --template iso-iec-42001 --sample --out /tmp/iso-sample.md
```
