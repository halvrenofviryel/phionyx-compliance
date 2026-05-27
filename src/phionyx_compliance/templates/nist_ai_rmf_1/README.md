# Template: `nist-ai-rmf-1`

> **Framework:** NIST AI RMF 1.0 (MAP / MEASURE / MANAGE / GOVERN)
> **Reference:** NIST AI 100-1, January 2023, DOI 10.6028/NIST.AI.100-1
> **Template version:** `1.0.0` (W1.5, 2026-05-26)
> **Status:** alpha

## What this template produces

A markdown DRAFT structured against the four NIST AI RMF 1.0 functions. The runtime evidence chain provides direct evidence for MEASURE; GOVERN, MAP, and MANAGE are operator-supplied.

## NIST AI RMF 1.0 functions covered

| Function | Section | Source of evidence |
|---|---|---|
| GOVERN 1.x | §2 | operator-supplied (policies, roles, risk tolerance) |
| MAP 1.x-5.x | §3 | operator-supplied (context, capabilities, risks) |
| MEASURE 2.x (tracking) | §4 | chain-derived (verdicts, anomalies, descriptors) |
| MANAGE 4.x | §5 | operator-supplied (response, recovery, communication) |

## What this template does NOT do

- Does NOT establish "RMF compliance" — the RMF is voluntary, NIST does not certify.
- Does NOT cover NIST AI 600-1 Generative AI Profile categories (planned for a separate template).
- Does NOT replace the RMF Playbook's category-specific guidance.
- Does NOT exercise GOVERN, MAP, or MANAGE — those are organisational processes the chain cannot record.

## Files

```
templates/nist_ai_rmf_1/
├── template.md / schema.json / mapping.yaml / disclaimer.md / README.md
```

## Sample render

```bash
phionyx-compliance generate --template nist-ai-rmf-1 --sample --out /tmp/nist-sample.md
```
