# Template: `owasp-agentic-ai-v1`

> **Framework:** OWASP Agentic AI Threats v1.0 (February 2025)
> **Reference:** OWASP Foundation, Generative AI Security Project
> **Template version:** `1.0.0` (W1.5, 2026-05-26)
> **Status:** alpha

## What this template produces

A markdown DRAFT structured against OWASP's Agentic AI threat taxonomy. The output is a per-threat **coverage table** showing what direct evidence the chain provides for each threat and what is operator-required.

## Threat coverage matrix

| Threat | Chain coverage | Section |
|---|---|---|
| T1 Memory Poisoning | operator-required (memory-write provenance not yet recorded in the chain) | §2 |
| T2 Tool Misuse | **chain-derived** (descriptor_change_count, tool_call_count) | §2, §3 |
| T3 Privilege Compromise | partial (capability profile policy) | §2, §4 |
| T4 Resource Overload | operator-required (rate-limit telemetry outside chain) | §2, §4 |
| T5 Cascading Hallucinations | operator-required (downstream tracking) | §2, §6 |
| T6 Intent Breaking & Goal Manipulation | **chain-derived** (gate verdict distribution) | §2, §3 |
| T7 Misaligned & Deceptive Behaviors | partial (anomaly_flag distribution) | §2, §6 |
| T8 Repudiation & Untraceability | **chain-derived (direct)** — chain IS the answer | §2, §5 |
| T9 Identity Spoofing | partial (signing_key_id continuity) | §2 |
| T10 Overwhelming HITL | **chain-derived** (HITL invocation count) | §2, §5.2 |

## What this template does NOT do

- Does NOT certify against the OWASP taxonomy — OWASP itself does not certify.
- Does NOT cover threats whose evidence lives outside the runtime chain (T1, T4, T5).
- Does NOT replace the OWASP document — full threat descriptions and mitigation patterns are at the source URL in `disclaimer.md`.

## Files

```
templates/owasp_agentic_ai_v1/
├── template.md / schema.json / mapping.yaml / disclaimer.md / README.md
```

## Sample render

```bash
phionyx-compliance generate --template owasp-agentic-ai-v1 --sample --out /tmp/owasp-sample.md
```
