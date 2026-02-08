---
name: masvs-security-review
description: Perform evidence-based mobile app security reviews using OWASP MASVS. Use this skill when asked to map findings to MASVS control IDs, prioritize by MAS domains and risk, or produce practical remediation guidance tied to MASVS controls.
---

# MASVS Security Review

Use OWASP MASVS as the baseline and report concrete, evidence-backed findings mapped to MASVS control IDs.

## Keep It Practical

- Default to focused review scope, not full certification claims.
- Prioritize controls based on app attack surface and business risk.
- Expand coverage only when explicitly requested.

## Inputs To Collect

Collect these inputs before reviewing:
- Scope: repo/module/features to assess.
- App context: platform (iOS/Android/cross-platform), auth model, data sensitivity, backend trust boundaries.
- Threat profile: default to MAS-L1 assumptions unless higher-risk context implies MAS-L2 and/or MAS-R focus.
- Evidence sources: code, configs, build scripts, CI/CD, architecture docs, tests.

If scope/profile is missing, infer conservatively and state assumptions.

## Source Of Truth

Use the bundled MASVS dataset:
- `references/OWASP_MASVS.v2.0.0.json`

Supplement with:
- `references/masvs-quick-map.md` for domain navigation and prioritization.
- `scripts/masvs_lookup.py` to shortlist controls by keyword/domain/profile.

Lookup defaults to bundled data. Override with `--data` or `MASVS_JSON`.

## Review Workflow

1. Build a threat-aware control focus.
- Identify relevant MASVS domains from app behavior (storage, crypto, auth, network, platform, code, resilience, privacy).
- Prioritize likely high-impact gaps first.

2. Gather implementation evidence.
- Trace concrete code/config paths that implement or violate controls.
- Prefer verifiable evidence: file paths, functions, manifests, transport settings, secure storage usage, key handling, attestation/root checks, data flows.

3. Map findings to MASVS controls.
- Map each finding to one or more control IDs (for example `MASVS-NETWORK-1`).
- Explain why evidence indicates pass/fail/uncertain.

4. Rate risk and confidence.
- Severity: `Critical`, `High`, `Medium`, `Low`.
- Confidence: `High`, `Medium`, `Low` based on evidence quality.
- Use `Needs validation` when evidence is incomplete.

5. Recommend remediation and verification.
- Provide minimal actionable code/config changes.
- Tie each recommendation to MASVS control IDs.
- Include concrete validation checks (tests, static checks, runtime checks).

## Fast Lookup Examples

```bash
scripts/masvs_lookup.py pinning --domain MASVS-NETWORK --limit 10
scripts/masvs_lookup.py biometrics --domain MASVS-AUTH --limit 10
scripts/masvs_lookup.py tamper --level R --limit 10
```

Note: MASVS v2 does not encode legacy L1/L2 mappings per control in this dataset. `--level R` is exact for resilience controls; `L1`/`L2` are treated as planning context.

## Output Format

Return findings first, then coverage summary.

For each finding include:
- `Title`
- `Severity`
- `MASVS`: control ID list
- `Evidence`: concrete code/config references
- `Risk`: exploitability and impact in this app context
- `Remediation`: specific changes
- `Validation`: how to verify fix

Then include:
- `Coverage Summary`: domains reviewed, domains skipped, assumptions.
- `Top Next Checks`: highest-value remaining controls.

## Guardrails

- Do not invent MASVS control IDs.
- Do not claim compliance/certification; report observed evidence only.
- Distinguish `Not observed` from `Not implemented`.
- Keep recommendations codebase-specific.
