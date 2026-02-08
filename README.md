# MASVS Security Review Skill

Practical Codex skill for evidence-based mobile app security reviews using OWASP MASVS.

## Included

- `SKILL.md`
- `references/OWASP_MASVS.v2.0.0.json` (bundled machine-readable dataset)
- `references/masvs-quick-map.md`
- `scripts/masvs_lookup.py`

## Install

```bash
mkdir -p "$CODEX_HOME/skills"
cp -R masvs-security-review "$CODEX_HOME/skills/masvs-security-review"
```

## Use In Codex

```text
Use $masvs-security-review.
Review this mobile app and map findings to MASVS control IDs with code evidence.
```

## Lookup Examples

Works out of the box with bundled data:

```bash
$CODEX_HOME/skills/masvs-security-review/scripts/masvs_lookup.py pinning --domain MASVS-NETWORK --limit 10
$CODEX_HOME/skills/masvs-security-review/scripts/masvs_lookup.py tamper --level R --limit 10
```

Override data source (optional):

```bash
$CODEX_HOME/skills/masvs-security-review/scripts/masvs_lookup.py crypto --data /path/to/OWASP_MASVS.v2.0.0.json
MASVS_JSON=/path/to/OWASP_MASVS.v2.0.0.json $CODEX_HOME/skills/masvs-security-review/scripts/masvs_lookup.py auth
```
