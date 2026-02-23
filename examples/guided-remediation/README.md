# guided-remediation

This project is a sample for validating integrated remediation planning behavior in `npmvulncheck`.

## Purpose

- Include a transitive vulnerable dependency (`minimist`) through `mkdirp@0.5.0`
- Show how `--strategy override` proposes transitive `package.json` override changes
- Show how `--strategy auto` can combine direct upgrades and transitive overrides

## Run Example

```bash
# Remediation plan (transitive only)
npmvulncheck --root examples/guided-remediation --strategy override --format text

# Remediation plan (direct + transitive)
npmvulncheck --root examples/guided-remediation --strategy auto --format text
```

Expected behavior:

- Dry-run shows one `Manifest changes` entry for `minimist`
- In this fixture, `auto` yields the same plan as `override` because there are no vulnerable direct dependencies
