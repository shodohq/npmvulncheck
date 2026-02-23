# guided-remediation

This project is a sample for validating `npmvulncheck fix` (`Guided remediation`) behavior.

## Purpose

- Include a transitive vulnerable dependency (`minimist`) through `mkdirp@0.5.0`
- Show how `fix --strategy override` proposes `package.json` override changes
- Show apply flow with `--relock` and `--verify`

## Run Example

```bash
# Dry-run remediation plan
npmvulncheck fix --root examples/guided-remediation --strategy override --format text

# Apply package.json override + relock + verify
npmvulncheck fix --root examples/guided-remediation --strategy override --apply --relock --verify --no-introduce --format text
```

Expected behavior:

- Dry-run shows one `Manifest changes` entry for `minimist`
- Apply mode updates `package.json` overrides and regenerates `package-lock.json`
- Verify output ends with `status: ok`
