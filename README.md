# npmvulncheck

[![CI](https://github.com/shodohq/npmvulncheck/actions/workflows/ci.yml/badge.svg)](https://github.com/shodohq/npmvulncheck/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/shodohq/npmvulncheck/badge)](https://scorecard.dev/viewer/?uri=github.com/shodohq/npmvulncheck)
[![npm version](https://img.shields.io/npm/v/npmvulncheck)](https://www.npmjs.com/package/npmvulncheck)
[![License](https://img.shields.io/npm/l/npmvulncheck)](LICENSE)

`npmvulncheck` is a `govulncheck`-inspired vulnerability scanner for npm projects.
It combines lockfile/installed dependency analysis with optional source reachability to help reduce noisy findings.

## Community quick links

- [Contributing guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security policy](SECURITY.md)
- [Release notes](https://github.com/shodohq/npmvulncheck/releases)
- [Issue tracker](https://github.com/shodohq/npmvulncheck/issues)
- [OSS launch playbook](docs/launch-playbook.md)

## Why this tool

- Uses OSV as the vulnerability source (`/v1/querybatch`, `/v1/vulns/{id}`)
- Supports three scan modes: `lockfile`, `installed`, `source`
- Supports `package-lock.json` / `npm-shrinkwrap.json` / `pnpm-lock.yaml` / `yarn.lock` in lockfile-based modes
- Understands JS/TS `import`, `require`, and literal dynamic `import(...)`
- Resolves imports from each containing workspace/package context (not only root)
- Supports `text`, `json`, `sarif`, and `openvex` outputs
- CI-friendly exit code control (`--exit-code-on`, `--fail-on`, `--severity-threshold`)
- Includes local cache support and offline scanning

## Requirements

- Node.js `>=18`
- Node.js project with one of:
  - `package-lock.json` / `npm-shrinkwrap.json`
  - `pnpm-lock.yaml`
  - `yarn.lock`
- `node_modules` installed for `installed` mode (npm tree only)

## Installation

### From npm

```bash
npm install -g npmvulncheck
```

Or run without global install:

```bash
npx npmvulncheck --help
```

### From source

```bash
npm install
npm run build
npm link
```

## Quick start

```bash
# Default scan (lockfile + text)
npmvulncheck

# Installed tree scan
npmvulncheck --mode installed --format text

# Source reachability scan
npmvulncheck --mode source --entry src/index.ts --show traces

# Machine-readable output
npmvulncheck --mode source --format json > findings.json
```

## Scan modes

| Mode        | Input graph                  | When to use                     | Notes |
|-------------|------------------------------|----------------------------------|-------|
| `lockfile`  | lockfile dependency graph      | Fast, deterministic CI scans      | Supports npm/pnpm/yarn lockfiles |
| `installed` | actual `node_modules` tree     | Match what is actually installed  | npm installed tree only |
| `source`    | lockfile + source imports      | Prioritize reachable dependencies | Falls back to full inventory when imports are unresolved |

### Entry points in `source` mode

You can pass explicit entry files with repeatable `--entry`.
If no valid entries are provided, entries are auto-discovered from:

- `package.json` fields (`main`, `bin`, `exports`)
- Common conventions (`src/index.ts`, `src/index.js`, `index.ts`, `index.js`, etc.)

## Commands

```bash
# Scan
npmvulncheck [options]

# Show vulnerability detail
npmvulncheck explain GHSA-xxxx-xxxx-xxxx

# Show tool/db cache metadata
npmvulncheck version
```

## Main options

- `--mode lockfile|installed|source`
- `--format text|json|sarif|openvex`
- `--root <dir>`
- `--entry <file>` (repeatable)
- `--conditions <condition>` (repeatable; source-mode module conditions override)
- `--include-type-imports` (include `import type` / `export type` in source reachability)
- `--explain-resolve` (include unresolved import diagnostics and resolution candidates)
- `--show traces|verbose`
- `--include dev` / `--omit dev` (default: omit dev)
- `--include-dev` / `--omit-dev`
- `--cache-dir <dir>`
- `--offline`
- `--ignore-file <path>`
- `--exit-code-on none|findings|reachable-findings`
- `--fail-on all|reachable|direct`
- `--severity-threshold low|medium|high|critical`

## Exit codes and CI behavior

Default behavior depends on output format:

- `text`: default `--exit-code-on findings` (exit `1` when filtered findings exist)
- `json`/`sarif`/`openvex`: default `--exit-code-on none` (exit `0` unless runtime error)

Examples:

```bash
# Fail CI only for reachable vulnerabilities with severity >= high
npmvulncheck \
  --mode source \
  --format json \
  --exit-code-on reachable-findings \
  --fail-on reachable \
  --severity-threshold high
```

## Ignore policy

Default file: `.npmvulncheck-ignore.json` at project root.

```json
{
  "ignore": [
    {
      "id": "GHSA-xxxx-xxxx-xxxx",
      "until": "2026-06-30",
      "reason": "Waiting for upstream patch"
    }
  ]
}
```

Notes:

- Rules are matched by vulnerability `id`
- Expired rules are ignored
- Invalid `until` values are ignored

## Cache and offline mode

`npmvulncheck` caches vulnerability details and can run offline.

```bash
# Warm cache (online)
npmvulncheck --mode lockfile

# Reuse cache only
npmvulncheck --mode lockfile --offline
```

Use `--cache-dir <dir>` to override the cache location.

## Example project

`examples/complex-unused-deps` demonstrates how `source` mode can reduce findings from dependencies that exist in the lockfile but are not reachable from your entrypoint.

```bash
npmvulncheck --root examples/complex-unused-deps --mode lockfile --format text
npmvulncheck --root examples/complex-unused-deps --mode source --entry src/index.ts --show traces --format text
```

## Development

```bash
npm install
npm run lint
npm test
npm run build
```

## CI/CD

GitHub Actions workflows are configured in `.github/workflows`.

- `ci.yml`: runs on every `push` and `pull_request` with Node.js `18`, `20`, and `22`
  - Steps: `npm ci` -> `npm run lint` -> `npm test` -> `npm run build`
- `scorecards.yml`: runs OpenSSF Scorecard on `main` push and weekly schedule, then uploads SARIF to code scanning
- `cd.yml`: runs on `v*` tag push and publishes to npm after lint/test/build pass
  - Includes a guard that checks `vX.Y.Z` tag matches `package.json` version
  - Uses `npm publish --provenance --access public`

### Required repository secret

Set this secret in GitHub repository settings:

- `NPM_TOKEN`: npm automation token with publish permission

### Release flow

```bash
# 1) bump version
npm version patch

# 2) push commit and tag
git push origin main --follow-tags
```

When the `v*` tag is pushed, the CD workflow publishes the package automatically.
After publish, create a GitHub Release with generated notes:

```bash
gh release create vX.Y.Z --generate-notes
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, PR checklist, and review expectations.

## License

`AGPL-3.0-only` (see `LICENSE`)
