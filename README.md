# npmvulncheck

`npmvulncheck` is a govulncheck-inspired CLI for npm projects.

## Implemented MVP

- Dependency inventory from npm lockfile (`package-lock.json` / `npm-shrinkwrap.json`) via Arborist virtual tree
- Installed tree mode via Arborist actual tree
- Source reachability mode (JS/TS import/require/dynamic import parsing)
- OSV query (`/v1/querybatch`) + detail fetch (`/v1/vulns/{id}`)
- Vulnerability detail cache keyed by `vulnId + modified`
- Output formats: `text`, `json`, `sarif`, `openvex`
- `explain <VULN_ID>` command (cache-aware)
- Exit-code policy compatible with govulncheck defaults, plus CI overrides

## Usage

```bash
# lockfile scan
npmvulncheck --mode lockfile --format text

# installed tree scan
npmvulncheck --mode installed --format json

# source reachability scan
npmvulncheck --mode source --entry src/index.ts --show traces --format text

# machine-readable output (always exit 0 by default)
npmvulncheck --mode source --format json > findings.json

# override exit behavior for CI
npmvulncheck --format json --exit-code-on findings --fail-on reachable

# vulnerability detail
npmvulncheck explain GHSA-xxxx-xxxx-xxxx
```

## Complex Example

`examples/complex-unused-deps` is a sample project that intentionally mixes:

- dependencies reachable from the entrypoint (`lodash`, `qs`, `axios`)
- dependencies present in the lockfile but not reachable from the entrypoint (`minimist`, `serialize-javascript`)
- non-literal dynamic import (`import(moduleName)`)

```bash
# dependency inventory based scan
npmvulncheck --root examples/complex-unused-deps --mode lockfile --format text

# source reachability scan
npmvulncheck --root examples/complex-unused-deps --mode source --entry src/index.ts --show traces --format text
```

In `source` mode, you can confirm that noise from non-reachable dependencies is reduced.

## Main options

- `--mode lockfile|installed|source`
- `--format text|json|sarif|openvex`
- `--entry <file>` (repeatable)
- `--show traces|verbose`
- `--include dev` / `--omit dev` (default omit dev)
- `--exit-code-on none|findings|reachable-findings`
- `--severity-threshold low|medium|high|critical`
- `--fail-on all|reachable|direct`
- `--ignore-file <path>`
- `--cache-dir <dir>`
- `--offline` (requires previously cached query/detail data; run one online scan first)

## Ignore policy format

`.npmvulncheck-ignore.json`

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

## Development

```bash
npm install
npm run lint
npm test
npm run build
```
