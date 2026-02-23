# complex-unused-deps

This project is a sample for validating `npmvulncheck` reachability behavior (`source` mode).

## Purpose

- Mix dependencies that exist in the lockfile but are not reachable from the entrypoint (`src/index.ts`)
- Include `import` / `require` / `dynamic import` patterns in one project
- Include a non-literal `import(moduleName)` case to represent `unknown`-style scenarios

## Dependency Usage

- Dependencies reachable from `src/index.ts`
  - `lodash` (imported in `src/pipeline.ts`)
  - `qs` (required in `src/pipeline.ts`)
  - `axios` (dynamically imported in `src/runtime/loadFlags.ts`)
- Dependencies present but unused (not reachable from the entrypoint)
  - `minimist` (`src/tools/legacyCli.ts`)
  - `serialize-javascript` (`src/tools/templatePreview.ts`)
  - `mkdirp` (optional dependency, not referenced in source)

## Run Example

```bash
# lockfile-based scan (entire dependency set)
npmvulncheck --root examples/complex-unused-deps --mode lockfile --format text

# source mode (adds entrypoint reachability)
npmvulncheck --root examples/complex-unused-deps --mode source --entry src/index.ts --show traces --format text
```

In `source` mode, non-reachable dependencies appear as `reachability: unknown` (or non-reachable), reducing noise.

This fixture is focused on scan behavior. Running with `--strategy override` can return a no-op remediation plan
because vulnerable packages in this sample are direct dependencies, while `override` targets transitive ones.
Use `--strategy direct` (direct only) or `--strategy auto` (direct + transitive) to include direct upgrades.
