import fs from "node:fs/promises";
import path from "node:path";
import { getManifestOverrideProvider } from "../providers";
import { RemediationOperation } from "../types";

const DIRECT_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"] as const;
type DirectField = (typeof DIRECT_FIELDS)[number];

function getNestedValue(target: Record<string, unknown>, pathSegments: string[]): unknown {
  let current: unknown = target;
  for (const segment of pathSegments) {
    if (!current || typeof current !== "object" || Array.isArray(current)) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function setNestedValue(target: Record<string, unknown>, pathSegments: string[], value: unknown): void {
  if (pathSegments.length === 0) {
    return;
  }

  let current: Record<string, unknown> = target;
  for (let i = 0; i < pathSegments.length - 1; i += 1) {
    const segment = pathSegments[i];
    const next = current[segment];
    if (!next || typeof next !== "object" || Array.isArray(next)) {
      current[segment] = {};
    }
    current = current[segment] as Record<string, unknown>;
  }

  current[pathSegments[pathSegments.length - 1]] = value;
}

export async function applyManifestOverrideOperation(
  operation: Extract<RemediationOperation, { kind: "manifest-override" }>,
  projectRoot: string
): Promise<void> {
  const packageJsonPath = path.join(projectRoot, operation.file);
  const raw = await fs.readFile(packageJsonPath, "utf8");
  const packageJson = JSON.parse(raw) as Record<string, unknown>;

  const provider = getManifestOverrideProvider(operation.manager);
  const additions: Record<string, string> = {};

  for (const change of operation.changes) {
    const key =
      change.scope === "global"
        ? provider.buildOverrideKey({
            pkg: change.package
          })
        : provider.buildOverrideKey({
            pkg: change.package,
            scope: {
              parent: change.scope.parent,
              parentVersion: change.scope.parentVersion
            }
          });
    additions[key] = change.to;
  }

  const fieldPath = provider.getFieldPath();
  const merged = provider.mergeOverrides(getNestedValue(packageJson, fieldPath), additions);
  setNestedValue(packageJson, fieldPath, merged);

  await fs.writeFile(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`, "utf8");
}

function getDependencyMap(target: Record<string, unknown>, field: DirectField): Record<string, unknown> | undefined {
  const value = target[field];
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

function resolveDirectUpgradeTarget(
  packageJson: Record<string, unknown>,
  operation: Extract<RemediationOperation, { kind: "manifest-direct-upgrade" }>
): { field: DirectField; deps: Record<string, unknown> } {
  const preferred = getDependencyMap(packageJson, operation.depField);
  if (preferred && typeof preferred[operation.package] === "string") {
    return {
      field: operation.depField,
      deps: preferred
    };
  }

  for (const field of DIRECT_FIELDS) {
    const deps = getDependencyMap(packageJson, field);
    if (deps && typeof deps[operation.package] === "string") {
      return { field, deps };
    }
  }

  throw new Error(
    `Cannot apply direct upgrade: dependency "${operation.package}" was not found in dependencies/devDependencies/optionalDependencies.`
  );
}

export async function applyManifestDirectUpgradeOperation(
  operation: Extract<RemediationOperation, { kind: "manifest-direct-upgrade" }>,
  projectRoot: string
): Promise<void> {
  const packageJsonPath = path.join(projectRoot, operation.file);
  const raw = await fs.readFile(packageJsonPath, "utf8");
  const packageJson = JSON.parse(raw) as Record<string, unknown>;

  const target = resolveDirectUpgradeTarget(packageJson, operation);
  target.deps[operation.package] = operation.toRange;
  packageJson[target.field] = target.deps;

  await fs.writeFile(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`, "utf8");
}
