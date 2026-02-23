import fs from "node:fs/promises";
import path from "node:path";
import { getManifestOverrideProvider } from "../providers";
import { RemediationOperation } from "../types";

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
