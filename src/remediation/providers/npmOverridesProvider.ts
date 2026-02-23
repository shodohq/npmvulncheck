import { RemediationPlan } from "../types";
import { asObject, ManifestOverrideProvider } from "./provider";

function splitScopedKey(key: string): { parentKey: string; child: string } | undefined {
  const idx = key.indexOf(">");
  if (idx <= 0 || idx >= key.length - 1) {
    return undefined;
  }
  return {
    parentKey: key.slice(0, idx),
    child: key.slice(idx + 1)
  };
}

function readDependencySpecs(packageJson: Record<string, unknown>): Map<string, string> {
  const out = new Map<string, string>();
  const fields = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];

  for (const field of fields) {
    const value = packageJson[field];
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      continue;
    }

    for (const [name, spec] of Object.entries(value as Record<string, unknown>)) {
      if (typeof spec === "string") {
        out.set(name, spec);
      }
    }
  }

  return out;
}

export class NpmOverridesProvider implements ManifestOverrideProvider {
  manager: "npm" = "npm";

  getFieldPath(): string[] {
    return ["overrides"];
  }

  buildOverrideKey(input: {
    pkg: string;
    scope?: {
      parent?: string;
      parentVersion?: string;
    };
  }): string {
    if (!input.scope?.parent) {
      return input.pkg;
    }

    const parentSpec = input.scope.parentVersion
      ? `${input.scope.parent}@${input.scope.parentVersion}`
      : input.scope.parent;
    return `${parentSpec}>${input.pkg}`;
  }

  mergeOverrides(existing: unknown, additions: Record<string, string>): Record<string, unknown> {
    const merged = asObject(existing);

    for (const [key, value] of Object.entries(additions)) {
      const scoped = splitScopedKey(key);
      if (!scoped) {
        merged[key] = value;
        continue;
      }

      const parentCurrent = merged[scoped.parentKey];
      if (!parentCurrent || typeof parentCurrent !== "object" || Array.isArray(parentCurrent)) {
        if (typeof parentCurrent === "string") {
          merged[scoped.parentKey] = {
            ".": parentCurrent,
            [scoped.child]: value
          };
          continue;
        }
        merged[scoped.parentKey] = {
          [scoped.child]: value
        };
        continue;
      }

      const next = { ...(parentCurrent as Record<string, unknown>) };
      next[scoped.child] = value;
      merged[scoped.parentKey] = next;
    }

    return merged;
  }

  validate(plan: RemediationPlan, packageJson: unknown): { ok: true } | { ok: false; errors: string[] } {
    if (!packageJson || typeof packageJson !== "object" || Array.isArray(packageJson)) {
      return {
        ok: false,
        errors: ["package.json is not a JSON object."]
      };
    }

    const errors: string[] = [];
    const directSpecs = readDependencySpecs(packageJson as Record<string, unknown>);
    const seen = new Map<string, string>();

    for (const operation of plan.operations) {
      if (operation.kind !== "manifest-override" || operation.manager !== this.manager) {
        continue;
      }

      for (const change of operation.changes) {
        const key =
          change.scope === "global"
            ? this.buildOverrideKey({ pkg: change.package })
            : this.buildOverrideKey({
                pkg: change.package,
                scope: {
                  parent: change.scope.parent,
                  parentVersion: change.scope.parentVersion
                }
              });

        const existing = seen.get(key);
        if (existing && existing !== change.to) {
          errors.push(`Conflicting npm override values for "${key}": "${existing}" vs "${change.to}".`);
          continue;
        }
        seen.set(key, change.to);

        if (change.scope !== "global") {
          continue;
        }

        const directSpec = directSpecs.get(change.package);
        if (!directSpec) {
          continue;
        }

        if (directSpec !== change.to) {
          errors.push(
            `Direct dependency "${change.package}" uses "${directSpec}" but override plans "${change.to}". ` +
              "npm may fail with EOVERRIDE. Use direct strategy or match the declared spec."
          );
        }
      }
    }

    return errors.length > 0 ? { ok: false, errors } : { ok: true };
  }
}
