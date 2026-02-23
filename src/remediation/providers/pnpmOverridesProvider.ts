import { RemediationPlan } from "../types";
import { asObject, ManifestOverrideProvider } from "./provider";

export class PnpmOverridesProvider implements ManifestOverrideProvider {
  manager: "pnpm" = "pnpm";

  getFieldPath(): string[] {
    return ["pnpm", "overrides"];
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
    return {
      ...asObject(existing),
      ...additions
    };
  }

  validate(plan: RemediationPlan, packageJson: unknown): { ok: true } | { ok: false; errors: string[] } {
    if (!packageJson || typeof packageJson !== "object" || Array.isArray(packageJson)) {
      return {
        ok: false,
        errors: ["package.json is not a JSON object."]
      };
    }

    const seen = new Map<string, string>();
    const errors: string[] = [];

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
          errors.push(`Conflicting pnpm override values for "${key}": "${existing}" vs "${change.to}".`);
          continue;
        }
        seen.set(key, change.to);
      }
    }

    return errors.length > 0 ? { ok: false, errors } : { ok: true };
  }
}
