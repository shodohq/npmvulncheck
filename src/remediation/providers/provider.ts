import { DependencyManager } from "../../core/types";
import { RemediationPlan } from "../types";

export interface ManifestOverrideProvider {
  manager: DependencyManager;
  getFieldPath(): string[];
  buildOverrideKey(input: {
    pkg: string;
    scope?: {
      parent?: string;
      parentVersion?: string;
    };
  }): string;
  mergeOverrides(existing: unknown, additions: Record<string, string>): Record<string, unknown>;
  validate(plan: RemediationPlan, packageJson: unknown): { ok: true } | { ok: false; errors: string[] };
}

export function asObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return { ...(value as Record<string, unknown>) };
}
