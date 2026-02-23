import { ScanResult } from "../core/types";
import { RemediationPlan, RemediationScopeSelector } from "../remediation/types";

export type RemediationReplacement = {
  deletedRegion: {
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
  };
  insertedContent: {
    text: string;
  };
};

export type RemediationAction = {
  description: string;
  file: string;
  replacements?: RemediationReplacement[];
};

export function remediationLookupKey(vulnId: string, packageName: string): string {
  return `${vulnId}::${packageName}`;
}

export function remediationActionKeyForDirectOperation(operationId: string): string {
  return `direct:${operationId}`;
}

export function remediationActionKeyForOverrideChange(operationId: string, changeIndex: number): string {
  return `override:${operationId}:${changeIndex}`;
}

function scopeToText(scope: RemediationScopeSelector): string {
  if (scope === "global") {
    return "global";
  }
  return `${scope.parent}${scope.parentVersion ? `@${scope.parentVersion}` : ""}`;
}

function referencedVulnIds(reason: string, knownVulnIds: string[]): string[] {
  const ids: string[] = [];
  for (const vulnId of knownVulnIds) {
    if (reason.includes(vulnId)) {
      ids.push(vulnId);
    }
  }
  return ids;
}

function addAction(lookup: Map<string, RemediationAction[]>, key: string, action: RemediationAction): void {
  const existing = lookup.get(key);
  if (!existing) {
    lookup.set(key, [action]);
    return;
  }

  const duplicate = existing.some((item) => item.description === action.description && item.file === action.file);
  if (!duplicate) {
    existing.push(action);
  }
}

export function buildRemediationActionLookup(
  result: ScanResult,
  remediationPlan?: RemediationPlan,
  options: {
    replacementByActionKey?: Map<string, RemediationReplacement[]>;
  } = {}
): Map<string, RemediationAction[]> {
  const lookup = new Map<string, RemediationAction[]>();
  if (!remediationPlan) {
    return lookup;
  }

  const knownVulnIds = result.findings.map((finding) => finding.vulnId);
  for (const operation of remediationPlan.operations) {
    if (operation.kind === "manifest-direct-upgrade") {
      const vulnIds = referencedVulnIds(operation.why, knownVulnIds);
      if (vulnIds.length === 0) {
        continue;
      }

      const action: RemediationAction = {
        description: `Upgrade direct dependency ${operation.package} from ${operation.fromRange} to ${operation.toRange} in ${operation.file}.`,
        file: operation.file,
        replacements: options.replacementByActionKey?.get(remediationActionKeyForDirectOperation(operation.id))
      };
      for (const vulnId of vulnIds) {
        addAction(lookup, remediationLookupKey(vulnId, operation.package), action);
      }
      continue;
    }

    if (operation.kind === "manifest-override") {
      for (const [changeIndex, change] of operation.changes.entries()) {
        const vulnIds = referencedVulnIds(change.why, knownVulnIds);
        if (vulnIds.length === 0) {
          continue;
        }

        const action: RemediationAction = {
          description: `Update ${change.package} override to ${change.to} (scope: ${scopeToText(change.scope)}) in ${operation.file}.`,
          file: operation.file,
          replacements: options.replacementByActionKey?.get(
            remediationActionKeyForOverrideChange(operation.id, changeIndex)
          )
        };
        for (const vulnId of vulnIds) {
          addAction(lookup, remediationLookupKey(vulnId, change.package), action);
        }
      }
    }
  }

  return lookup;
}

export function mergeRemediationFixNotes(result: ScanResult, remediationPlan?: RemediationPlan): ScanResult {
  const actionsByFindingAndPackage = buildRemediationActionLookup(result, remediationPlan);
  if (actionsByFindingAndPackage.size === 0) {
    return result;
  }

  let changed = false;
  const findings = result.findings.map((finding) => {
    let affectedChanged = false;
    const affected = finding.affected.map((entry) => {
      const actions = actionsByFindingAndPackage.get(remediationLookupKey(finding.vulnId, entry.package.name));
      if (!actions || actions.length === 0) {
        return entry;
      }

      const notes = [entry.fix?.note, ...actions.map((action) => action.description)];
      const mergedNote = Array.from(new Set(notes.filter((value): value is string => typeof value === "string" && value.length > 0)))
        .join(" ")
        .trim();
      if (entry.fix?.note === mergedNote) {
        return entry;
      }

      affectedChanged = true;
      return {
        ...entry,
        fix: {
          fixedVersion: entry.fix?.fixedVersion,
          note: mergedNote || undefined
        }
      };
    });

    if (!affectedChanged) {
      return finding;
    }

    changed = true;
    return {
      ...finding,
      affected
    };
  });

  if (!changed) {
    return result;
  }

  return {
    ...result,
    findings
  };
}
