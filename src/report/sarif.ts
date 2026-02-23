import { ScanResult } from "../core/types";
import { findingHighestSeverityLevel } from "../policy/severity";
import { RemediationPlan, RemediationScopeSelector } from "../remediation/types";

type SarifFix = {
  description: {
    text: string;
  };
  artifactChanges: Array<{
    artifactLocation: {
      uri: string;
    };
    replacements: Array<{
      deletedRegion: {
        startLine: number;
        startColumn: number;
        endColumn: number;
      };
      insertedContent: {
        text: string;
      };
    }>;
  }>;
};

export type RenderSarifOptions = {
  remediationPlan?: RemediationPlan;
};

function buildLookupKey(vulnId: string, packageName: string): string {
  return `${vulnId}::${packageName}`;
}

function scopeToText(scope: RemediationScopeSelector): string {
  if (scope === "global") {
    return "global";
  }
  return `${scope.parent}${scope.parentVersion ? `@${scope.parentVersion}` : ""}`;
}

function severityToSarifLevel(level?: "low" | "medium" | "high" | "critical"): "none" | "note" | "warning" | "error" {
  if (!level) {
    return "warning";
  }
  if (level === "critical" || level === "high") {
    return "error";
  }
  if (level === "medium") {
    return "warning";
  }
  return "note";
}

function buildNoopFix(description: string, file: string): SarifFix {
  return {
    description: {
      text: description
    },
    artifactChanges: [
      {
        artifactLocation: {
          uri: file
        },
        replacements: [
          {
            deletedRegion: {
              startLine: 1,
              startColumn: 1,
              endColumn: 1
            },
            insertedContent: {
              text: ""
            }
          }
        ]
      }
    ]
  };
}

function referencedVulnIds(why: string, knownVulnIds: string[]): string[] {
  const ids: string[] = [];
  for (const vulnId of knownVulnIds) {
    if (why.includes(vulnId)) {
      ids.push(vulnId);
    }
  }
  return ids;
}

function addFix(lookup: Map<string, SarifFix[]>, key: string, fix: SarifFix): void {
  const existing = lookup.get(key);
  if (!existing) {
    lookup.set(key, [fix]);
    return;
  }

  const duplicate = existing.some(
    (item) =>
      item.description.text === fix.description.text &&
      item.artifactChanges[0]?.artifactLocation.uri === fix.artifactChanges[0]?.artifactLocation.uri
  );
  if (!duplicate) {
    existing.push(fix);
  }
}

function buildFixLookup(result: ScanResult, remediationPlan?: RemediationPlan): Map<string, SarifFix[]> {
  const lookup = new Map<string, SarifFix[]>();
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

      const fix = buildNoopFix(
        `Upgrade direct dependency ${operation.package} from ${operation.fromRange} to ${operation.toRange} in ${operation.file}.`,
        operation.file
      );
      for (const vulnId of vulnIds) {
        addFix(lookup, buildLookupKey(vulnId, operation.package), fix);
      }
      continue;
    }

    if (operation.kind === "manifest-override") {
      for (const change of operation.changes) {
        const vulnIds = referencedVulnIds(change.why, knownVulnIds);
        if (vulnIds.length === 0) {
          continue;
        }

        const scope = scopeToText(change.scope);
        const fix = buildNoopFix(
          `Update ${change.package} override to ${change.to} (scope: ${scope}) in ${operation.file}.`,
          operation.file
        );
        for (const vulnId of vulnIds) {
          addFix(lookup, buildLookupKey(vulnId, change.package), fix);
        }
      }
    }
  }

  return lookup;
}

export function renderSarif(result: ScanResult, options: RenderSarifOptions = {}): string {
  const fixesByFindingAndPackage = buildFixLookup(result, options.remediationPlan);
  const rules = result.findings.map((finding) => ({
    id: finding.vulnId,
    shortDescription: {
      text: finding.summary
    },
    helpUri: finding.references[0]?.url
  }));

  const sarifResults = result.findings.flatMap((finding) =>
    finding.affected.map((affected) => {
      const key = buildLookupKey(finding.vulnId, affected.package.name);
      const fixes = fixesByFindingAndPackage.get(key);
      const baseResult = {
        ruleId: finding.vulnId,
        level: severityToSarifLevel(findingHighestSeverityLevel(finding)),
        message: {
          text: `${affected.package.name}@${affected.package.version}`
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: affected.reachability?.evidences[0]?.file ?? "package-lock.json"
              },
              region: {
                startLine: affected.reachability?.evidences[0]?.line ?? 1,
                startColumn: affected.reachability?.evidences[0]?.column ?? 1
              }
            }
          }
        ]
      };

      if (!fixes || fixes.length === 0) {
        return baseResult;
      }

      return {
        ...baseResult,
        fixes
      };
    })
  );

  const sarif = {
    version: "2.1.0",
    $schema: "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
    runs: [
      {
        tool: {
          driver: {
            name: result.meta.tool.name,
            version: result.meta.tool.version,
            rules
          }
        },
        results: sarifResults
      }
    ]
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}
