import { ScanResult } from "../core/types";
import { findingHighestSeverityLevel } from "../policy/severity";
import { RemediationPlan } from "../remediation/types";
import { buildRemediationActionLookup, remediationLookupKey } from "./remediation";

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

export function renderSarif(result: ScanResult, options: RenderSarifOptions = {}): string {
  const actionsByFindingAndPackage = buildRemediationActionLookup(result, options.remediationPlan);
  const rules = result.findings.map((finding) => ({
    id: finding.vulnId,
    shortDescription: {
      text: finding.summary
    },
    helpUri: finding.references[0]?.url
  }));

  const sarifResults = result.findings.flatMap((finding) =>
    finding.affected.map((affected) => {
      const key = remediationLookupKey(finding.vulnId, affected.package.name);
      const actions = actionsByFindingAndPackage.get(key);
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

      if (!actions || actions.length === 0) {
        return baseResult;
      }

      return {
        ...baseResult,
        fixes: actions.map((action) => buildNoopFix(action.description, action.file))
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
