import { ScanResult } from "../core/types";
import { findingHighestSeverityLevel } from "../policy/severity";

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

export function renderSarif(result: ScanResult): string {
  const rules = result.findings.map((finding) => ({
    id: finding.vulnId,
    shortDescription: {
      text: finding.summary
    },
    helpUri: finding.references[0]?.url
  }));

  const sarifResults = result.findings.flatMap((finding) =>
    finding.affected.map((affected) => ({
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
    }))
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
