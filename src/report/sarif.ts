import { ScanResult } from "../core/types";

function severityToSarifLevel(score?: string): "none" | "note" | "warning" | "error" {
  if (!score) {
    return "warning";
  }
  const normalized = score.toLowerCase();
  if (normalized.includes("critical") || normalized.includes("9") || normalized.includes("10")) {
    return "error";
  }
  if (normalized.includes("high") || normalized.includes("8") || normalized.includes("7")) {
    return "error";
  }
  if (normalized.includes("medium") || normalized.includes("6") || normalized.includes("5") || normalized.includes("4")) {
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
      level: severityToSarifLevel(finding.severity?.[0]?.score),
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
