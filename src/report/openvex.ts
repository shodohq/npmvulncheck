import { randomUUID } from "node:crypto";
import { ScanResult } from "../core/types";
import { RemediationPlan } from "../remediation/types";
import { buildRemediationActionLookup, remediationLookupKey } from "./remediation";

function statusForAffected(
  reachability: { reachable: boolean; level: "import" | "transitive" | "unknown" } | undefined
): "affected" | "not_affected" | "under_investigation" {
  if (!reachability) {
    return "affected";
  }
  if (reachability.level === "unknown") {
    return "under_investigation";
  }
  if (reachability.reachable === false) {
    return "not_affected";
  }
  return "affected";
}

export type RenderOpenVexOptions = {
  remediationPlan?: RemediationPlan;
};

export function renderOpenVex(result: ScanResult, options: RenderOpenVexOptions = {}): string {
  const actionsByFindingAndPackage = buildRemediationActionLookup(result, options.remediationPlan);
  const statements = result.findings.flatMap((finding) =>
    finding.affected.map((affected) => {
      const actions = actionsByFindingAndPackage.get(remediationLookupKey(finding.vulnId, affected.package.name));
      const actionStatement =
        actions && actions.length > 0
          ? actions.map((action) => action.description).join(" ")
          : affected.fix?.fixedVersion
            ? `Upgrade ${affected.package.name} to >= ${affected.fix.fixedVersion}`
            : undefined;

      return {
        vulnerability: {
          name: finding.vulnId
        },
        products: [
          {
            "@id": affected.package.purl ?? `pkg:npm/${encodeURIComponent(affected.package.name)}@${affected.package.version}`
          }
        ],
        status: statusForAffected(affected.reachability),
        justification:
          affected.reachability?.reachable === false && affected.reachability.level !== "unknown"
            ? "vulnerable_code_not_in_execute_path"
            : undefined,
        action_statement: actionStatement,
        timestamp: result.meta.timestamp
      };
    })
  );

  const openvex = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": `urn:uuid:${randomUUID()}`,
    author: result.meta.tool.name,
    timestamp: result.meta.timestamp,
    version: 1,
    statements
  };

  return `${JSON.stringify(openvex, null, 2)}\n`;
}
