import { ScanResult } from "../core/types";

function statusForAffected(reachable: boolean | undefined): "affected" | "not_affected" {
  if (reachable === false) {
    return "not_affected";
  }
  return "affected";
}

export function renderOpenVex(result: ScanResult): string {
  const statements = result.findings.flatMap((finding) =>
    finding.affected.map((affected) => ({
      vulnerability: {
        name: finding.vulnId
      },
      products: [
        {
          "@id": affected.package.purl ?? `pkg:npm/${encodeURIComponent(affected.package.name)}@${affected.package.version}`
        }
      ],
      status: statusForAffected(affected.reachability?.reachable),
      justification:
        affected.reachability?.reachable === false
          ? "vulnerable_code_not_in_execute_path"
          : undefined,
      action_statement: affected.fix?.fixedVersion
        ? `Upgrade ${affected.package.name} to >= ${affected.fix.fixedVersion}`
        : undefined,
      timestamp: result.meta.timestamp
    }))
  );

  const openvex = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": `urn:uuid:${crypto.randomUUID()}`,
    author: result.meta.tool.name,
    timestamp: result.meta.timestamp,
    version: 1,
    statements
  };

  return `${JSON.stringify(openvex, null, 2)}\n`;
}
