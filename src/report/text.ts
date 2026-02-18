import { Finding, ScanResult } from "../core/types";

function summarizeSeverity(finding: Finding): string {
  if (!finding.severity || finding.severity.length === 0) {
    return "UNKNOWN";
  }

  const top = finding.severity[0];
  return `${top.type}:${top.score}`;
}

function formatTrace(trace: string[]): string {
  return trace.join(" -> ");
}

export function renderText(result: ScanResult, showTraces: boolean, showVerbose: boolean): string {
  const lines: string[] = [];

  lines.push(`Mode: ${result.meta.mode}`);
  lines.push(`Findings: ${result.findings.length}`);

  if (showVerbose) {
    lines.push(
      `Stats: nodes=${result.stats.nodes}, edges=${result.stats.edges}, queried=${result.stats.queriedPackages}, vulns=${result.stats.vulnerabilities}`
    );
  }

  lines.push("");

  if (result.findings.length === 0) {
    lines.push("No vulnerabilities found.");
    return `${lines.join("\n")}\n`;
  }

  for (const finding of result.findings) {
    lines.push(`${finding.vulnId}  ${summarizeSeverity(finding)}  ${finding.summary || "(no summary)"}`);

    for (const affected of finding.affected) {
      lines.push(`  package: ${affected.package.name}@${affected.package.version} (${affected.package.location || affected.package.id})`);

      if (affected.reachability) {
        lines.push(
          `  reachability: ${affected.reachability.reachable ? "reachable" : "unknown"} (${affected.reachability.level})`
        );
      }

      if (showTraces && affected.reachability?.traces && affected.reachability.traces.length > 0) {
        lines.push("  trace:");
        for (const trace of affected.reachability.traces) {
          lines.push(`    ${formatTrace(trace)}`);
        }
      }

      if (affected.fix?.fixedVersion) {
        lines.push(`  fix: upgrade to >= ${affected.fix.fixedVersion}`);
      }
    }

    if (finding.references.length > 0) {
      const firstRef = finding.references[0];
      lines.push(`  refs: ${firstRef.url}`);
    }

    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}
