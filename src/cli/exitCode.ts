import { Finding, ScanOptions, ScanResult } from "../core/types";

export function isReachableFinding(finding: Finding): boolean {
  return finding.affected.some((affected) => affected.reachability?.reachable);
}

export function isDirectFinding(finding: Finding): boolean {
  return finding.affected.some((affected) => affected.paths.some((path) => path.length <= 2));
}

export function applyFailOnFilter(findings: Finding[], failOn: ScanOptions["failOn"]): Finding[] {
  if (failOn === "reachable") {
    return findings.filter((finding) => isReachableFinding(finding));
  }
  if (failOn === "direct") {
    return findings.filter((finding) => isDirectFinding(finding));
  }
  return findings;
}

export function determineExitCode(result: ScanResult, opts: ScanOptions): number {
  if (opts.exitCodeOn === "none") {
    return 0;
  }

  let findings = result.findings;
  if (opts.exitCodeOn === "reachable-findings") {
    findings = findings.filter((finding) => isReachableFinding(finding));
  }

  findings = applyFailOnFilter(findings, opts.failOn);
  return findings.length > 0 ? 1 : 0;
}
