import { Finding, PackageNode } from "../core/types";

const SEVERITY_ORDER = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3
} as const;

type SeverityLabel = keyof typeof SEVERITY_ORDER;

function normalizeSeverity(label: string): SeverityLabel | undefined {
  const lower = label.toLowerCase();
  if (lower.includes("critical")) {
    return "critical";
  }
  if (lower.includes("high")) {
    return "high";
  }
  if (lower.includes("medium")) {
    return "medium";
  }
  if (lower.includes("low")) {
    return "low";
  }
  return undefined;
}

export function includeNodeByDependencyType(node: PackageNode, includeDev: boolean): boolean {
  if (includeDev) {
    return true;
  }
  return !node.flags.dev;
}

export function passesSeverityThreshold(
  finding: Finding,
  threshold?: "low" | "medium" | "high" | "critical"
): boolean {
  if (!threshold) {
    return true;
  }

  const thresholdScore = SEVERITY_ORDER[threshold];
  const observed = finding.severity
    ?.map((severity) => normalizeSeverity(`${severity.type} ${severity.score}`))
    .filter((value): value is SeverityLabel => Boolean(value));

  if (!observed || observed.length === 0) {
    return true;
  }

  return observed.some((severity) => SEVERITY_ORDER[severity] >= thresholdScore);
}

export function isReachableFinding(finding: Finding): boolean {
  return finding.affected.some((affected) => affected.reachability?.reachable);
}

export function isDirectFinding(finding: Finding, rootDirectNodeIds: Set<string>): boolean {
  return finding.affected.some((affected) => rootDirectNodeIds.has(affected.package.id));
}
