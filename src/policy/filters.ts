import { Finding, PackageNode } from "../core/types";
import { findingHighestSeverityLevel, severityRank } from "./severity";

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

  const observed = findingHighestSeverityLevel(finding);
  if (!observed) {
    return true;
  }

  return severityRank(observed) >= severityRank(threshold);
}

export function isReachableFinding(finding: Finding): boolean {
  return finding.affected.some((affected) => affected.reachability?.reachable);
}

export function isDirectFinding(finding: Finding, rootDirectNodeIds: Set<string>): boolean {
  return finding.affected.some((affected) => rootDirectNodeIds.has(affected.package.id));
}
