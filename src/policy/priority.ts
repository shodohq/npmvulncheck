import { Finding, FindingPriority, FindingPriorityLevel, ScanMode } from "../core/types";
import { findingHighestSeverityLevel, severityRank } from "./severity";

type ReachabilityState = "reachable" | "unknown-reachability" | "unreachable" | "none";

function severityToPriorityLevel(level?: ReturnType<typeof findingHighestSeverityLevel>): FindingPriorityLevel {
  if (level === "critical" || level === "high") {
    return "high";
  }
  if (level === "medium") {
    return "medium";
  }
  return "low";
}

function findingReachabilityState(finding: Finding): ReachabilityState {
  let sawReachability = false;
  let sawUnknown = false;
  let sawUnreachable = false;

  for (const affected of finding.affected) {
    if (!affected.reachability) {
      continue;
    }

    sawReachability = true;

    if (affected.reachability.reachable) {
      return "reachable";
    }

    if (affected.reachability.level === "unknown") {
      sawUnknown = true;
    } else {
      sawUnreachable = true;
    }
  }

  if (!sawReachability) {
    return "none";
  }
  if (sawUnknown) {
    return "unknown-reachability";
  }
  if (sawUnreachable) {
    return "unreachable";
  }
  return "none";
}

export function evaluateFindingPriority(finding: Finding, mode: ScanMode): FindingPriority {
  const severityLevel = findingHighestSeverityLevel(finding);
  const severityScore = severityLevel ? severityRank(severityLevel) : 0;

  if (mode !== "source") {
    return {
      level: severityToPriorityLevel(severityLevel),
      reason: "severity",
      score: 20 + severityScore
    };
  }

  const reachabilityState = findingReachabilityState(finding);

  if (reachabilityState === "reachable") {
    return {
      level: "high",
      reason: "reachable",
      score: 30 + severityScore
    };
  }

  if (reachabilityState === "unknown-reachability") {
    return {
      level: "medium",
      reason: "unknown-reachability",
      score: 20 + severityScore
    };
  }

  if (reachabilityState === "unreachable") {
    return {
      level: "low",
      reason: "unreachable",
      score: 10 + severityScore
    };
  }

  return {
    level: severityToPriorityLevel(severityLevel),
    reason: "severity",
    score: 20 + severityScore
  };
}

export function compareFindingsByPriority(a: Finding, b: Finding): number {
  const scoreDiff = (b.priority?.score ?? 0) - (a.priority?.score ?? 0);
  if (scoreDiff !== 0) {
    return scoreDiff;
  }
  return a.vulnId.localeCompare(b.vulnId);
}
