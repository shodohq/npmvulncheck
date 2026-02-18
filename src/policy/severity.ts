import { Finding, OsvSeverity } from "../core/types";

export type SeverityLevel = "low" | "medium" | "high" | "critical";

const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3
};

function parseSeverityLabel(text: string): SeverityLevel | undefined {
  const lower = text.toLowerCase();
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

function parseNumericCvssScore(score: string): number | undefined {
  const trimmed = score.trim();
  if (!/^(10(?:\.0+)?|[0-9](?:\.[0-9]+)?)$/.test(trimmed)) {
    return undefined;
  }
  const value = Number(trimmed);
  if (Number.isNaN(value) || value < 0 || value > 10) {
    return undefined;
  }
  return value;
}

function roundUpOneDecimal(value: number): number {
  return Math.ceil((value * 10) - 1e-10) / 10;
}

function parseCvssV3VectorScore(score: string): number | undefined {
  const trimmed = score.trim().toUpperCase();
  if (!trimmed.startsWith("CVSS:3.0/") && !trimmed.startsWith("CVSS:3.1/")) {
    return undefined;
  }

  const metrics = new Map<string, string>();
  for (const part of trimmed.split("/").slice(1)) {
    const [key, value] = part.split(":");
    if (!key || !value) {
      continue;
    }
    metrics.set(key, value);
  }

  const scope = metrics.get("S");
  const av = metrics.get("AV");
  const ac = metrics.get("AC");
  const pr = metrics.get("PR");
  const ui = metrics.get("UI");
  const c = metrics.get("C");
  const i = metrics.get("I");
  const a = metrics.get("A");

  if (!scope || !av || !ac || !pr || !ui || !c || !i || !a) {
    return undefined;
  }

  const avWeight = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[av];
  const acWeight = { L: 0.77, H: 0.44 }[ac];
  const uiWeight = { N: 0.85, R: 0.62 }[ui];
  const ciaWeight = { N: 0, L: 0.22, H: 0.56 };
  const cWeight = ciaWeight[c as keyof typeof ciaWeight];
  const iWeight = ciaWeight[i as keyof typeof ciaWeight];
  const aWeight = ciaWeight[a as keyof typeof ciaWeight];

  if (
    avWeight === undefined ||
    acWeight === undefined ||
    uiWeight === undefined ||
    cWeight === undefined ||
    iWeight === undefined ||
    aWeight === undefined
  ) {
    return undefined;
  }

  const prWeights =
    scope === "C"
      ? { N: 0.85, L: 0.68, H: 0.5 }
      : scope === "U"
        ? { N: 0.85, L: 0.62, H: 0.27 }
        : undefined;
  if (!prWeights) {
    return undefined;
  }
  const prWeight = prWeights[pr as keyof typeof prWeights];
  if (prWeight === undefined) {
    return undefined;
  }

  const impact = 1 - (1 - cWeight) * (1 - iWeight) * (1 - aWeight);
  if (impact <= 0) {
    return 0;
  }

  const impactSubScore =
    scope === "U"
      ? 6.42 * impact
      : 7.52 * (impact - 0.029) - 3.25 * Math.pow(impact - 0.02, 15);
  const exploitability = 8.22 * avWeight * acWeight * prWeight * uiWeight;
  const baseScore =
    scope === "U"
      ? Math.min(impactSubScore + exploitability, 10)
      : Math.min(1.08 * (impactSubScore + exploitability), 10);

  return roundUpOneDecimal(baseScore);
}

function parseCvssScore(score: string): number | undefined {
  return parseNumericCvssScore(score) ?? parseCvssV3VectorScore(score);
}

function scoreToSeverityLevel(score: number): SeverityLevel | undefined {
  if (score >= 9) {
    return "critical";
  }
  if (score >= 7) {
    return "high";
  }
  if (score >= 4) {
    return "medium";
  }
  if (score > 0) {
    return "low";
  }
  return undefined;
}

function severityEntryToLevel(severity: OsvSeverity): SeverityLevel | undefined {
  const fromLabel = parseSeverityLabel(`${severity.type} ${severity.score}`);
  if (fromLabel) {
    return fromLabel;
  }

  const numeric = parseCvssScore(severity.score);
  if (numeric === undefined) {
    return undefined;
  }
  return scoreToSeverityLevel(numeric);
}

export function severityRank(level: SeverityLevel): number {
  return SEVERITY_ORDER[level];
}

export function findingHighestSeverityLevel(finding: Finding): SeverityLevel | undefined {
  let best: SeverityLevel | undefined;

  for (const severity of finding.severity ?? []) {
    const level = severityEntryToLevel(severity);
    if (!level) {
      continue;
    }

    if (!best || severityRank(level) > severityRank(best)) {
      best = level;
    }
  }

  return best;
}
