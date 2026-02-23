import { RemediationPlan } from "./types";

export function renderRemediationText(plan: RemediationPlan): string {
  const lines: string[] = [];
  lines.push(`Strategy: ${plan.strategy}`);
  lines.push(`Package manager: ${plan.packageManager}`);
  lines.push(`Proposed fixes: ${plan.fixes.fixedVulnerabilities.length}`);
  lines.push(`Remaining: ${plan.fixes.remainingVulnerabilities.length}`);

  const directOps = plan.operations.filter((op) => op.kind === "manifest-direct-upgrade");
  if (directOps.length > 0) {
    lines.push("");
    lines.push("Direct dependency changes:");
    for (const operation of directOps) {
      lines.push(`  - ${operation.package}: ${operation.fromRange} -> ${operation.toRange} [field=${operation.depField}]`);
      lines.push(`    reason: ${operation.why}`);
    }
  }

  const manifestOp = plan.operations.find((op) => op.kind === "manifest-override");
  if (manifestOp && manifestOp.kind === "manifest-override") {
    lines.push("");
    lines.push("Manifest changes:");
    for (const change of manifestOp.changes) {
      const scopeText =
        change.scope === "global"
          ? "global"
          : `${change.scope.parent}${change.scope.parentVersion ? `@${change.scope.parentVersion}` : ""}`;
      lines.push(`  - ${change.package}: ${change.to} [scope=${scopeText}]`);
      lines.push(`    reason: ${change.why}`);
    }
  } else if (directOps.length === 0) {
    lines.push("");
    lines.push("No manifest override changes were generated.");

    const directUpgradeRequired = plan.summary.reasonedTopChoices.some(
      (item) => item.opId === "op-direct-upgrade-required"
    );
    if (directUpgradeRequired) {
      lines.push(
        "Hint: override strategy currently remediates transitive dependencies only. Upgrade vulnerable direct dependencies in package.json."
      );
    }
  }

  if (plan.summary.reasonedTopChoices.length > 0) {
    lines.push("");
    lines.push("Summary:");
    for (const item of plan.summary.reasonedTopChoices) {
      lines.push(`  - ${item.opId} (${item.risk}): ${item.rationale}`);
    }
  }

  return `${lines.join("\n")}\n`;
}

export function renderVerifyOutcomeText(outcome: {
  ok: boolean;
  fixedVulnerabilities: string[];
  remainingVulnerabilities: string[];
  introducedVulnerabilities: string[];
}): string {
  const lines: string[] = [];
  lines.push("Verify result:");
  lines.push(`  status: ${outcome.ok ? "ok" : "failed"}`);
  lines.push(
    `  fixed: ${outcome.fixedVulnerabilities.length > 0 ? outcome.fixedVulnerabilities.join(", ") : "(none)"}`
  );
  lines.push(
    `  remaining: ${
      outcome.remainingVulnerabilities.length > 0 ? outcome.remainingVulnerabilities.join(", ") : "(none)"
    }`
  );
  lines.push(
    `  introduced: ${
      outcome.introducedVulnerabilities.length > 0 ? outcome.introducedVulnerabilities.join(", ") : "(none)"
    }`
  );
  return `${lines.join("\n")}\n`;
}
