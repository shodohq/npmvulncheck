import { ScanResult } from "../core/types";
import { RemediationPlan } from "../remediation/types";
import { mergeRemediationFixNotes } from "./remediation";

export type RenderJsonOptions = {
  remediationPlan?: RemediationPlan;
};

export function renderJson(result: ScanResult, options: RenderJsonOptions = {}): string {
  const resultWithRemediationNotes = mergeRemediationFixNotes(result, options.remediationPlan);
  const payload = options.remediationPlan
    ? {
        ...resultWithRemediationNotes,
        remediation: options.remediationPlan
      }
    : resultWithRemediationNotes;

  return `${JSON.stringify(payload, null, 2)}\n`;
}
