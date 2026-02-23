import { runScan } from "../../core/scan";
import { DependencyGraphProvider } from "../../deps/provider";
import { VulnerabilityProvider } from "../../osv/provider";
import { VerifyContext, VerifyOutcome } from "../types";

export async function runVerify(
  context: VerifyContext,
  depsProvider: DependencyGraphProvider,
  vulnProvider: VulnerabilityProvider
): Promise<VerifyOutcome> {
  const result = await runScan(context.scanOptions, depsProvider, vulnProvider, context.toolVersion);

  const currentVulnIds = new Set(result.findings.map((finding) => finding.vulnId));
  const baselineSet = new Set(context.baselineVulnIds);

  const remainingVulnerabilities = context.expectedFixedVulnIds
    .filter((id) => currentVulnIds.has(id))
    .sort();

  const fixedVulnerabilities = context.expectedFixedVulnIds
    .filter((id) => !currentVulnIds.has(id))
    .sort();

  const introducedVulnerabilities = Array.from(currentVulnIds)
    .filter((id) => !baselineSet.has(id))
    .sort();

  const ok =
    remainingVulnerabilities.length === 0 &&
    (!context.noIntroduce || introducedVulnerabilities.length === 0);

  return {
    ok,
    fixedVulnerabilities,
    remainingVulnerabilities,
    introducedVulnerabilities
  };
}
