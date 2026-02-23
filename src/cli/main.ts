#!/usr/bin/env node
import { Command } from "commander";
import packageJson from "../../package.json";
import { resolveScanOptions, collect } from "./args";
import { runScan } from "../core/scan";
import { ProviderRegistry } from "../deps/registry";
import { OsvCache } from "../osv/cache";
import { OsvClient } from "../osv/client";
import { OsvProvider } from "../osv/provider";
import { renderJson } from "../report/json";
import { renderOpenVex } from "../report/openvex";
import { renderSarif } from "../report/sarif";
import { renderText } from "../report/text";
import { ScanOptions, ScanResult } from "../core/types";
import { determineExitCode } from "./exitCode";
import { applyRemediationPlan, buildRemediationPlan } from "../remediation";
import { renderRemediationText, renderVerifyOutcomeText } from "../remediation/render";
import {
  RemediationFormat,
  RemediationScope,
  RemediationStrategy,
  UpgradeLevel
} from "../remediation/types";

function renderResult(result: ScanResult, opts: ScanOptions): string {
  switch (opts.format) {
    case "json":
      return renderJson(result);
    case "sarif":
      return renderSarif(result);
    case "openvex":
      return renderOpenVex(result);
    case "text":
    default:
      return renderText(result, opts.showTraces, opts.showVerbose);
  }
}

function renderExplainText(vuln: {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  references?: Array<{ url?: string }>;
}): string {
  const lines: string[] = [];
  lines.push(`${vuln.id} ${vuln.summary ?? ""}`.trim());
  if (vuln.aliases && vuln.aliases.length > 0) {
    lines.push(`aliases: ${vuln.aliases.join(", ")}`);
  }
  if (vuln.modified) {
    lines.push(`modified: ${vuln.modified}`);
  }
  if (vuln.details) {
    lines.push("");
    lines.push(vuln.details);
  }
  if (vuln.references && vuln.references.length > 0) {
    lines.push("");
    lines.push("references:");
    for (const ref of vuln.references) {
      if (ref.url) {
        lines.push(`  - ${ref.url}`);
      }
    }
  }
  return `${lines.join("\n")}\n`;
}

function parseFixStrategy(value: string | undefined): RemediationStrategy {
  if (value === "override" || value === "direct" || value === "in-place" || value === "auto") {
    return value;
  }
  return "auto";
}

function parseFixScope(value: string | undefined): RemediationScope {
  if (value === "global" || value === "by-parent") {
    return value;
  }
  return "global";
}

function parseFixUpgradeLevel(value: string | undefined): UpgradeLevel {
  if (value === "patch" || value === "minor" || value === "major" || value === "any") {
    return value;
  }
  return "any";
}

function parseFixFormat(value: string | undefined): RemediationFormat {
  if (value === "json") {
    return "json";
  }
  if (value === "sarif") {
    return "sarif";
  }
  return "text";
}

type FixCommandOptions = {
  strategy?: string;
  scope?: string;
  upgradeLevel?: string;
  format?: string;
  apply?: boolean;
  relock?: boolean;
  verify?: boolean;
  noIntroduce?: boolean;
  rollbackOnFail?: boolean;
  onlyReachable?: boolean;
  includeUnreachable?: boolean;
  mode?: string;
  root?: string;
  entry?: string[];
  conditions?: string[];
  includeTypeImports?: boolean;
  includeDev?: boolean;
  omitDev?: boolean;
  include?: string[];
  omit?: string[];
  cacheDir?: string;
  offline?: boolean;
  ignoreFile?: string;
  severityThreshold?: "low" | "medium" | "high" | "critical";
};

async function detectOrThrow(registry: ProviderRegistry, opts: ScanOptions): Promise<{
  manager: "npm" | "pnpm" | "yarn";
  lockfilePath: string;
}> {
  const detectMode = opts.mode === "installed" ? "installed" : "lockfile";
  const detected = await registry.detectContext(opts.root, detectMode);

  if (!detected) {
    if (opts.mode === "installed") {
      throw new Error(
        `No installed dependency tree found in ${opts.root}. Installed mode currently requires node_modules/.`
      );
    }
    throw new Error(
      `No supported lockfile found in ${opts.root}. Expected one of: pnpm-lock.yaml, yarn.lock, package-lock.json, npm-shrinkwrap.json.`
    );
  }

  const warnings = detected.details?.warnings;
  if (Array.isArray(warnings)) {
    for (const warning of warnings) {
      if (typeof warning === "string" && warning.length > 0) {
        process.stderr.write(`Warning: ${warning}\n`);
      }
    }
  }

  return {
    manager: detected.manager,
    lockfilePath: detected.lockfilePath
  };
}

async function runDefaultScan(raw: Record<string, unknown>): Promise<void> {
  const opts = resolveScanOptions(raw as never, process.cwd());
  const depsProvider = new ProviderRegistry();
  await detectOrThrow(depsProvider, opts);

  const osvProvider = new OsvProvider(new OsvClient(), new OsvCache(opts.cacheDir), opts.offline);
  const result = await runScan(opts, depsProvider, osvProvider, packageJson.version);
  process.stdout.write(renderResult(result, opts));
  process.exitCode = determineExitCode(result, opts);
}

async function runFix(raw: FixCommandOptions): Promise<void> {
  const strategy = parseFixStrategy(raw.strategy);
  const scope = parseFixScope(raw.scope);
  const upgradeLevel = parseFixUpgradeLevel(raw.upgradeLevel);
  const format = parseFixFormat(raw.format);

  const scanOpts = resolveScanOptions(
    {
      mode: raw.mode,
      format: "json",
      root: raw.root,
      entry: raw.entry,
      conditions: raw.conditions,
      includeTypeImports: raw.includeTypeImports,
      includeDev: raw.includeDev,
      omitDev: raw.omitDev,
      include: raw.include,
      omit: raw.omit,
      cacheDir: raw.cacheDir,
      offline: raw.offline,
      ignoreFile: raw.ignoreFile,
      severityThreshold: raw.severityThreshold,
      exitCodeOn: "none",
      failOn: "all"
    },
    process.cwd()
  );

  const onlyReachable = Boolean(raw.onlyReachable);
  const includeUnreachable = Boolean(raw.includeUnreachable);

  const depsProvider = new ProviderRegistry();
  const detected = await detectOrThrow(depsProvider, scanOpts);
  const osvProvider = new OsvProvider(new OsvClient(), new OsvCache(scanOpts.cacheDir), scanOpts.offline);

  const detectMode = scanOpts.mode === "installed" ? "installed" : "lockfile";
  const [result, graph] = await Promise.all([
    runScan(scanOpts, depsProvider, osvProvider, packageJson.version),
    depsProvider.load(scanOpts.root, detectMode)
  ]);

  const plan = buildRemediationPlan(result, graph, {
    strategy,
    manager: detected.manager,
    policy: {
      scope,
      upgradeLevel,
      onlyReachable,
      includeUnreachable,
      includeDev: scanOpts.includeDev,
      severityThreshold: scanOpts.severityThreshold
    },
    relock: Boolean(raw.relock),
    verify: Boolean(raw.verify)
  });

  let verifyOutput: string | undefined;
  if (raw.apply) {
    const applyResult = await applyRemediationPlan(
      plan,
      {
        projectRoot: scanOpts.root,
        lockfilePath: detected.lockfilePath,
        rollbackOnFail: raw.rollbackOnFail !== false,
        verify: raw.verify
          ? {
              scanOptions: scanOpts,
              expectedFixedVulnIds: plan.fixes.fixedVulnerabilities,
              baselineVulnIds: result.findings.map((finding) => finding.vulnId),
              noIntroduce: Boolean(raw.noIntroduce),
              toolVersion: packageJson.version
            }
          : undefined
      },
      depsProvider,
      osvProvider
    );

    if (applyResult.verify) {
      plan.fixes.fixedVulnerabilities = applyResult.verify.fixedVulnerabilities;
      plan.fixes.remainingVulnerabilities = applyResult.verify.remainingVulnerabilities;
      plan.fixes.introducedVulnerabilities = applyResult.verify.introducedVulnerabilities;
      verifyOutput = renderVerifyOutcomeText(applyResult.verify);
      if (!applyResult.verify.ok) {
        process.exitCode = 1;
      }
    }
  }

  if (format === "json") {
    process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
    if (verifyOutput && raw.apply) {
      process.stderr.write(verifyOutput);
    }
    return;
  }

  if (format === "sarif") {
    process.stdout.write(
      renderSarif(result, {
        remediationPlan: plan
      })
    );
    if (verifyOutput && raw.apply) {
      process.stderr.write(verifyOutput);
    }
    return;
  }

  process.stdout.write(renderRemediationText(plan));
  if (raw.apply) {
    process.stdout.write(`Applied: yes\n`);
    if (raw.relock) {
      process.stdout.write("Relock: requested\n");
    }
  } else {
    process.stdout.write("Applied: no (dry-run)\n");
  }
  if (verifyOutput) {
    process.stdout.write(verifyOutput);
  }
}

async function runExplain(vulnId: string, options: { cacheDir?: string; offline?: boolean; format?: string }): Promise<void> {
  const provider = new OsvProvider(
    new OsvClient(),
    new OsvCache(options.cacheDir),
    Boolean(options.offline)
  );

  const vuln = await provider.getVuln(vulnId);

  if (options.format === "json") {
    process.stdout.write(`${JSON.stringify(vuln, null, 2)}\n`);
    return;
  }

  process.stdout.write(renderExplainText(vuln));
}

const program = new Command();
program
  .name("npmvulncheck")
  .description("govulncheck-compatible vulnerability scanner for npm")
  .version(packageJson.version, "--version", "Show version")
  .option("--mode <mode>", "scan mode: lockfile|installed|source", "lockfile")
  .option("--format <format>", "output format: text|json|sarif|openvex", "text")
  .option("--root <dir>", "project root", ".")
  .option("--entry <file>", "entry file (repeatable)", collect, [])
  .option("--conditions <condition>", "module resolution condition (repeatable)", collect, [])
  .option("--include-type-imports", "include TypeScript type-only imports in reachability")
  .option("--explain-resolve", "show unresolved import resolution candidates in source mode")
  .option("--show <item>", "show extra sections: traces,verbose", collect, [])
  .option("--include <type>", "include dependency types (e.g. dev)", collect, [])
  .option("--omit <type>", "omit dependency types (default: dev)", collect, ["dev"])
  .option("--include-dev", "include dev dependencies")
  .option("--omit-dev", "omit dev dependencies")
  .option("--cache-dir <dir>", "OSV cache directory")
  .option("--offline", "use cached vulnerability records only")
  .option("--ignore-file <path>", "ignore policy file path")
  .option("--exit-code-on <mode>", "none|findings|reachable-findings")
  .option("--severity-threshold <level>", "low|medium|high|critical")
  .option("--fail-on <scope>", "all|reachable|direct", "all")
  .action(async (rawOptions) => {
    await runDefaultScan(rawOptions as Record<string, unknown>);
  });

program
  .command("fix")
  .description("generate guided remediation plan and optionally apply it")
  .option("--strategy <strategy>", "override|direct|in-place|auto", "auto")
  .option("--scope <scope>", "global|by-parent", "global")
  .option("--upgrade-level <level>", "patch|minor|major|any", "any")
  .option("--format <format>", "text|json|sarif", "text")
  .option("--apply", "apply manifest changes")
  .option("--relock", "update lockfile after apply")
  .option("--verify", "rescan and verify target vulnerabilities are fixed")
  .option("--no-introduce", "verify fails when new vulnerabilities are introduced")
  .option("--no-rollback-on-fail", "keep modified files when apply/relock fails")
  .option("--only-reachable", "plan only for reachable findings")
  .option("--include-unreachable", "include unreachable findings in planning")
  .option("--mode <mode>", "scan mode: lockfile|installed|source", "lockfile")
  .option("--root <dir>", "project root", ".")
  .option("--entry <file>", "entry file (repeatable)", collect, [])
  .option("--conditions <condition>", "module resolution condition (repeatable)", collect, [])
  .option("--include-type-imports", "include TypeScript type-only imports in reachability")
  .option("--include <type>", "include dependency types (e.g. dev)", collect, [])
  .option("--omit <type>", "omit dependency types (default: dev)", collect, ["dev"])
  .option("--include-dev", "include dev dependencies")
  .option("--omit-dev", "omit dev dependencies")
  .option("--cache-dir <dir>", "OSV cache directory")
  .option("--offline", "use cached vulnerability records only")
  .option("--ignore-file <path>", "ignore policy file path")
  .option("--severity-threshold <level>", "low|medium|high|critical")
  .action(async (_options, command) => {
    await runFix(command.optsWithGlobals() as FixCommandOptions);
  });

program
  .command("explain")
  .description("show vulnerability details by ID")
  .argument("<vulnId>")
  .option("--cache-dir <dir>", "OSV cache directory")
  .option("--offline", "use cached vulnerability records only")
  .option("--format <format>", "text|json", "text")
  .action(async (vulnId, _options, command) => {
    await runExplain(vulnId, command.optsWithGlobals() as { cacheDir?: string; offline?: boolean; format?: string });
  });

program
  .command("version")
  .description("show tool and database metadata")
  .option("--cache-dir <dir>", "OSV cache directory")
  .action(async (options) => {
    const cache = new OsvCache(options.cacheDir);
    const summary = await cache.getVulnSummary();
    process.stdout.write(
      [
        `npmvulncheck ${packageJson.version}`,
        "db: osv",
        `db records: ${summary.count}`,
        `db last-updated: ${summary.lastUpdated ?? "unknown"}`,
        `osv cache: ${cache.dir}`
      ].join("\n") + "\n"
    );
  });

program.parseAsync(process.argv).catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`Error: ${message}\n`);
  process.exitCode = 2;
});
