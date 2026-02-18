#!/usr/bin/env node
import { Command } from "commander";
import packageJson from "../../package.json";
import { resolveScanOptions, collect } from "./args";
import { runScan } from "../core/scan";
import { NpmArboristProvider } from "../deps/npmArborist";
import { OsvCache } from "../osv/cache";
import { OsvClient } from "../osv/client";
import { OsvProvider } from "../osv/provider";
import { renderJson } from "../report/json";
import { renderOpenVex } from "../report/openvex";
import { renderSarif } from "../report/sarif";
import { renderText } from "../report/text";
import { Finding, ScanOptions, ScanResult } from "../core/types";

function isReachableFinding(finding: Finding): boolean {
  return finding.affected.some((affected) => affected.reachability?.reachable);
}

function isDirectFinding(finding: Finding): boolean {
  return finding.affected.some((affected) => affected.paths.some((path) => path.length <= 2));
}

function applyFailOnFilter(findings: Finding[], failOn: ScanOptions["failOn"]): Finding[] {
  if (failOn === "reachable") {
    return findings.filter((finding) => isReachableFinding(finding));
  }
  if (failOn === "direct") {
    return findings.filter((finding) => isDirectFinding(finding));
  }
  return findings;
}

function determineExitCode(result: ScanResult, opts: ScanOptions): number {
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

async function runDefaultScan(raw: Record<string, unknown>): Promise<void> {
  const opts = resolveScanOptions(raw as never, process.cwd());
  const depsProvider = new NpmArboristProvider();
  const detected = await depsProvider.detect(opts.root);
  if (!detected) {
    throw new Error(`No npm lockfile found in ${opts.root}. Expected package-lock.json or npm-shrinkwrap.json.`);
  }

  const osvProvider = new OsvProvider(new OsvClient(), new OsvCache(opts.cacheDir), opts.offline);
  const result = await runScan(opts, depsProvider, osvProvider, packageJson.version);
  process.stdout.write(renderResult(result, opts));
  process.exitCode = determineExitCode(result, opts);
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
  .command("explain")
  .description("show vulnerability details by ID")
  .argument("<vulnId>")
  .option("--cache-dir <dir>", "OSV cache directory")
  .option("--offline", "use cached vulnerability records only")
  .option("--format <format>", "text|json", "text")
  .action(async (vulnId, options) => {
    await runExplain(vulnId, options);
  });

program
  .command("version")
  .description("show tool and database metadata")
  .option("--cache-dir <dir>", "OSV cache directory")
  .action(async (options) => {
    const cache = new OsvCache(options.cacheDir);
    process.stdout.write(`npmvulncheck ${packageJson.version}\nosv cache: ${cache.dir}\n`);
  });

program.parseAsync(process.argv).catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`Error: ${message}\n`);
  process.exitCode = 2;
});
