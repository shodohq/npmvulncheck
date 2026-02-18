import fs from "node:fs/promises";
import path from "node:path";
import { IgnorePolicy } from "../core/types";

function isRuleActive(until?: string): boolean {
  if (!until) {
    return true;
  }
  const untilDate = new Date(until);
  if (Number.isNaN(untilDate.getTime())) {
    return true;
  }
  const now = new Date();
  return now <= untilDate;
}

export async function loadIgnorePolicy(projectRoot: string, ignorePath?: string): Promise<IgnorePolicy> {
  const resolved = ignorePath
    ? path.resolve(projectRoot, ignorePath)
    : path.join(projectRoot, ".npmvulncheck-ignore.json");

  const text = await fs.readFile(resolved, "utf8").catch(() => undefined);
  if (!text) {
    return { ignore: [] };
  }

  const parsed = JSON.parse(text) as IgnorePolicy;
  if (!parsed.ignore || !Array.isArray(parsed.ignore)) {
    return { ignore: [] };
  }

  return {
    ignore: parsed.ignore.filter((rule) => Boolean(rule.id) && isRuleActive(rule.until))
  };
}

export function isIgnored(vulnId: string, policy: IgnorePolicy): boolean {
  return policy.ignore.some((rule) => rule.id === vulnId);
}
