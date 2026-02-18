import fs from "node:fs/promises";
import path from "node:path";

async function fileExists(filePath: string): Promise<boolean> {
  try {
    return (await fs.stat(filePath)).isFile();
  } catch {
    return false;
  }
}

function collectFromExportsField(value: unknown, out: string[]): void {
  if (typeof value === "string") {
    out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectFromExportsField(item, out);
    }
    return;
  }
  if (typeof value === "object" && value !== null) {
    for (const nested of Object.values(value)) {
      collectFromExportsField(nested, out);
    }
  }
}

export async function discoverEntries(projectRoot: string, explicitEntries: string[]): Promise<string[]> {
  const candidates = new Set<string>();

  for (const entry of explicitEntries) {
    const abs = path.resolve(projectRoot, entry);
    if (await fileExists(abs)) {
      candidates.add(abs);
    }
  }

  if (candidates.size > 0) {
    return Array.from(candidates);
  }

  const packageJsonPath = path.join(projectRoot, "package.json");
  const packageJsonText = await fs.readFile(packageJsonPath, "utf8").catch(() => undefined);
  if (packageJsonText) {
    const manifest = JSON.parse(packageJsonText) as {
      main?: string;
      bin?: string | Record<string, string>;
      exports?: unknown;
    };

    if (manifest.main) {
      candidates.add(path.resolve(projectRoot, manifest.main));
    }
    if (typeof manifest.bin === "string") {
      candidates.add(path.resolve(projectRoot, manifest.bin));
    } else if (manifest.bin && typeof manifest.bin === "object") {
      for (const binPath of Object.values(manifest.bin)) {
        candidates.add(path.resolve(projectRoot, binPath));
      }
    }

    const exportsCandidates: string[] = [];
    collectFromExportsField(manifest.exports, exportsCandidates);
    for (const exportPath of exportsCandidates) {
      candidates.add(path.resolve(projectRoot, exportPath));
    }
  }

  for (const convention of [
    "src/index.ts",
    "src/index.tsx",
    "src/index.js",
    "src/index.jsx",
    "index.ts",
    "index.js"
  ]) {
    candidates.add(path.resolve(projectRoot, convention));
  }

  const existing: string[] = [];
  for (const candidate of candidates) {
    if (await fileExists(candidate)) {
      existing.push(candidate);
    }
  }

  return existing;
}
