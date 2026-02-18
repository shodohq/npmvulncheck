import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const tempDirs: string[] = [];

export async function makeTempDir(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

export async function copyFixtureToTemp(fixtureName: string, prefix = "npmvulncheck-fixture-"): Promise<string> {
  const dest = await makeTempDir(prefix);
  const src = path.resolve(process.cwd(), "test", "fixtures", fixtureName);
  await fs.cp(src, dest, { recursive: true });
  return dest;
}

export async function cleanupTempDirs(): Promise<void> {
  const dirs = tempDirs.splice(0);
  await Promise.all(dirs.map((dir) => fs.rm(dir, { recursive: true, force: true })));
}
