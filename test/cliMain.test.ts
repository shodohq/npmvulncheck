import path from "node:path";
import fs from "node:fs/promises";
import os from "node:os";
import { execFile as execFileCb } from "node:child_process";
import { promisify } from "node:util";
import { beforeAll, describe, expect, it } from "vitest";

const execFile = promisify(execFileCb);

beforeAll(async () => {
  await execFile("npm", ["run", "build"], {
    cwd: process.cwd(),
    env: { ...process.env, NO_COLOR: "1" }
  });
});

describe("cli main error handling", () => {
  it("returns non-zero with clear error on missing lockfile", async () => {
    const nodeBin = process.execPath;
    const cliFile = path.resolve(process.cwd(), "dist", "cli", "main.js");
    const fixtureRoot = path.resolve(process.cwd(), "test", "fixtures", "no-lock");

    let code = 0;
    try {
      await execFile(nodeBin, [cliFile, "--root", fixtureRoot], {
        cwd: process.cwd(),
        env: { ...process.env, NO_COLOR: "1" }
      });
    } catch (error) {
      const err = error as { code?: number };
      code = Number(err.code ?? 0);
    }

    expect(code).toBe(2);
  });

  it("returns non-zero in installed mode when node_modules is missing", async () => {
    const nodeBin = process.execPath;
    const cliFile = path.resolve(process.cwd(), "dist", "cli", "main.js");
    const fixtureRoot = path.resolve(process.cwd(), "test", "fixtures", "dep-graph-local");

    let code = 0;
    try {
      await execFile(nodeBin, [cliFile, "--mode", "installed", "--root", fixtureRoot], {
        cwd: process.cwd(),
        env: { ...process.env, NO_COLOR: "1" }
      });
    } catch (error) {
      const err = error as { code?: number };
      code = Number(err.code ?? 0);
    }

    expect(code).toBe(2);
  });

  it("runs fix apply+relock+verify end-to-end on a minimal npm fixture", async () => {
    const nodeBin = process.execPath;
    const cliFile = path.resolve(process.cwd(), "dist", "cli", "main.js");
    const fixtureRoot = await fs.mkdtemp(path.join(os.tmpdir(), "npmvulncheck-cli-fix-"));

    try {
      await fs.writeFile(
        path.join(fixtureRoot, "package.json"),
        `${JSON.stringify(
          {
            name: "fixture",
            version: "1.0.0",
            private: true
          },
          null,
          2
        )}\n`,
        "utf8"
      );
      await fs.writeFile(
        path.join(fixtureRoot, "package-lock.json"),
        `${JSON.stringify(
          {
            name: "fixture",
            version: "1.0.0",
            lockfileVersion: 3,
            requires: true,
            packages: {
              "": {
                name: "fixture",
                version: "1.0.0"
              }
            }
          },
          null,
          2
        )}\n`,
        "utf8"
      );

      const { stdout } = await execFile(
        nodeBin,
        [
          cliFile,
          "fix",
          "--strategy",
          "override",
          "--apply",
          "--relock",
          "--verify",
          "--format",
          "text",
          "--offline",
          "--root",
          fixtureRoot
        ],
        {
          cwd: process.cwd(),
          env: { ...process.env, NO_COLOR: "1" }
        }
      );

      expect(stdout.includes("Relock: requested")).toBe(true);
      expect(stdout.includes("Verify result:")).toBe(true);
    } finally {
      await fs.rm(fixtureRoot, { recursive: true, force: true });
    }
  }, 20000);

  it("honors fix --root and returns non-zero when the target has no lockfile", async () => {
    const nodeBin = process.execPath;
    const cliFile = path.resolve(process.cwd(), "dist", "cli", "main.js");
    const fixtureRoot = path.resolve(process.cwd(), "test", "fixtures", "no-lock");

    let code = 0;
    let stderr = "";
    try {
      await execFile(nodeBin, [cliFile, "fix", "--root", fixtureRoot, "--offline"], {
        cwd: process.cwd(),
        env: { ...process.env, NO_COLOR: "1" }
      });
    } catch (error) {
      const err = error as { code?: number; stderr?: string };
      code = Number(err.code ?? 0);
      stderr = String(err.stderr ?? "");
    }

    expect(code).toBe(2);
    expect(stderr.includes("No supported lockfile found")).toBe(true);
  });

  it("uses auto as the default fix strategy and emits plan JSON", async () => {
    const nodeBin = process.execPath;
    const cliFile = path.resolve(process.cwd(), "dist", "cli", "main.js");
    const fixtureRoot = await fs.mkdtemp(path.join(os.tmpdir(), "npmvulncheck-cli-fix-json-"));

    try {
      await fs.writeFile(
        path.join(fixtureRoot, "package.json"),
        `${JSON.stringify(
          {
            name: "fixture",
            version: "1.0.0",
            private: true
          },
          null,
          2
        )}\n`,
        "utf8"
      );
      await fs.writeFile(
        path.join(fixtureRoot, "package-lock.json"),
        `${JSON.stringify(
          {
            name: "fixture",
            version: "1.0.0",
            lockfileVersion: 3,
            requires: true,
            packages: {
              "": {
                name: "fixture",
                version: "1.0.0"
              }
            }
          },
          null,
          2
        )}\n`,
        "utf8"
      );

      const { stdout } = await execFile(
        nodeBin,
        [
          cliFile,
          "fix",
          "--format",
          "json",
          "--offline",
          "--root",
          fixtureRoot
        ],
        {
          cwd: process.cwd(),
          env: { ...process.env, NO_COLOR: "1" }
        }
      );

      const parsed = JSON.parse(stdout) as { tool?: string; strategy?: string };
      expect(parsed.tool).toBe("npmvulncheck");
      expect(parsed.strategy).toBe("auto");
    } finally {
      await fs.rm(fixtureRoot, { recursive: true, force: true });
    }
  });

  it("honors explain --offline and fails with an offline cache-miss message", async () => {
    const nodeBin = process.execPath;
    const cliFile = path.resolve(process.cwd(), "dist", "cli", "main.js");
    const cacheDir = await fs.mkdtemp(path.join(os.tmpdir(), "npmvulncheck-cli-explain-offline-"));

    let code = 0;
    let stderr = "";
    try {
      await execFile(
        nodeBin,
        [
          cliFile,
          "explain",
          "GHSA-test-test-test",
          "--offline",
          "--format",
          "json",
          "--cache-dir",
          cacheDir
        ],
        {
          cwd: process.cwd(),
          env: { ...process.env, NO_COLOR: "1" }
        }
      );
    } catch (error) {
      const err = error as { code?: number; stderr?: string };
      code = Number(err.code ?? 0);
      stderr = String(err.stderr ?? "");
    } finally {
      await fs.rm(cacheDir, { recursive: true, force: true });
    }

    expect(code).toBe(2);
    expect(stderr.includes("Offline mode: vulnerability GHSA-test-test-test is not in cache.")).toBe(true);
  });
});
