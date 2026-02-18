import path from "node:path";
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
});
