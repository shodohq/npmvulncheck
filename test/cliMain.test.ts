import path from "node:path";
import { execFile as execFileCb } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFile = promisify(execFileCb);

describe("cli main error handling", () => {
  it("returns non-zero with clear error on missing lockfile", async () => {
    const tsxBin = path.resolve(process.cwd(), "node_modules", ".bin", "tsx");
    const fixtureRoot = path.resolve(process.cwd(), "test", "fixtures", "no-lock");

    let code = 0;
    let stderr = "";
    try {
      await execFile(tsxBin, ["src/cli/main.ts", "--root", fixtureRoot], {
        cwd: process.cwd(),
        env: { ...process.env, NO_COLOR: "1" }
      });
    } catch (error) {
      const err = error as { code?: number; stderr?: string };
      code = Number(err.code ?? 0);
      stderr = err.stderr ?? "";
    }

    expect(code).toBe(2);
    expect(stderr).toContain("No npm lockfile found");
  });
});
