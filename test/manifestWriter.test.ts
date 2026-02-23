import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { applyManifestOverrideOperation } from "../src/remediation/apply/manifestWriter";
import { cleanupTempDirs, makeTempDir } from "./helpers";

afterEach(async () => {
  await cleanupTempDirs();
});

describe("applyManifestOverrideOperation", () => {
  it("writes npm overrides in package.json", async () => {
    const root = await makeTempDir("npmvulncheck-manifest-writer-");
    const packageJsonPath = path.join(root, "package.json");

    await fs.writeFile(
      packageJsonPath,
      JSON.stringify(
        {
          name: "fixture",
          version: "1.0.0"
        },
        null,
        2
      ),
      "utf8"
    );

    await applyManifestOverrideOperation(
      {
        id: "op-1",
        kind: "manifest-override",
        manager: "npm",
        file: "package.json",
        changes: [
          {
            package: "lodash",
            to: "4.17.21",
            scope: "global",
            why: "test"
          },
          {
            package: "debug",
            to: "4.3.6",
            scope: {
              parent: "webpack",
              parentVersion: "5.90.0"
            },
            why: "test"
          }
        ]
      },
      root
    );

    const parsed = JSON.parse(await fs.readFile(packageJsonPath, "utf8")) as {
      overrides?: Record<string, unknown>;
    };

    expect(parsed.overrides).toEqual({
      lodash: "4.17.21",
      "webpack@5.90.0": {
        debug: "4.3.6"
      }
    });
  });

  it("writes pnpm overrides under pnpm.overrides", async () => {
    const root = await makeTempDir("npmvulncheck-manifest-writer-pnpm-");
    const packageJsonPath = path.join(root, "package.json");

    await fs.writeFile(
      packageJsonPath,
      JSON.stringify(
        {
          name: "fixture",
          version: "1.0.0"
        },
        null,
        2
      ),
      "utf8"
    );

    await applyManifestOverrideOperation(
      {
        id: "op-1",
        kind: "manifest-override",
        manager: "pnpm",
        file: "package.json",
        changes: [
          {
            package: "lodash",
            to: "4.17.21",
            scope: "global",
            why: "test"
          }
        ]
      },
      root
    );

    const parsed = JSON.parse(await fs.readFile(packageJsonPath, "utf8")) as {
      pnpm?: { overrides?: Record<string, string> };
    };

    expect(parsed.pnpm?.overrides).toEqual({
      lodash: "4.17.21"
    });
  });
});
