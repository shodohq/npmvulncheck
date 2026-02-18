import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseImportsFromFile } from "../src/reachability/sourceParse";

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

describe("parseImportsFromFile", () => {
  it("extracts import/require/export/dynamic import specifiers", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "npmvulncheck-parse-"));
    tempDirs.push(tempDir);

    const file = path.join(tempDir, "index.ts");
    await fs.writeFile(
      file,
      [
        'import express from "express";',
        'export * from "@scope/pkg/sub";',
        'const a = require("lodash/map");',
        'await import("chalk");',
        "const b = require(dynamicVar);"
      ].join("\n"),
      "utf8"
    );

    const imports = await parseImportsFromFile(file);
    expect(imports.map((entry) => entry.specifier).filter((value): value is string => Boolean(value))).toEqual([
      "express",
      "@scope/pkg/sub",
      "lodash/map",
      "chalk"
    ]);
    expect(imports.some((entry) => entry.unknown)).toBe(true);
  });
});
