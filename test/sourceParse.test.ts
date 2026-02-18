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
        'import type { Foo } from "./types";',
        'export * from "@scope/pkg/sub";',
        'export type { Bar } from "./types";',
        'const a = require("lodash/map");',
        'await import("chalk");',
        "const b = require(dynamicVar);"
      ].join("\n"),
      "utf8"
    );

    const imports = await parseImportsFromFile(file);
    expect(imports.map((entry) => entry.specifier).filter((value): value is string => Boolean(value))).toEqual([
      "express",
      "./types",
      "@scope/pkg/sub",
      "./types",
      "lodash/map",
      "chalk"
    ]);
    expect(imports.find((entry) => entry.specifier === "express")?.kind).toBe("esm-import");
    expect(imports.find((entry) => entry.specifier === "lodash/map")?.kind).toBe("cjs-require");
    expect(imports.find((entry) => entry.specifier === "chalk")?.kind).toBe("esm-dynamic-import");
    expect(imports.filter((entry) => entry.specifier === "./types").every((entry) => entry.typeOnly)).toBe(true);
    expect(imports.some((entry) => entry.unknown)).toBe(true);
  });

  it("marks declaration-only type imports and exports correctly", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "npmvulncheck-parse-typeonly-"));
    tempDirs.push(tempDir);

    const file = path.join(tempDir, "index.ts");
    await fs.writeFile(
      file,
      [
        'import { type Foo } from "pkg-import-type-only";',
        'import { type Bar, Baz } from "pkg-import-mixed";',
        'export { type Qux } from "pkg-export-type-only";',
        'export { type Quux, Corge } from "pkg-export-mixed";'
      ].join("\n"),
      "utf8"
    );

    const imports = await parseImportsFromFile(file);

    expect(imports.find((entry) => entry.specifier === "pkg-import-type-only")?.typeOnly).toBe(true);
    expect(imports.find((entry) => entry.specifier === "pkg-import-mixed")?.typeOnly).toBe(false);
    expect(imports.find((entry) => entry.specifier === "pkg-export-type-only")?.typeOnly).toBe(true);
    expect(imports.find((entry) => entry.specifier === "pkg-export-mixed")?.typeOnly).toBe(false);
  });
});
