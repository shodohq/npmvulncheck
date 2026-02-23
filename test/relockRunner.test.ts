import { describe, expect, it } from "vitest";
import { buildRelockCommand } from "../src/remediation/apply/relockRunner";

describe("buildRelockCommand", () => {
  it("returns npm lockfile-only command", () => {
    expect(buildRelockCommand("npm")).toEqual({
      command: "npm",
      args: ["install", "--package-lock-only"]
    });
  });

  it("returns pnpm lockfile-only command", () => {
    expect(buildRelockCommand("pnpm")).toEqual({
      command: "pnpm",
      args: ["install", "--lockfile-only"]
    });
  });

  it("returns yarn update-lockfile command", () => {
    expect(buildRelockCommand("yarn")).toEqual({
      command: "yarn",
      args: ["install", "--mode=update-lockfile"]
    });
  });
});
