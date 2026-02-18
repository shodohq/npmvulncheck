import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { isIgnored, loadIgnorePolicy } from "../src/policy/ignore";
import { cleanupTempDirs, makeTempDir } from "./helpers";

afterEach(async () => {
  await cleanupTempDirs();
});

describe("ignore policy", () => {
  it("ignores only active rules and treats invalid until as inactive", async () => {
    const tempDir = await makeTempDir("npmvulncheck-ignore-");
    const file = path.join(tempDir, ".npmvulncheck-ignore.json");
    await fs.writeFile(
      file,
      JSON.stringify(
        {
          ignore: [
            { id: "GHSA-active" },
            { id: "GHSA-future", until: "2099-01-01" },
            { id: "GHSA-expired", until: "2000-01-01" },
            { id: "GHSA-invalid", until: "not-a-date" }
          ]
        },
        null,
        2
      ),
      "utf8"
    );

    const policy = await loadIgnorePolicy(tempDir);
    expect(isIgnored("GHSA-active", policy)).toBe(true);
    expect(isIgnored("GHSA-future", policy)).toBe(true);
    expect(isIgnored("GHSA-expired", policy)).toBe(false);
    expect(isIgnored("GHSA-invalid", policy)).toBe(false);
  });
});
