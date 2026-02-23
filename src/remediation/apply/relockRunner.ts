import { spawn } from "node:child_process";
import { DependencyManager } from "../../core/types";
import { RemediationOperation } from "../types";

export type RelockCommand = {
  command: string;
  args: string[];
};

export function buildRelockCommand(manager: DependencyManager): RelockCommand {
  if (manager === "npm") {
    return {
      command: "npm",
      args: ["install", "--package-lock-only"]
    };
  }

  if (manager === "pnpm") {
    return {
      command: "pnpm",
      args: ["install", "--lockfile-only"]
    };
  }

  return {
    command: "yarn",
    args: ["install", "--mode=update-lockfile"]
  };
}

export async function runRelockOperation(
  operation: Extract<RemediationOperation, { kind: "relock" }>,
  projectRoot: string
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn(operation.command, operation.args, {
      cwd: projectRoot,
      stdio: "inherit"
    });

    child.on("error", (error) => {
      reject(error);
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`relock failed: ${operation.command} ${operation.args.join(" ")} (exit ${String(code)})`));
    });
  });
}
