import { runPipeline } from "./pipeline";
import { fetchRemoteFlags } from "./runtime/loadFlags";

async function main(): Promise<void> {
  const normalized = runPipeline(["Red Apple", "green_pear", "red apple"]);

  let flagCount = 0;
  try {
    const flags = await fetchRemoteFlags();
    flagCount = Object.keys(flags).length;
  } catch {
    // Ignore network errors in this sample.
  }

  console.log({ normalized, flagCount });
}

void main();
