export async function loadHeuristicModule(): Promise<unknown> {
  const moduleName = process.env.HEURISTIC_MODULE;
  if (!moduleName) {
    return null;
  }

  return import(moduleName);
}
