import fs from "node:fs";
import path from "node:path";

const SOURCE_EXTENSIONS = [
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".mts",
  ".cts"
];

function isFile(filePath: string): boolean {
  try {
    return fs.statSync(filePath).isFile();
  } catch {
    return false;
  }
}

function isDirectory(dirPath: string): boolean {
  try {
    return fs.statSync(dirPath).isDirectory();
  } catch {
    return false;
  }
}

export function normalizePackageSpecifier(specifier: string): string | undefined {
  if (!specifier || specifier.startsWith(".") || specifier.startsWith("/") || specifier.startsWith("node:")) {
    return undefined;
  }

  if (specifier.startsWith("@")) {
    const parts = specifier.split("/");
    if (parts.length < 2) {
      return undefined;
    }
    return `${parts[0]}/${parts[1]}`;
  }

  const firstSlash = specifier.indexOf("/");
  if (firstSlash < 0) {
    return specifier;
  }

  return specifier.slice(0, firstSlash);
}

export function resolveLocalModule(fromFile: string, specifier: string): string | undefined {
  if (!(specifier.startsWith(".") || specifier.startsWith("/"))) {
    return undefined;
  }

  const base = specifier.startsWith("/")
    ? specifier
    : path.resolve(path.dirname(fromFile), specifier);

  if (path.extname(base)) {
    if (isFile(base)) {
      return base;
    }
  } else {
    for (const ext of SOURCE_EXTENSIONS) {
      const file = `${base}${ext}`;
      if (isFile(file)) {
        return file;
      }
    }
  }

  if (isDirectory(base)) {
    for (const ext of SOURCE_EXTENSIONS) {
      const indexFile = path.join(base, `index${ext}`);
      if (isFile(indexFile)) {
        return indexFile;
      }
    }
  }

  return undefined;
}
