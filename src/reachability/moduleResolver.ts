import path from "node:path";
import ts from "typescript";
import { ImportKind } from "../core/types";

const SOURCE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".mts",
  ".cts"
]);

const DEFAULT_COMPILER_OPTIONS: ts.CompilerOptions = {
  module: ts.ModuleKind.NodeNext,
  moduleResolution: ts.ModuleResolutionKind.NodeNext,
  allowJs: true,
  resolveJsonModule: true
};

export type ModuleResolution = {
  filePath?: string;
  failedLookupLocations: string[];
};

export interface ModuleResolver {
  resolveToFile(specifier: string, fromFile: string, importKind: ImportKind, conditions: string[]): ModuleResolution;
}

function canonicalFileName(fileName: string): string {
  return ts.sys.useCaseSensitiveFileNames ? fileName : fileName.toLowerCase();
}

function withDefaultCompilerOptions(options: ts.CompilerOptions): ts.CompilerOptions {
  return {
    ...DEFAULT_COMPILER_OPTIONS,
    ...options,
    allowJs: options.allowJs ?? true
  };
}

function findTsConfigPath(projectRoot: string): string | undefined {
  return ts.findConfigFile(projectRoot, ts.sys.fileExists, "tsconfig.json");
}

function loadCompilerOptionsFromTsConfig(configPath: string): ts.CompilerOptions | undefined {
  const config = ts.readConfigFile(configPath, ts.sys.readFile);
  if (config.error || !config.config) {
    return undefined;
  }

  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, path.dirname(configPath));
  if (parsed.errors.length > 0) {
    return undefined;
  }

  return withDefaultCompilerOptions(parsed.options);
}

function loadCompilerOptions(projectRoot: string): ts.CompilerOptions {
  const configPath = findTsConfigPath(projectRoot);
  if (!configPath) {
    return { ...DEFAULT_COMPILER_OPTIONS };
  }

  const loaded = loadCompilerOptionsFromTsConfig(configPath);
  if (!loaded) {
    return { ...DEFAULT_COMPILER_OPTIONS };
  }

  return loaded;
}

function modeForImportKind(importKind: ImportKind): ts.ResolutionMode {
  if (importKind === "cjs-require") {
    return ts.ModuleKind.CommonJS;
  }
  return ts.ModuleKind.ESNext;
}

export function isSourceCodePath(filePath: string): boolean {
  return SOURCE_EXTENSIONS.has(path.extname(filePath));
}

export function isNodeModulesPath(filePath: string): boolean {
  const normalized = path.normalize(filePath);
  const needle = `${path.sep}node_modules${path.sep}`;
  return normalized.includes(needle);
}

class TypeScriptApiResolver implements ModuleResolver {
  private readonly projectRoot: string;
  private readonly compilerOptions: ts.CompilerOptions;
  private readonly defaultCache: ts.ModuleResolutionCache;
  private readonly cacheByConditions = new Map<string, { options: ts.CompilerOptions; cache: ts.ModuleResolutionCache }>();

  constructor(projectRoot: string, compilerOptions: ts.CompilerOptions) {
    this.projectRoot = projectRoot;
    this.compilerOptions = compilerOptions;
    this.defaultCache = ts.createModuleResolutionCache(projectRoot, canonicalFileName, this.compilerOptions);
  }

  private contextForConditions(conditions: string[]): { options: ts.CompilerOptions; cache: ts.ModuleResolutionCache } {
    const normalizedConditions = Array.from(new Set(conditions.filter(Boolean)));
    if (normalizedConditions.length === 0) {
      return {
        options: this.compilerOptions,
        cache: this.defaultCache
      };
    }

    const key = normalizedConditions.join("\u0000");
    const existing = this.cacheByConditions.get(key);
    if (existing) {
      return existing;
    }

    const options: ts.CompilerOptions = {
      ...this.compilerOptions,
      customConditions: normalizedConditions
    };
    const cache = ts.createModuleResolutionCache(this.projectRoot, canonicalFileName, options);
    const entry = { options, cache };
    this.cacheByConditions.set(key, entry);
    return entry;
  }

  resolveToFile(specifier: string, fromFile: string, importKind: ImportKind, conditions: string[]): ModuleResolution {
    const context = this.contextForConditions(conditions);
    const resolved = ts.resolveModuleName(
      specifier,
      fromFile,
      context.options,
      ts.sys,
      context.cache,
      undefined,
      modeForImportKind(importKind)
    );

    const resolvedFileName = resolved.resolvedModule?.resolvedFileName;
    const failedLookupLocations =
      ((resolved as { failedLookupLocations?: readonly string[] }).failedLookupLocations ?? []).map((location: string) =>
        path.resolve(location)
      );
    if (!resolvedFileName) {
      return { failedLookupLocations };
    }

    return {
      filePath: path.resolve(resolvedFileName),
      failedLookupLocations
    };
  }
}

export class TsResolver extends TypeScriptApiResolver {
  constructor(projectRoot: string) {
    super(projectRoot, loadCompilerOptions(projectRoot));
  }
}

export class NodeResolver extends TypeScriptApiResolver {
  constructor(projectRoot: string) {
    super(projectRoot, { ...DEFAULT_COMPILER_OPTIONS });
  }
}

export function createModuleResolver(projectRoot: string): ModuleResolver {
  if (findTsConfigPath(projectRoot)) {
    return new TsResolver(projectRoot);
  }
  return new NodeResolver(projectRoot);
}
