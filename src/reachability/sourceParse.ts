import fs from "node:fs/promises";
import ts from "typescript";
import { ImportKind } from "../core/types";

export type ParsedImport = {
  specifier?: string;
  kind: ImportKind;
  typeOnly: boolean;
  line: number;
  column: number;
  importText: string;
  unknown?: boolean;
};

function addImport(
  out: ParsedImport[],
  sourceFile: ts.SourceFile,
  node: ts.Node,
  kind: ImportKind,
  typeOnly: boolean,
  specifier?: string,
  unknown = false
): void {
  const { line, character } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  out.push({
    specifier,
    kind,
    typeOnly,
    line: line + 1,
    column: character + 1,
    importText: node.getText(sourceFile),
    unknown
  });
}

function isRequireCall(node: ts.CallExpression): boolean {
  return ts.isIdentifier(node.expression) && node.expression.text === "require";
}

function isDynamicImport(node: ts.CallExpression): boolean {
  return node.expression.kind === ts.SyntaxKind.ImportKeyword;
}

function isTypeOnlyImportDeclaration(node: ts.ImportDeclaration): boolean {
  const clause = node.importClause;
  if (!clause) {
    return false;
  }

  if (clause.isTypeOnly) {
    return true;
  }

  if (clause.name) {
    return false;
  }

  const bindings = clause.namedBindings;
  if (!bindings) {
    return false;
  }

  if (!ts.isNamedImports(bindings)) {
    return false;
  }

  return bindings.elements.length > 0 && bindings.elements.every((element) => element.isTypeOnly);
}

function isTypeOnlyExportDeclaration(node: ts.ExportDeclaration): boolean {
  if (node.isTypeOnly) {
    return true;
  }

  if (!node.exportClause || !ts.isNamedExports(node.exportClause)) {
    return false;
  }

  return node.exportClause.elements.length > 0 && node.exportClause.elements.every((element) => element.isTypeOnly);
}

export async function parseImportsFromFile(filePath: string): Promise<ParsedImport[]> {
  const sourceText = await fs.readFile(filePath, "utf8");
  const sourceFile = ts.createSourceFile(filePath, sourceText, ts.ScriptTarget.Latest, true);
  const imports: ParsedImport[] = [];

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      const moduleSpecifier = node.moduleSpecifier;
      const typeOnly = ts.isImportDeclaration(node)
        ? isTypeOnlyImportDeclaration(node)
        : isTypeOnlyExportDeclaration(node);
      if (moduleSpecifier && ts.isStringLiteral(moduleSpecifier)) {
        addImport(imports, sourceFile, node, "esm-import", typeOnly, moduleSpecifier.text);
      } else if (moduleSpecifier) {
        addImport(imports, sourceFile, node, "esm-import", typeOnly, undefined, true);
      }
    } else if (ts.isCallExpression(node) && (isRequireCall(node) || isDynamicImport(node))) {
      const [firstArg] = node.arguments;
      const importKind: ImportKind = isRequireCall(node) ? "cjs-require" : "esm-dynamic-import";
      if (firstArg && ts.isStringLiteral(firstArg)) {
        addImport(imports, sourceFile, node, importKind, false, firstArg.text);
      } else if (firstArg) {
        addImport(imports, sourceFile, node, importKind, false, undefined, true);
      }
    }

    ts.forEachChild(node, visit);
  };

  visit(sourceFile);

  return imports;
}
