import fs from "node:fs/promises";
import ts from "typescript";

export type ParsedImport = {
  specifier?: string;
  line: number;
  column: number;
  importText: string;
  unknown?: boolean;
};

function addImport(
  out: ParsedImport[],
  sourceFile: ts.SourceFile,
  node: ts.Node,
  specifier?: string,
  unknown = false
): void {
  const { line, character } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  out.push({
    specifier,
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

export async function parseImportsFromFile(filePath: string): Promise<ParsedImport[]> {
  const sourceText = await fs.readFile(filePath, "utf8");
  const sourceFile = ts.createSourceFile(filePath, sourceText, ts.ScriptTarget.Latest, true);
  const imports: ParsedImport[] = [];

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      const moduleSpecifier = node.moduleSpecifier;
      if (moduleSpecifier && ts.isStringLiteral(moduleSpecifier)) {
        addImport(imports, sourceFile, node, moduleSpecifier.text);
      } else if (moduleSpecifier) {
        addImport(imports, sourceFile, node, undefined, true);
      }
    } else if (ts.isCallExpression(node) && (isRequireCall(node) || isDynamicImport(node))) {
      const [firstArg] = node.arguments;
      if (firstArg && ts.isStringLiteral(firstArg)) {
        addImport(imports, sourceFile, node, firstArg.text);
      } else if (firstArg) {
        addImport(imports, sourceFile, node, undefined, true);
      }
    }

    ts.forEachChild(node, visit);
  };

  visit(sourceFile);

  return imports;
}
