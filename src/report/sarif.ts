import fs from "node:fs";
import path from "node:path";
import ts from "typescript";
import { FindingPriority, ScanResult } from "../core/types";
import { findingHighestSeverityLevel } from "../policy/severity";
import { getManifestOverrideProvider } from "../remediation/providers";
import { RemediationOperation, RemediationPlan } from "../remediation/types";
import {
  buildRemediationActionLookup,
  remediationActionKeyForDirectOperation,
  remediationActionKeyForOverrideChange,
  remediationLookupKey,
  RemediationReplacement
} from "./remediation";

type SarifReplacement = RemediationReplacement;

type SarifFix = {
  description: {
    text: string;
  };
  artifactChanges: Array<{
    artifactLocation: {
      uri: string;
    };
    replacements: SarifReplacement[];
  }>;
};

export type RenderSarifOptions = {
  remediationPlan?: RemediationPlan;
  projectRoot?: string;
};

type ManifestOperation = Extract<RemediationOperation, { kind: "manifest-override" | "manifest-direct-upgrade" }>;
type OverrideOperation = Extract<ManifestOperation, { kind: "manifest-override" }>;
type DirectUpgradeOperation = Extract<ManifestOperation, { kind: "manifest-direct-upgrade" }>;
type DirectField = "dependencies" | "devDependencies" | "optionalDependencies";

type JsonEdit = {
  start: number;
  end: number;
  newText: string;
};

type JsonEditContext = {
  text: string;
  sourceFile: ts.JsonSourceFile;
  root: ts.ObjectLiteralExpression;
  lineStarts: number[];
  newline: string;
  defaultIndent: string;
};

const DIRECT_FIELDS: DirectField[] = ["dependencies", "devDependencies", "optionalDependencies"];

function severityToSarifLevel(level?: "low" | "medium" | "high" | "critical"): "none" | "note" | "warning" | "error" {
  if (!level) {
    return "warning";
  }
  if (level === "critical" || level === "high") {
    return "error";
  }
  if (level === "medium") {
    return "warning";
  }
  return "note";
}

function priorityProperties(priority: FindingPriority | undefined): Record<string, string | number> | undefined {
  if (!priority) {
    return undefined;
  }

  return {
    priority_level: priority.level,
    priority_reason: priority.reason,
    priority_score: priority.score
  };
}

function getRootObjectNode(sourceFile: ts.JsonSourceFile): ts.ObjectLiteralExpression | undefined {
  const statement = sourceFile.statements[0];
  if (!statement || !ts.isExpressionStatement(statement)) {
    return undefined;
  }

  return ts.isObjectLiteralExpression(statement.expression) ? statement.expression : undefined;
}

function detectDefaultIndent(text: string): string {
  const match = text.match(/\r?\n([ \t]+)"/);
  return match?.[1] ?? "  ";
}

function buildLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) {
      starts.push(i + 1);
    }
  }
  return starts;
}

function findLineIndex(lineStarts: number[], offset: number): number {
  let low = 0;
  let high = lineStarts.length - 1;

  while (low <= high) {
    const mid = (low + high) >> 1;
    if (lineStarts[mid] <= offset) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  return Math.max(0, high);
}

function offsetToLineColumn(lineStarts: number[], offset: number): { line: number; column: number } {
  const lineIndex = findLineIndex(lineStarts, offset);
  const lineStart = lineStarts[lineIndex] ?? 0;
  return {
    line: lineIndex + 1,
    column: offset - lineStart + 1
  };
}

function toSarifReplacement(context: JsonEditContext, edit: JsonEdit): SarifReplacement {
  const start = offsetToLineColumn(context.lineStarts, edit.start);
  const end = offsetToLineColumn(context.lineStarts, edit.end);
  return {
    deletedRegion: {
      startLine: start.line,
      startColumn: start.column,
      endLine: end.line,
      endColumn: end.column
    },
    insertedContent: {
      text: edit.newText
    }
  };
}

function indentAtOffset(context: JsonEditContext, offset: number): string {
  const lineIndex = findLineIndex(context.lineStarts, offset);
  const lineStart = context.lineStarts[lineIndex] ?? 0;
  let cursor = lineStart;
  while (cursor < context.text.length) {
    const char = context.text[cursor];
    if (char !== " " && char !== "\t") {
      break;
    }
    cursor += 1;
  }

  return context.text.slice(lineStart, cursor);
}

function renderJsonValue(value: unknown, context: JsonEditContext, propertyIndent: string): string {
  const serialized = JSON.stringify(value, null, context.defaultIndent);
  if (!serialized.includes("\n")) {
    return serialized;
  }

  return serialized.replace(/\n/g, `${context.newline}${propertyIndent}`);
}

function propertyNameAsText(name: ts.PropertyName): string | undefined {
  if (ts.isStringLiteral(name) || ts.isNumericLiteral(name) || ts.isIdentifier(name)) {
    return name.text;
  }
  return undefined;
}

function findProperty(objectNode: ts.ObjectLiteralExpression, key: string): ts.PropertyAssignment | undefined {
  for (const element of objectNode.properties) {
    if (!ts.isPropertyAssignment(element)) {
      continue;
    }
    if (propertyNameAsText(element.name) === key) {
      return element;
    }
  }
  return undefined;
}

function buildReplacePropertyInitializerEdit(
  context: JsonEditContext,
  property: ts.PropertyAssignment,
  value: unknown
): JsonEdit | undefined {
  const start = property.initializer.getStart(context.sourceFile);
  const end = property.initializer.getEnd();
  const propertyIndent = indentAtOffset(context, property.getStart(context.sourceFile));
  const nextText = renderJsonValue(value, context, propertyIndent);
  if (context.text.slice(start, end) === nextText) {
    return undefined;
  }

  return {
    start,
    end,
    newText: nextText
  };
}

function buildInsertPropertyEdit(
  context: JsonEditContext,
  objectNode: ts.ObjectLiteralExpression,
  key: string,
  value: unknown
): JsonEdit {
  const objectStart = objectNode.getStart(context.sourceFile);
  const baseIndent = indentAtOffset(context, objectStart);
  let propertyIndent = `${baseIndent}${context.defaultIndent}`;

  if (objectNode.properties.length > 0) {
    const firstProperty = objectNode.properties[0];
    propertyIndent = indentAtOffset(context, firstProperty.getStart(context.sourceFile));
  }

  const propertyText = `${JSON.stringify(key)}: ${renderJsonValue(value, context, propertyIndent)}`;

  if (objectNode.properties.length === 0) {
    const insertPos = objectStart + 1;
    return {
      start: insertPos,
      end: insertPos,
      newText: `${context.newline}${propertyIndent}${propertyText}${context.newline}${baseIndent}`
    };
  }

  const lastProperty = objectNode.properties[objectNode.properties.length - 1];
  const insertPos = lastProperty.getEnd();
  return {
    start: insertPos,
    end: insertPos,
    newText: `,${context.newline}${propertyIndent}${propertyText}`
  };
}

function buildNestedObject(pathSegments: string[], key: string, value: unknown): unknown {
  let nested: unknown = {
    [key]: value
  };

  for (let i = pathSegments.length - 1; i >= 0; i -= 1) {
    nested = {
      [pathSegments[i]]: nested
    };
  }

  return nested;
}

function setPropertyValueEdit(
  context: JsonEditContext,
  objectPath: string[],
  key: string,
  value: unknown
): JsonEdit | undefined {
  let currentObject = context.root;

  for (let pathIndex = 0; pathIndex < objectPath.length; pathIndex += 1) {
    const segment = objectPath[pathIndex];
    const property = findProperty(currentObject, segment);
    if (!property) {
      const nestedObject = buildNestedObject(objectPath.slice(pathIndex + 1), key, value);
      return buildInsertPropertyEdit(context, currentObject, segment, nestedObject);
    }

    if (!ts.isObjectLiteralExpression(property.initializer)) {
      const nestedObject = buildNestedObject(objectPath.slice(pathIndex + 1), key, value);
      return buildReplacePropertyInitializerEdit(context, property, nestedObject);
    }

    currentObject = property.initializer;
  }

  const targetProperty = findProperty(currentObject, key);
  if (!targetProperty) {
    return buildInsertPropertyEdit(context, currentObject, key, value);
  }

  return buildReplacePropertyInitializerEdit(context, targetProperty, value);
}

function buildDirectUpgradeEdit(context: JsonEditContext, operation: DirectUpgradeOperation): JsonEdit | undefined {
  const preferredFields: DirectField[] = [operation.depField, ...DIRECT_FIELDS.filter((field) => field !== operation.depField)];

  for (const field of preferredFields) {
    const fieldProperty = findProperty(context.root, field);
    if (!fieldProperty || !ts.isObjectLiteralExpression(fieldProperty.initializer)) {
      continue;
    }

    const packageProperty = findProperty(fieldProperty.initializer, operation.package);
    if (!packageProperty) {
      continue;
    }

    return buildReplacePropertyInitializerEdit(context, packageProperty, operation.toRange);
  }

  return undefined;
}

function buildNpmParentSpec(change: OverrideOperation["changes"][number]): string {
  if (change.scope === "global") {
    return "";
  }
  return change.scope.parentVersion ? `${change.scope.parent}@${change.scope.parentVersion}` : change.scope.parent;
}

function buildOverrideChangeEdit(
  context: JsonEditContext,
  operation: OverrideOperation,
  change: OverrideOperation["changes"][number]
): JsonEdit | undefined {
  if (operation.manager === "npm") {
    if (change.scope === "global") {
      return setPropertyValueEdit(context, ["overrides"], change.package, change.to);
    }

    const parentSpec = buildNpmParentSpec(change);
    const overridesProperty = findProperty(context.root, "overrides");

    if (!overridesProperty || !ts.isObjectLiteralExpression(overridesProperty.initializer)) {
      return setPropertyValueEdit(context, ["overrides"], parentSpec, { [change.package]: change.to });
    }

    const parentProperty = findProperty(overridesProperty.initializer, parentSpec);
    if (!parentProperty) {
      return setPropertyValueEdit(context, ["overrides"], parentSpec, { [change.package]: change.to });
    }

    if (ts.isObjectLiteralExpression(parentProperty.initializer)) {
      return setPropertyValueEdit(context, ["overrides", parentSpec], change.package, change.to);
    }

    if (ts.isStringLiteral(parentProperty.initializer)) {
      return buildReplacePropertyInitializerEdit(context, parentProperty, {
        ".": parentProperty.initializer.text,
        [change.package]: change.to
      });
    }

    return buildReplacePropertyInitializerEdit(context, parentProperty, { [change.package]: change.to });
  }

  const provider = getManifestOverrideProvider(operation.manager);
  const key =
    change.scope === "global"
      ? provider.buildOverrideKey({
          pkg: change.package
        })
      : provider.buildOverrideKey({
          pkg: change.package,
          scope: {
            parent: change.scope.parent,
            parentVersion: change.scope.parentVersion
          }
        });

  return setPropertyValueEdit(context, provider.getFieldPath(), key, change.to);
}

function createJsonEditContext(text: string): JsonEditContext | undefined {
  const sourceFile = ts.parseJsonText("package.json", text);
  const root = getRootObjectNode(sourceFile);
  if (!root) {
    return undefined;
  }

  return {
    text,
    sourceFile,
    root,
    lineStarts: buildLineStarts(text),
    newline: text.includes("\r\n") ? "\r\n" : "\n",
    defaultIndent: detectDefaultIndent(text)
  };
}

function buildReplacementByActionKey(
  remediationPlan?: RemediationPlan,
  projectRoot?: string
): Map<string, SarifReplacement[]> {
  const replacementByActionKey = new Map<string, SarifReplacement[]>();
  if (!remediationPlan || !projectRoot) {
    return replacementByActionKey;
  }

  const operationsByFile = new Map<string, ManifestOperation[]>();
  for (const operation of remediationPlan.operations) {
    if (operation.kind !== "manifest-direct-upgrade" && operation.kind !== "manifest-override") {
      continue;
    }

    const existing = operationsByFile.get(operation.file);
    if (!existing) {
      operationsByFile.set(operation.file, [operation]);
      continue;
    }
    existing.push(operation);
  }

  for (const [file, operations] of operationsByFile.entries()) {
    try {
      const absolutePath = path.join(projectRoot, file);
      const raw = fs.readFileSync(absolutePath, "utf8");
      const context = createJsonEditContext(raw);
      if (!context) {
        continue;
      }

      for (const operation of operations) {
        if (operation.kind === "manifest-direct-upgrade") {
          const edit = buildDirectUpgradeEdit(context, operation);
          if (!edit) {
            continue;
          }

          replacementByActionKey.set(remediationActionKeyForDirectOperation(operation.id), [toSarifReplacement(context, edit)]);
          continue;
        }

        for (const [changeIndex, change] of operation.changes.entries()) {
          const edit = buildOverrideChangeEdit(context, operation, change);
          if (!edit) {
            continue;
          }

          replacementByActionKey.set(remediationActionKeyForOverrideChange(operation.id, changeIndex), [
            toSarifReplacement(context, edit)
          ]);
        }
      }
    } catch {
      // Keep SARIF generation best-effort when files are missing/unreadable.
      continue;
    }
  }

  return replacementByActionKey;
}

function buildFix(description: string, file: string, replacements?: SarifReplacement[]): SarifFix | undefined {
  if (!replacements || replacements.length === 0) {
    return undefined;
  }

  return {
    description: {
      text: description
    },
    artifactChanges: [
      {
        artifactLocation: {
          uri: file
        },
        replacements
      }
    ]
  };
}

export function renderSarif(result: ScanResult, options: RenderSarifOptions = {}): string {
  const replacementByActionKey = buildReplacementByActionKey(options.remediationPlan, options.projectRoot);
  const actionsByFindingAndPackage = buildRemediationActionLookup(result, options.remediationPlan, {
    replacementByActionKey
  });
  const rules = result.findings.map((finding) => {
    const properties = priorityProperties(finding.priority);
    return {
      id: finding.vulnId,
      shortDescription: {
        text: finding.summary
      },
      helpUri: finding.references[0]?.url,
      ...(properties
        ? {
            properties
          }
        : {})
    };
  });

  const sarifResults = result.findings.flatMap((finding) =>
    finding.affected.map((affected) => {
      const key = remediationLookupKey(finding.vulnId, affected.package.name);
      const actions = actionsByFindingAndPackage.get(key);
      const properties = priorityProperties(finding.priority);
      const baseResult = {
        ruleId: finding.vulnId,
        level: severityToSarifLevel(findingHighestSeverityLevel(finding)),
        message: {
          text: `${affected.package.name}@${affected.package.version}`
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: affected.reachability?.evidences[0]?.file ?? "package-lock.json"
              },
              region: {
                startLine: affected.reachability?.evidences[0]?.line ?? 1,
                startColumn: affected.reachability?.evidences[0]?.column ?? 1
              }
            }
          }
        ],
        ...(properties
          ? {
              properties
            }
          : {})
      };

      if (!actions || actions.length === 0) {
        return baseResult;
      }

      const fixes = actions
        .map((action) => buildFix(action.description, action.file, action.replacements))
        .filter((fix): fix is SarifFix => Boolean(fix));
      if (fixes.length === 0) {
        return baseResult;
      }

      return {
        ...baseResult,
        fixes
      };
    })
  );

  const sarif = {
    version: "2.1.0",
    $schema: "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
    runs: [
      {
        tool: {
          driver: {
            name: result.meta.tool.name,
            version: result.meta.tool.version,
            rules
          }
        },
        results: sarifResults
      }
    ]
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}
