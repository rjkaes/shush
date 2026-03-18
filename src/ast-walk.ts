import parse from "bash-parser";
import type { Stage } from "./types.js";

// AST node type aliases (bash-parser doesn't export types)
interface AstNode {
  type: string;
  [key: string]: unknown;
}

/**
 * Parse a bash command and extract flat pipeline stages.
 * Falls back to simple splitting when bash-parser can't handle the syntax.
 */
export function extractStages(command: string): Stage[] {
  if (!command.trim()) return [];

  try {
    const ast = parse(command, { mode: "bash" });
    return walkScript(ast);
  } catch {
    return fallbackSplit(command);
  }
}

function walkScript(ast: AstNode): Stage[] {
  const commands = ast.commands as AstNode[] | undefined;
  if (!commands?.length) return [];

  const stages: Stage[] = [];
  for (let i = 0; i < commands.length; i++) {
    const isLast = i === commands.length - 1;
    stages.push(...walkNode(commands[i], isLast ? "" : ";"));
  }
  return stages;
}

function walkNode(node: AstNode, trailingOp: string): Stage[] {
  switch (node.type) {
    case "Command":
      return [commandToStage(node, trailingOp)];

    case "Pipeline":
      return walkPipeline(node, trailingOp);

    case "LogicalExpression":
      return walkLogical(node, trailingOp);

    case "Subshell":
      return walkCompoundList(
        (node.list as AstNode) ?? node,
        trailingOp,
      );

    case "If":
    case "While":
    case "Until":
    case "For":
    case "Case":
      return walkControlFlow(node, trailingOp);

    case "Function":
      return walkCompoundList(
        (node.body as AstNode) ?? node,
        trailingOp,
      );

    case "CompoundList":
      return walkCompoundList(node, trailingOp);

    default:
      return [];
  }
}

function walkPipeline(node: AstNode, trailingOp: string): Stage[] {
  const commands = node.commands as AstNode[];
  if (!commands?.length) return [];

  const stages: Stage[] = [];
  for (let i = 0; i < commands.length; i++) {
    const isLast = i === commands.length - 1;
    const op = isLast ? trailingOp : "|";
    stages.push(...walkNode(commands[i], op));
  }
  return stages;
}

function walkLogical(node: AstNode, trailingOp: string): Stage[] {
  const op = (node.op as string) === "and" ? "&&" : "||";
  const leftStages = walkNode(node.left as AstNode, op);
  const rightStages = walkNode(node.right as AstNode, trailingOp);
  return [...leftStages, ...rightStages];
}

function walkCompoundList(node: AstNode, trailingOp: string): Stage[] {
  const commands = node.commands as AstNode[] | undefined;
  if (!commands?.length) return [];

  const stages: Stage[] = [];
  for (let i = 0; i < commands.length; i++) {
    const isLast = i === commands.length - 1;
    stages.push(...walkNode(commands[i], isLast ? trailingOp : ";"));
  }
  return stages;
}

function walkControlFlow(node: AstNode, trailingOp: string): Stage[] {
  // Extract stages from all compound lists in control flow nodes
  const stages: Stage[] = [];
  for (const key of ["clause", "then", "else", "do", "cases"]) {
    const child = node[key];
    if (!child) continue;
    if (Array.isArray(child)) {
      // Case items
      for (const item of child) {
        if ((item as AstNode).body) {
          stages.push(...walkCompoundList((item as AstNode).body as AstNode, ""));
        }
      }
    } else if (typeof child === "object" && (child as AstNode).type) {
      stages.push(...walkNode(child as AstNode, ""));
    }
  }
  // Tag the last stage with the trailing operator
  if (stages.length > 0 && trailingOp) {
    stages[stages.length - 1].operator = trailingOp;
  }
  return stages;
}

function commandToStage(node: AstNode, operator: string): Stage {
  const tokens: string[] = [];
  const envAssignments: string[] = [];
  let redirectTarget: string | undefined;
  let redirectAppend: boolean | undefined;

  // Extract command name
  const name = node.name as AstNode | undefined;
  if (name?.text) {
    tokens.push(name.text as string);
  }

  // Extract prefix: collect env assignments and redirects
  const prefix = node.prefix as AstNode[] | undefined;
  if (prefix) {
    for (const p of prefix) {
      if (p.type === "Redirect") {
        const file = p.file as AstNode | undefined;
        if (file?.text) {
          const opText = (p.op as AstNode)?.text as string | undefined;
          redirectTarget = file.text as string;
          redirectAppend = opText === ">>";
        }
      } else if (p.type === "AssignmentWord" && p.text) {
        envAssignments.push(p.text as string);
      }
    }
  }

  // Extract suffix: Word nodes become args, Redirect nodes capture targets
  const suffix = node.suffix as AstNode[] | undefined;
  if (suffix) {
    for (const s of suffix) {
      if (s.type === "Word") {
        tokens.push(s.text as string);
      } else if (s.type === "Redirect") {
        const file = s.file as AstNode | undefined;
        if (file?.text) {
          const opText = (s.op as AstNode)?.text as string | undefined;
          redirectTarget = file.text as string;
          redirectAppend = opText === ">>";
        }
      }
    }
  }

  return {
    tokens,
    operator,
    redirectTarget,
    redirectAppend,
    ...(envAssignments.length > 0 ? { envAssignments } : {}),
  };
}

/**
 * Fallback when bash-parser fails: split on shell metacharacters.
 * Handles basic pipes, &&, ||, ; splitting while respecting quotes.
 */
function fallbackSplit(command: string): Stage[] {
  const stages: Stage[] = [];
  // Split on unquoted operators, respecting single and double quotes
  const segments = splitOnUnquotedOperators(command);

  for (const { text, operator } of segments) {
    const trimmed = text.trim();
    if (trimmed) {
      const allTokens = trimmed.split(/\s+/);
      const { tokens, redirectTarget, redirectAppend } = extractRedirectFromTokens(allTokens);
      stages.push({ tokens, operator, redirectTarget, redirectAppend });
    }
  }
  return stages;
}

/** Pull > / >> and their target out of a raw token list. */
function extractRedirectFromTokens(tokens: string[]): {
  tokens: string[];
  redirectTarget?: string;
  redirectAppend?: boolean;
} {
  const clean: string[] = [];
  let redirectTarget: string | undefined;
  let redirectAppend: boolean | undefined;

  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i] === ">>" && i + 1 < tokens.length) {
      redirectTarget = tokens[i + 1];
      redirectAppend = true;
      i++; // skip target
    } else if (tokens[i] === ">" && i + 1 < tokens.length) {
      redirectTarget = tokens[i + 1];
      redirectAppend = false;
      i++; // skip target
    } else {
      clean.push(tokens[i]);
    }
  }

  return { tokens: clean, redirectTarget, redirectAppend };
}

/** Split command on |, &&, ||, ; that are outside quotes. */
function splitOnUnquotedOperators(command: string): Array<{ text: string; operator: string }> {
  const results: Array<{ text: string; operator: string }> = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < command.length; i++) {
    const ch = command[i];

    // Track quote state
    if (ch === "'" && !inDouble) { inSingle = !inSingle; current += ch; continue; }
    if (ch === '"' && !inSingle) { inDouble = !inDouble; current += ch; continue; }
    if (ch === "\\" && !inSingle) { current += ch + (command[i + 1] ?? ""); i++; continue; }

    // Only split when outside quotes
    if (!inSingle && !inDouble) {
      // Check for || and &&
      if ((ch === "|" || ch === "&") && command[i + 1] === ch) {
        const op = ch + ch;
        results.push({ text: current, operator: op });
        current = "";
        i++; // skip second char
        continue;
      }
      // Single | or ;
      if (ch === "|" || ch === ";") {
        results.push({ text: current, operator: ch });
        current = "";
        continue;
      }
    }

    current += ch;
  }

  results.push({ text: current, operator: "" });
  return results;
}
