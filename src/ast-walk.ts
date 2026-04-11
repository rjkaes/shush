import { parse } from "unbash";
import type {
  Script, Statement, Node, Command, Pipeline, AndOr,
  CompoundList, Redirect,
  If, While, For, Case,
  ArithmeticFor, Select,
} from "unbash";
import type { Stage } from "./types.js";

/** Sentinel token replacing extracted process substitutions. */
export const PROCSUB_PLACEHOLDER = "__PROCSUB__";

/**
 * Extract >(cmd) and <(cmd) process substitutions from a command string.
 * Returns the cleaned command (with placeholders) and the inner command strings.
 * Respects single/double quoting so quoted parens are not extracted.
 */
export function extractProcessSubs(command: string): { cleaned: string; subs: string[] } {
  const subs: string[] = [];
  let result = "";
  let i = 0;

  while (i < command.length) {
    const ch = command[i];

    // Skip single-quoted strings
    if (ch === "'" ) {
      const end = command.indexOf("'", i + 1);
      if (end === -1) { result += command.slice(i); break; }
      result += command.slice(i, end + 1);
      i = end + 1;
      continue;
    }

    // Skip double-quoted strings (with backslash escaping)
    if (ch === '"') {
      let j = i + 1;
      while (j < command.length && command[j] !== '"') {
        if (command[j] === "\\" && j + 1 < command.length) j++;
        j++;
      }
      result += command.slice(i, j + 1);
      i = j + 1;
      continue;
    }

    // Detect >( or <(
    if ((ch === ">" || ch === "<") && command[i + 1] === "(") {
      let depth = 1;
      let j = i + 2;
      let pInSQ = false;
      let pInDQ = false;
      while (j < command.length && depth > 0) {
        const c = command[j];
        if (c === "'" && !pInDQ) { pInSQ = !pInSQ; }
        else if (c === '"' && !pInSQ) { pInDQ = !pInDQ; }
        else if (c === "\\" && !pInSQ) { j++; } // skip escaped char
        else if (!pInSQ && !pInDQ) {
          if (c === "(") depth++;
          else if (c === ")") depth--;
        }
        j++;
      }
      if (depth === 0) {
        const inner = command.slice(i + 2, j - 1);
        subs.push(inner);
        result += PROCSUB_PLACEHOLDER;
        i = j;
        continue;
      }
    }

    result += ch;
    i++;
  }

  return { cleaned: result, subs };
}

/**
 * Parse a bash command and extract flat pipeline stages.
 *
 * Command substitution inner strings ($(...) and backticks) are always
 * extracted for separate recursive classification by bash-guard.ts,
 * regardless of whether parsing succeeds.
 *
 * Falls back to simple token splitting when unbash reports parse errors.
 */
export function extractStages(command: string): { stages: Stage[]; cmdSubs: string[] } {
  if (!command.trim()) return { stages: [], cmdSubs: [] };

  // Extract command substitution inner strings for separate security
  // classification (bash-guard.ts classifies these recursively).
  // Guard: skip the char-by-char scan when no substitution markers are present.
  const cmdSubs = (command.includes("$(") || command.includes("`"))
    ? extractCommandSubs(command).subs
    : [];

  const ast = parse(command);
  if (ast.errors?.length) {
    return { stages: fallbackSplit(command), cmdSubs };
  }

  return { stages: walkScript(ast), cmdSubs };
}

/**
 * Extract $(...) command substitutions from a command string.
 * Returns the cleaned command (with $__SHUSH_CMD_n variable placeholders)
 * and the inner command strings. Respects quoting: substitutions inside
 * single quotes are left alone (they're literal text in bash).
 */
export function extractCommandSubs(command: string): { cleaned: string; subs: string[] } {
  const subs: string[] = [];
  let result = "";
  let i = 0;

  while (i < command.length) {
    const ch = command[i];

    // Skip single-quoted strings (no substitutions inside)
    if (ch === "'") {
      const end = command.indexOf("'", i + 1);
      if (end === -1) { result += command.slice(i); break; }
      result += command.slice(i, end + 1);
      i = end + 1;
      continue;
    }

    // Track double-quoted strings but continue scanning inside them
    // (command substitutions ARE expanded inside double quotes)
    if (ch === "\\" && i + 1 < command.length) {
      result += command.slice(i, i + 2);
      i += 2;
      continue;
    }

    // Heredoc: skip the body so cmdsubs inside it are not extracted at the
    // top level. Quoted delimiters (<<'EOF' or <<"EOF") suppress expansion
    // in real bash, so cmdsubs in those bodies are literal text. Unquoted
    // heredocs DO expand, so we only skip extraction for quoted delimiters.
    if (ch === "<" && command[i + 1] === "<" && command[i + 2] !== "<") {
      const hm = command.slice(i).match(/^<<[-~]?\s*(['"]?)(\w+)\1/);
      if (hm) {
        const isQuoted = hm[1] !== "";
        const delim = hm[2];
        const afterHeader = i + hm[0].length;
        // Find the end of the heredoc body (delimiter on its own line)
        const rest = command.slice(afterHeader);
        const dm = rest.match(new RegExp(`\n\\t*${delim}[ \\t]*(?:\n|$)`));
        if (dm != null && dm.index != null) {
          const bodyEnd = afterHeader + dm.index + dm[0].length;
          if (isQuoted) {
            // Quoted heredoc: skip the entire body without extracting cmdsubs
            result += command.slice(i, bodyEnd);
            i = bodyEnd;
          } else {
            // Unquoted heredoc: just skip the operator and delimiter line,
            // continue scanning the body so cmdsubs inside are extracted
            result += command.slice(i, afterHeader);
            i = afterHeader;
          }
          continue;
        }
      }
    }

    // Detect $( - start of command substitution (but not $(( arithmetic))
    if (ch === "$" && command[i + 1] === "(" && command[i + 2] !== "(") {
      let depth = 1;
      let j = i + 2;
      let inSQ = false;
      let inDQ = false;

      while (j < command.length && depth > 0) {
        const c = command[j];
        if (c === "'" && !inDQ) { inSQ = !inSQ; }
        else if (c === '"' && !inSQ) { inDQ = !inDQ; }
        else if (c === "\\" && !inSQ) { j++; }  // skip escaped char
        else if (!inSQ && !inDQ) {
          if (c === "(" && command[j - 1] === "$") depth++;
          else if (c === "(") depth++;  // arithmetic $(( )) or nested
          else if (c === ")") depth--;
          // Heredoc: skip the body so that quotes and parens inside it
          // do not corrupt the depth/quote tracking.  Without this,
          // an apostrophe in the body (e.g. "endpoint's") opens
          // single-quote mode permanently and the closing ) is missed.
          else if (c === "<" && command[j + 1] === "<") {
            const hm = command.slice(j).match(/^<<[-~]?\s*['"]?(\w+)['"]?/);
            if (hm) {
              const delim = hm[1];
              const after = command.slice(j + hm[0].length);
              const dm = after.match(new RegExp(`\n\\t*${delim}[ \\t]*(?:\n|$)`));
              if (dm != null && dm.index != null) {
                j = j + hm[0].length + dm.index + dm[0].length;
                continue;
              }
            }
          }
        }
        j++;
      }

      if (depth === 0) {
        const inner = command.slice(i + 2, j - 1);
        // Safety net: if the depth tracker matched parens but the body
        // contains a heredoc marker, skip extraction.  The tracker above
        // skips heredoc bodies, but this catches edge cases.
        if (/<<[-~]?\s*['"]?\w/.test(inner)) {
          result += command.slice(i, j);
          i = j;
          continue;
        }
        subs.push(inner);
        result += `$__SHUSH_CMD_${subs.length - 1}`;
        i = j;
        continue;
      }
    }

    // Detect backtick command substitution
    if (ch === "`") {
      let j = i + 1;
      while (j < command.length && command[j] !== "`") {
        if (command[j] === "\\") j++;  // skip escaped char
        j++;
      }
      if (j < command.length) {
        const inner = command.slice(i + 1, j);
        subs.push(inner);
        result += `$__SHUSH_CMD_${subs.length - 1}`;
        i = j + 1;
        continue;
      }
    }

    result += ch;
    i++;
  }

  return { cleaned: result, subs };
}

// ==============================================================================
// AST Walking
// ==============================================================================

function walkScript(ast: Script): Stage[] {
  if (!ast.commands.length) return [];

  const stages: Stage[] = [];
  for (let i = 0; i < ast.commands.length; i++) {
    const isLast = i === ast.commands.length - 1;
    stages.push(...walkStatement(ast.commands[i], isLast ? "" : ";"));
  }
  return stages;
}

/** Unwrap a Statement node and dispatch on its inner command. */
function walkStatement(stmt: Statement, trailingOp: string): Stage[] {
  return walkNode(stmt.command, trailingOp, stmt.redirects);
}

function walkNode(node: Node, trailingOp: string, stmtRedirects?: Redirect[]): Stage[] {
  switch (node.type) {
    case "Command":
      return [commandToStage(node, trailingOp, stmtRedirects)];

    case "Pipeline":
      return walkPipeline(node, trailingOp);

    case "AndOr":
      return walkAndOr(node, trailingOp);

    case "Subshell":
      return walkCompoundList(node.body, trailingOp);

    case "BraceGroup":
      return walkCompoundList(node.body, trailingOp);

    case "If":
      return walkIf(node, trailingOp);

    case "While":
      return walkWhile(node, trailingOp);

    case "For":
    case "ArithmeticFor":
    case "Select":
      return walkLoop(node, trailingOp);

    case "Case":
      return walkCase(node, trailingOp);

    case "Function":
      return walkNode(node.body, trailingOp);

    case "Coproc":
      return walkNode(node.body, trailingOp);

    case "CompoundList":
      return walkCompoundList(node, trailingOp);

    case "Statement":
      return walkStatement(node, trailingOp);

    default:
      return [];
  }
}

function walkPipeline(node: Pipeline, trailingOp: string): Stage[] {
  const stages: Stage[] = [];
  for (let i = 0; i < node.commands.length; i++) {
    const isLast = i === node.commands.length - 1;
    const op = isLast ? trailingOp : "|";
    stages.push(...walkNode(node.commands[i], op));
  }
  return stages;
}

/** AndOr uses a flat commands[] + operators[] instead of binary left/right. */
function walkAndOr(node: AndOr, trailingOp: string): Stage[] {
  const stages: Stage[] = [];
  for (let i = 0; i < node.commands.length; i++) {
    const isLast = i === node.commands.length - 1;
    const op = isLast ? trailingOp : node.operators[i];
    stages.push(...walkNode(node.commands[i], op));
  }
  return stages;
}

function walkCompoundList(node: CompoundList, trailingOp: string): Stage[] {
  if (!node.commands.length) return [];

  const stages: Stage[] = [];
  for (let i = 0; i < node.commands.length; i++) {
    const isLast = i === node.commands.length - 1;
    stages.push(...walkStatement(node.commands[i], isLast ? trailingOp : ";"));
  }
  return stages;
}

function walkIf(node: If, trailingOp: string): Stage[] {
  const stages: Stage[] = [];
  stages.push(...walkCompoundList(node.clause, ""));
  stages.push(...walkCompoundList(node.then, ""));
  if (node.else) {
    if (node.else.type === "If") {
      stages.push(...walkIf(node.else, ""));
    } else {
      stages.push(...walkCompoundList(node.else, ""));
    }
  }
  if (stages.length > 0 && trailingOp) {
    stages[stages.length - 1].operator = trailingOp;
  }
  return stages;
}

function walkWhile(node: While, trailingOp: string): Stage[] {
  const stages: Stage[] = [];
  stages.push(...walkCompoundList(node.clause, ""));
  stages.push(...walkCompoundList(node.body, ""));
  if (stages.length > 0 && trailingOp) {
    stages[stages.length - 1].operator = trailingOp;
  }
  return stages;
}

function walkLoop(node: For | ArithmeticFor | Select, trailingOp: string): Stage[] {
  const stages = walkCompoundList(node.body, "");
  if (stages.length > 0 && trailingOp) {
    stages[stages.length - 1].operator = trailingOp;
  }
  return stages;
}

function walkCase(node: Case, trailingOp: string): Stage[] {
  const stages: Stage[] = [];
  for (const item of node.items) {
    stages.push(...walkCompoundList(item.body, ""));
  }
  if (stages.length > 0 && trailingOp) {
    stages[stages.length - 1].operator = trailingOp;
  }
  return stages;
}

// ==============================================================================
// Command → Stage conversion
// ==============================================================================

function commandToStage(node: Command, operator: string, stmtRedirects?: Redirect[]): Stage {
  const tokens: string[] = [];
  const envAssignments: string[] = [];
  let redirectTarget: string | undefined;
  let redirectAppend: boolean | undefined;

  // Extract command name (use .value for unquoted content)
  if (node.name) {
    tokens.push(node.name.value);
  }

  // Extract prefix assignments (e.g., FOO=bar cmd)
  // Use .text here to preserve the raw KEY=value form
  for (const a of node.prefix) {
    if (a.text) {
      envAssignments.push(a.text);
    }
  }

  // Extract suffix (arguments; .value gives unquoted content)
  for (const s of node.suffix) {
    tokens.push(s.value);
  }

  // Extract redirects from Command node and parent Statement.
  // Skip operators that don't write to real files:
  //   >&, <&  — fd duplication (e.g. 2>&1)
  //   <<, <<- — heredocs (input, not file writes)
  const allRedirects = [...node.redirects, ...(stmtRedirects ?? [])];
  for (const r of allRedirects) {
    if (r.target && r.operator !== ">&" && r.operator !== "<&"
        && r.operator !== "<<" && r.operator !== "<<-") {
      redirectTarget = r.target.value;
      redirectAppend = r.operator === ">>";
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

// ==============================================================================
// Fallback (when parser reports errors)
// ==============================================================================

/**
 * Fallback when the parser reports errors: split on shell metacharacters.
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

/**
 * Pull > / >> and their target out of a raw token list.
 * Fd-duplication redirects (N>&M, N<&M, >&N) are stripped without
 * setting redirectTarget because they don't write to files.
 */
function extractRedirectFromTokens(tokens: string[]): {
  tokens: string[];
  redirectTarget?: string;
  redirectAppend?: boolean;
} {
  const clean: string[] = [];
  let redirectTarget: string | undefined;
  let redirectAppend: boolean | undefined;

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    // Fd-duplication: 2>&1, >&2, <&3, etc. — strip without setting redirectTarget.
    // Matches tokens like "2>&1", ">&2", "2<&-" as a single fused token.
    if (/^\d*[<>]&\S+$/.test(tok)) {
      continue;
    }
    // Split redirect operators: 2>&, >&  followed by a separate target token
    if (/^\d*[<>]&$/.test(tok) && i + 1 < tokens.length) {
      i++; // skip target
      continue;
    }
    if (tok === ">>" && i + 1 < tokens.length) {
      redirectTarget = tokens[i + 1];
      redirectAppend = true;
      i++; // skip target
    } else if (tok === ">" && i + 1 < tokens.length) {
      redirectTarget = tokens[i + 1];
      redirectAppend = false;
      i++; // skip target
    } else {
      clean.push(tok);
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
      // Single | or ; or & (background).  Skip & when preceded by > or <
      // because >& and <& are fd-duplication redirects, not background ops.
      if (ch === "|" || ch === ";") {
        results.push({ text: current, operator: ch });
        current = "";
        continue;
      }
      if (ch === "&" && !current.endsWith(">") && !current.endsWith("<")) {
        results.push({ text: current, operator: ";" });
        current = "";
        continue;
      }
    }

    current += ch;
  }

  results.push({ text: current, operator: "" });
  return results;
}
