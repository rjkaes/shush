// src/classifiers/index.ts
//
// Classifier registry. Maps command names to ordered lists of
// classifier functions. lookup() iterates the list, returning
// the first non-null result.

import { classifyGit, checkDangerousGitConfig, stripGitGlobalFlags } from "./git.js";
import { checkFlagRules } from "../flag-rules.js";
import { cmdBasename } from "../types.js";
import { INLINE_CODE_CMDS } from "./inline-code.js";
import { classifyGhApi } from "./gh-api.js";
import { classifyTar } from "./tar.js";
import { classifyFind } from "./find.js";
import { classifyCurl } from "./curl.js";
import { classifyWget } from "./wget.js";
import { classifyHttpie } from "./httpie.js";
import { classifyTee } from "./tee.js";
import { classifyInlineCode } from "./inline-code.js";
import { classifyScriptExec } from "./script-exec.js";

export type Classifier = (tokens: string[]) => string | null;

const REGISTRY: Map<string, Classifier[]> = new Map();

/** Register classifiers for a command. */
export function register(command: string, classifiers: Classifier[]): void {
  REGISTRY.set(command, classifiers);
}

/** Register a single classifier for multiple command names. */
export function registerMany(commands: string[], classifier: Classifier): void {
  for (const cmd of commands) {
    const existing = REGISTRY.get(cmd) ?? [];
    existing.push(classifier);
    REGISTRY.set(cmd, existing);
  }
}

/**
 * Look up classifiers for a command and run them in order.
 * Returns the first non-null result, or null if none match.
 */
export function lookup(command: string, tokens: string[]): string | null {
  const classifiers = REGISTRY.get(command);
  if (!classifiers) return null;

  for (const classifier of classifiers) {
    const result = classifier(tokens);
    if (result !== null) return result;
  }
  return null;
}

// ==============================================================================
// Classifier Registrations
// ==============================================================================

// sed without -i is a pure stream filter (reads stdin, writes stdout).
// Flag rules handle -i -> filesystem_write; this provides the default.
function classifySedDefault(_tokens: string[]): string | null {
  return "filesystem_read";
}

function registerAll(): void {
  // Procedural classifiers (stateful/complex logic)
  register("git", [classifyGit]);
  register("gh", [classifyGhApi]);
  register("tar", [classifyTar]);
  register("find", [classifyFind]);
  register("curl", [classifyCurl]);
  register("wget", [classifyWget]);
  register("tee", [classifyTee]);
  register("sed", [classifySedDefault]);
  registerMany(["http", "https", "xh", "xhs"], classifyHttpie);

  // Inline code: python, node, ruby get inline-code directly
  registerMany(["python", "python3", "node", "ruby"], classifyInlineCode);

  // bun: global-install handled by flag rules (data/flag_rules/bun.json),
  // inline-code fallback for bun -e
  registerMany(["bun"], classifyInlineCode);
}

registerAll();

/** Reset registry for testing, then re-register production classifiers. */
export function resetForTest(): void {
  REGISTRY.clear();
  registerAll();
}

// ==============================================================================
// Compatibility: classifyWithFlags
// ==============================================================================

/**
 * Combined classifier pipeline: basename normalize -> dangerous git config ->
 * strip git flags -> flag rules -> registry -> inline-code fallback.
 * Used by tests; bash-guard.ts calls these steps individually.
 */
export function classifyWithFlags(tokens: string[]): string | null {
  if (!tokens.length) return null;

  // Basename normalization: /usr/bin/curl -> curl
  let normalized = tokens;
  if (tokens[0].includes("/")) {
    normalized = [cmdBasename(tokens[0]), ...tokens.slice(1)];
  }

  // Git: check for dangerous -c config keys (before stripping them)
  if (normalized[0] === "git") {
    const dangerousConfig = checkDangerousGitConfig(normalized);
    if (dangerousConfig) return dangerousConfig;
    normalized = stripGitGlobalFlags(normalized);
  }

  // Flag rules (data-driven)
  const flagResult = checkFlagRules(normalized[0], normalized);
  if (flagResult) return flagResult;

  // Registry lookup
  const result = lookup(normalized[0], normalized);
  if (result !== null) return result;

  // Fallback: try inlineCode for commands in INLINE_CODE_CMDS
  if (normalized[0] in INLINE_CODE_CMDS) {
    return classifyInlineCode(normalized);
  }
  return null;
}

// Re-exports for bash-guard.ts
export { checkDangerousGitConfig } from "./git.js";
export { stripGitGlobalFlags, extractGitDirPaths } from "./git.js";
export { classifyScriptExec } from "./script-exec.js";
