import {
  type ActionType, type Decision, type ShushConfig, type ClassifyEntry,
  isActionType, cmdBasename, normalizeVersionedCmd,
} from "./types.js";
import ACTION_TYPES from "../data/types.json";
import DEFAULT_POLICIES_JSON from "../data/policies.json";
import classifyTrieJSON from "../data/classifier-trie.json";

// Derive constants from the JSON keys for use throughout the codebase.
// The return type is ActionType, enforced at compile time.
const t = <K extends ActionType>(key: K): K => key;
export const FILESYSTEM_READ = t("filesystem_read");
export const FILESYSTEM_WRITE = t("filesystem_write");
export const FILESYSTEM_DELETE = t("filesystem_delete");
export const GIT_SAFE = t("git_safe");
export const GIT_WRITE = t("git_write");
export const GIT_DISCARD = t("git_discard");
export const GIT_HISTORY_REWRITE = t("git_history_rewrite");
export const NETWORK_OUTBOUND = t("network_outbound");
export const NETWORK_WRITE = t("network_write");
export const NETWORK_DIAGNOSTIC = t("network_diagnostic");
export const PACKAGE_INSTALL = t("package_install");
export const PACKAGE_RUN = t("package_run");
export const PACKAGE_UNINSTALL = t("package_uninstall");
export const SCRIPT_EXEC = t("script_exec");
export const LANG_EXEC = t("lang_exec");
export const PROCESS_SIGNAL = t("process_signal");
export const CONTAINER_DESTRUCTIVE = t("container_destructive");
export const DISK_DESTRUCTIVE = t("disk_destructive");
export const DB_READ = t("db_read");
export const DB_WRITE = t("db_write");
export const OBFUSCATED = t("obfuscated");
export const UNKNOWN = t("unknown");

// Default policies loaded from data/policies.json
export const DEFAULT_POLICIES: Record<ActionType, Decision> = DEFAULT_POLICIES_JSON as Record<ActionType, Decision>;

// ==============================================================================
// Prefix Trie (pre-built at build time by scripts/build-trie.ts)
// ==============================================================================

// PrefixEntry is the on-disk authoring format (per-type JSON files). Kept as
// an export for tests that pass ad-hoc tables to prefixMatch.
export interface PrefixEntry {
  prefix: string[];
  actionType: ActionType;
}

// Trie node shape matches the JSON: keys are tokens, "_" holds the action type,
// "_p" holds the pathArgs indices (omitted when empty).
interface TrieNode {
  [key: string]: TrieNode | string | number[] | undefined;
  _?: string;
  _p?: number[];
}

/** Walk the trie, returning the deepest (longest-prefix) action found. */
function trieLookup(root: TrieNode, tokens: string[]): ActionType {
  let node = root;
  let bestAction: ActionType = UNKNOWN;
  for (const token of tokens) {
    const child = node[token];
    if (!child || typeof child === "string" || Array.isArray(child)) break;
    if (child._ !== undefined) bestAction = child._ as ActionType;
    node = child;
  }
  return bestAction;
}

/** Walk the trie, returning action type and pathArgs for the deepest match. */
function trieLookupFull(
  root: TrieNode,
  tokens: string[],
): { actionType: ActionType; pathArgs: readonly number[] } {
  let node = root;
  let bestAction: ActionType = UNKNOWN;
  let bestPathArgs: readonly number[] = [];
  for (const token of tokens) {
    const child = node[token];
    if (!child || typeof child === "string" || Array.isArray(child)) break;
    if (child._ !== undefined) {
      bestAction = child._ as ActionType;
      bestPathArgs = Array.isArray(child._p) ? child._p : [];
    }
    node = child;
  }
  return { actionType: bestAction, pathArgs: bestPathArgs };
}

const classifyTrie: TrieNode = classifyTrieJSON as unknown as TrieNode;

/** Longest-prefix match. Uses the trie for the built-in table; falls back to
 *  linear scan for ad-hoc tables passed from tests. */
export function prefixMatch(
  tokens: string[],
  table?: PrefixEntry[],
): ActionType {
  // Fast path: built-in trie lookup, O(prefix depth).
  if (!table) return trieLookup(classifyTrie, tokens);

  // Slow path: ad-hoc table from tests.
  const sorted = [...table].sort((a, b) => b.prefix.length - a.prefix.length);
  for (const entry of sorted) {
    if (tokens.length >= entry.prefix.length) {
      let match = true;
      for (let i = 0; i < entry.prefix.length; i++) {
        if (tokens[i] !== entry.prefix[i]) {
          match = false;
          break;
        }
      }
      if (match) return entry.actionType;
    }
  }
  return UNKNOWN;
}

/** Get the policy for an action type. If config specifies a policy for this
 *  action type, it wins unconditionally; otherwise falls back to the hardcoded
 *  default from policies.json. Callers trust that loadConfig() has already
 *  prevented untrusted (project) config from loosening policies. */
export function getPolicy(actionType: string, config?: ShushConfig): Decision {
  if (config?.actions[actionType]) return config.actions[actionType];
  return (DEFAULT_POLICIES as Record<string, Decision>)[actionType] ?? "ask";
}

// Shell wrappers that need unwrapping
export const SHELL_WRAPPERS = new Set(["bash", "sh", "dash", "zsh", "pwsh", "powershell"]);

// Exec sinks for pipe composition
export const EXEC_SINKS = new Set([
  "bash", "sh", "dash", "zsh", "eval", "python", "python3",
  "node", "ruby", "perl", "php", "bun", "deno", "fish", "pwsh", "powershell",
]);

/** Check if a command name is a shell wrapper, with versioned normalization. */
export function isShellWrapper(cmd: string): boolean {
  return SHELL_WRAPPERS.has(cmd) || SHELL_WRAPPERS.has(normalizeVersionedCmd(cmd));
}

/** Check if a command name is an exec sink, with versioned normalization. */
export function isExecSink(cmd: string): boolean {
  return EXEC_SINKS.has(cmd) || EXEC_SINKS.has(normalizeVersionedCmd(cmd));
}

// Decode commands for pipe composition: [command, flag | null]
export const DECODE_COMMANDS: Array<[string, string | null]> = [
  ["base64", "-d"],
  ["base64", "--decode"],
  ["xxd", "-r"],
  ["uudecode", null],
];

// Cache for config classify pattern splits (avoids re-splitting per stage).
const splitCache = new Map<string, string[]>();
function classifySplitCache(pattern: string): string[] {
  let tokens = splitCache.get(pattern);
  if (!tokens) {
    tokens = pattern.split(/\s+/);
    splitCache.set(pattern, tokens);
  }
  return tokens;
}

/** Normalize /usr/bin/rm -> rm, then prefix-match against built-in trie. */
export function classifyTokens(tokens: string[], config?: ShushConfig): string {
  if (tokens.length === 0) return UNKNOWN;

  // Basename normalization
  const base = cmdBasename(tokens[0]);
  const normalized = base !== tokens[0] ? [base, ...tokens.slice(1)] : tokens;

  // Check config classify entries first (user-defined prefixes).
  // Patterns are pre-split at config load time via classifyTokenized.
  if (config) {
    for (const [actionType, patterns] of Object.entries(config.classify)) {
      for (const pattern of patterns) {
        const prefixTokens = classifySplitCache(pattern);
        if (normalized.length >= prefixTokens.length) {
          let match = true;
          for (let i = 0; i < prefixTokens.length; i++) {
            if (normalized[i] !== prefixTokens[i]) {
              match = false;
              break;
            }
          }
          if (match) return actionType;
        }
      }
    }
  }

  return prefixMatch(normalized);
}

/** Like classifyTokens but also returns pathArgs from the trie terminal.
 *  Config classify entries carry no pathArgs (returns []). */
export function classifyTokensFull(
  tokens: string[],
  config?: ShushConfig,
): { actionType: string; pathArgs: readonly number[] } {
  if (tokens.length === 0) return { actionType: UNKNOWN, pathArgs: [] };

  const base = cmdBasename(tokens[0]);
  const normalized = base !== tokens[0] ? [base, ...tokens.slice(1)] : tokens;

  // Config entries take priority but carry no pathArgs annotation.
  if (config) {
    for (const [actionType, patterns] of Object.entries(config.classify)) {
      for (const pattern of patterns) {
        const prefixTokens = classifySplitCache(pattern);
        if (normalized.length >= prefixTokens.length) {
          let match = true;
          for (let i = 0; i < prefixTokens.length; i++) {
            if (normalized[i] !== prefixTokens[i]) { match = false; break; }
          }
          if (match) return { actionType, pathArgs: [] };
        }
      }
    }
  }

  return trieLookupFull(classifyTrie, normalized);
}

// ==============================================================================
// parseClassifyEntry: validates the authoring format for classify JSON files
// ==============================================================================

/**
 * Parse and validate a raw classify entry from a command JSON file.
 * Accepts either:
 *   - bare array form: `["cmd", "sub"]`  (pathArgs defaults to [])
 *   - object form:     `{ prefix: ["cmd", "sub"], pathArgs: [2] }`
 */
export function parseClassifyEntry(raw: unknown): ClassifyEntry {
  if (Array.isArray(raw)) {
    if (!raw.every((t) => typeof t === "string")) {
      throw new Error(`classify entry: prefix tokens must be strings`);
    }
    return { prefix: raw as string[], pathArgs: [] };
  }
  if (raw === null || typeof raw !== "object") {
    throw new Error(`classify entry: must be array or object, got ${typeof raw}`);
  }
  const allowed = new Set(["prefix", "pathArgs"]);
  for (const k of Object.keys(raw as object)) {
    if (!allowed.has(k)) throw new Error(`classify entry: unknown field "${k}"`);
  }
  const obj = raw as { prefix?: unknown; pathArgs?: unknown };
  if (!Array.isArray(obj.prefix) || !obj.prefix.every((t) => typeof t === "string")) {
    throw new Error(`classify entry: prefix must be array of strings`);
  }
  const args = obj.pathArgs ?? [];
  if (!Array.isArray(args)) throw new Error(`classify entry: pathArgs must be array`);
  for (const n of args as unknown[]) {
    if (typeof n !== "number" || !Number.isInteger(n)) {
      throw new Error(`classify entry: pathArgs must contain integer indices`);
    }
  }
  const seen = new Set<number>();
  for (const n of args as number[]) {
    if (seen.has(n)) throw new Error(`classify entry: duplicate pathArgs index ${n}`);
    seen.add(n);
  }
  return { prefix: obj.prefix as string[], pathArgs: args as number[] };
}
