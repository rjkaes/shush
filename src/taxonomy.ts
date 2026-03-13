import { readdirSync, readFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { type Decision, type ShushConfig, stricter } from "./types.js";

const DATA_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "data");

// Action types loaded from data/types.json (keys are the type identifiers).
const ACTION_TYPES: Record<string, string> = JSON.parse(
  readFileSync(resolve(DATA_DIR, "types.json"), "utf-8"),
);

// Derive constants from the JSON keys for use throughout the codebase.
const t = (key: string): string => {
  if (!(key in ACTION_TYPES)) throw new Error(`Unknown action type: ${key}`);
  return key;
};
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
export const LANG_EXEC = t("lang_exec");
export const PROCESS_SIGNAL = t("process_signal");
export const CONTAINER_DESTRUCTIVE = t("container_destructive");
export const DB_READ = t("db_read");
export const DB_WRITE = t("db_write");
export const OBFUSCATED = t("obfuscated");
export const UNKNOWN = t("unknown");

// Default policies loaded from data/policies.json
export const DEFAULT_POLICIES: Record<string, Decision> = JSON.parse(
  readFileSync(resolve(DATA_DIR, "policies.json"), "utf-8"),
);

// ==============================================================================
// Prefix Trie
// ==============================================================================

// PrefixEntry is the on-disk format (per-type JSON files). Kept as an export
// for tests that pass ad-hoc tables to prefixMatch.
export interface PrefixEntry {
  prefix: string[];
  actionType: string;
}

interface TrieNode {
  action?: string;
  children: Map<string, TrieNode>;
}

function trieInsert(root: TrieNode, prefix: string[], actionType: string): void {
  let node = root;
  for (const token of prefix) {
    let child = node.children.get(token);
    if (!child) {
      child = { children: new Map() };
      node.children.set(token, child);
    }
    node = child;
  }
  node.action = actionType;
}

/** Walk the trie, returning the deepest (longest-prefix) action found. */
function trieLookup(root: TrieNode, tokens: string[]): string {
  let node = root;
  let bestAction = UNKNOWN;
  for (const token of tokens) {
    const child = node.children.get(token);
    if (!child) break;
    if (child.action !== undefined) bestAction = child.action;
    node = child;
  }
  return bestAction;
}

// Build the trie from data/classify_full/*.json at module load.
const CLASSIFY_FULL_DIR = resolve(DATA_DIR, "classify_full");

const classifyTrie: TrieNode = (() => {
  const root: TrieNode = { children: new Map() };
  const files = readdirSync(CLASSIFY_FULL_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort();
  for (const file of files) {
    const actionType = basename(file, ".json");
    const raw = JSON.parse(
      readFileSync(resolve(CLASSIFY_FULL_DIR, file), "utf-8"),
    ) as string[][];
    for (const prefix of raw) {
      trieInsert(root, prefix, actionType);
    }
  }
  return root;
})();

/** Longest-prefix match. Uses the trie for the built-in table; falls back to
 *  linear scan for ad-hoc tables passed from tests. */
export function prefixMatch(
  tokens: string[],
  table?: PrefixEntry[],
): string {
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

/** Get the default policy for an action type. */
export function getPolicy(actionType: string, config?: ShushConfig): Decision {
  const hardcoded = DEFAULT_POLICIES[actionType] ?? "ask";
  if (!config?.actions[actionType]) return hardcoded;
  return stricter(hardcoded, config.actions[actionType]);
}

// Shell wrappers that need unwrapping
export const SHELL_WRAPPERS = new Set(["bash", "sh", "dash", "zsh"]);

// Exec sinks for pipe composition
export const EXEC_SINKS = new Set([
  "bash", "sh", "dash", "zsh", "eval", "python", "python3",
  "node", "ruby", "perl", "php", "bun", "deno", "fish", "pwsh",
]);

// Decode commands for pipe composition: [command, flag | null]
export const DECODE_COMMANDS: Array<[string, string | null]> = [
  ["base64", "-d"],
  ["base64", "--decode"],
  ["xxd", "-r"],
  ["uudecode", null],
];

/** Normalize /usr/bin/rm -> rm, then prefix-match against built-in trie. */
export function classifyTokens(tokens: string[], config?: ShushConfig): string {
  if (tokens.length === 0) return UNKNOWN;

  // Basename normalization
  const base = tokens[0].includes("/")
    ? tokens[0].split("/").pop()!
    : tokens[0];
  const normalized = base !== tokens[0] ? [base, ...tokens.slice(1)] : tokens;

  // Check config classify entries first (user-defined prefixes)
  if (config) {
    for (const [actionType, patterns] of Object.entries(config.classify)) {
      for (const pattern of patterns) {
        const prefixTokens = pattern.split(/\s+/);
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
