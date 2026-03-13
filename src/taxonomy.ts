import { readdirSync, readFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { type Decision, type ShushConfig, stricter } from "./types.js";

// Action type constants
export const FILESYSTEM_READ = "filesystem_read";
export const FILESYSTEM_WRITE = "filesystem_write";
export const FILESYSTEM_DELETE = "filesystem_delete";
export const GIT_SAFE = "git_safe";
export const GIT_WRITE = "git_write";
export const GIT_DISCARD = "git_discard";
export const GIT_HISTORY_REWRITE = "git_history_rewrite";
export const NETWORK_OUTBOUND = "network_outbound";
export const NETWORK_WRITE = "network_write";
export const NETWORK_DIAGNOSTIC = "network_diagnostic";
export const PACKAGE_INSTALL = "package_install";
export const PACKAGE_RUN = "package_run";
export const PACKAGE_UNINSTALL = "package_uninstall";
export const LANG_EXEC = "lang_exec";
export const PROCESS_SIGNAL = "process_signal";
export const CONTAINER_DESTRUCTIVE = "container_destructive";
export const DB_READ = "db_read";
export const DB_WRITE = "db_write";
export const OBFUSCATED = "obfuscated";
export const UNKNOWN = "unknown";

// Default policies loaded from data/policies.json
const DATA_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "data");
export const DEFAULT_POLICIES: Record<string, Decision> = JSON.parse(
  readFileSync(resolve(DATA_DIR, "policies.json"), "utf-8"),
);

// Prefix table loaded from data/classify_full/*.json at module init.
export interface PrefixEntry {
  prefix: string[];
  actionType: string;
}

const CLASSIFY_FULL_DIR = resolve(DATA_DIR, "classify_full");

export const CLASSIFY_FULL_TABLE: PrefixEntry[] = (() => {
  const files = readdirSync(CLASSIFY_FULL_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort();
  const entries: PrefixEntry[] = [];
  for (const file of files) {
    const actionType = basename(file, ".json");
    const raw = JSON.parse(
      readFileSync(resolve(CLASSIFY_FULL_DIR, file), "utf-8"),
    ) as string[][];
    for (const prefix of raw) {
      entries.push({ prefix, actionType });
    }
  }
  // Sort: longest prefix first, then alphabetically by joined prefix.
  entries.sort((a, b) => {
    const lenDiff = b.prefix.length - a.prefix.length;
    if (lenDiff !== 0) return lenDiff;
    const aKey = a.prefix.join(" ");
    const bKey = b.prefix.join(" ");
    return aKey < bKey ? -1 : aKey > bKey ? 1 : 0;
  });
  return entries;
})();

// First-token index: maps the first token of each prefix entry to the
// subset of entries sharing that token. Built once at module load so
// prefixMatch only scans the relevant bucket instead of all entries.
const firstTokenIndex: Map<string, PrefixEntry[]> = (() => {
  const index = new Map<string, PrefixEntry[]>();
  for (const entry of CLASSIFY_FULL_TABLE) {
    const key = entry.prefix[0];
    let bucket = index.get(key);
    if (!bucket) {
      bucket = [];
      index.set(key, bucket);
    }
    bucket.push(entry);
  }
  return index;
})();

/** Longest-prefix-first match against a sorted table. */
export function prefixMatch(
  tokens: string[],
  table: PrefixEntry[],
): string {
  // Use first-token index when called with the default table
  const bucket = table === CLASSIFY_FULL_TABLE ? firstTokenIndex.get(tokens[0]) : undefined;
  const entries = bucket ?? table;

  for (const entry of entries) {
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

/** Normalize /usr/bin/rm → rm, then prefix-match against built-in table. */
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

  return prefixMatch(normalized, CLASSIFY_FULL_TABLE);
}
