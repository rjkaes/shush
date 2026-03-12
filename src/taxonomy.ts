import { type Decision, type ShushConfig, stricter } from "./types.js";
import { type PrefixEntry, CLASSIFY_FULL_TABLE } from "../data/classify-full.js";

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

// Default policies per action type
export const DEFAULT_POLICIES: Record<string, Decision> = {
  filesystem_read: "allow",
  filesystem_write: "context",
  filesystem_delete: "context",
  git_safe: "allow",
  git_write: "allow",
  git_discard: "ask",
  git_history_rewrite: "ask",
  network_outbound: "context",
  network_write: "context",
  network_diagnostic: "allow",
  package_install: "allow",
  package_run: "allow",
  package_uninstall: "ask",
  lang_exec: "ask",
  process_signal: "ask",
  container_destructive: "ask",
  db_read: "allow",
  db_write: "ask",
  obfuscated: "block",
  unknown: "ask",
};

// First-token index: maps the first token of each prefix entry to the
// subset of entries sharing that token. Built once at module load so
// prefixMatch only scans the relevant bucket instead of all ~580 entries.
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
