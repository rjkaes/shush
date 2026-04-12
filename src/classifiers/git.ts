import {
  GIT_SAFE,
  GIT_WRITE,
  GIT_DISCARD,
  GIT_HISTORY_REWRITE,
  LANG_EXEC,
  NETWORK_WRITE,
  DEFAULT_POLICIES,
} from "../taxonomy.js";
import { STRICTNESS, type Decision } from "../types.js";

// ==============================================================================
// Git Global Flag Stripping
// ==============================================================================

// Git global flags that consume a value argument.
const GIT_VALUE_FLAGS = new Set(["-C", "--git-dir", "--work-tree", "--namespace", "-c"]);

/** Check if token is a value flag, handling --flag=value joined form. */
function isValueFlag(tok: string): boolean {
  if (GIT_VALUE_FLAGS.has(tok)) return true;
  // Handle --flag=value joined form (e.g. --work-tree=/path)
  const eq = tok.indexOf("=");
  return eq > 0 && GIT_VALUE_FLAGS.has(tok.slice(0, eq));
}

// Git global flags that are standalone (no value argument).
const GIT_BOOLEAN_FLAGS = new Set([
  "--no-pager", "--no-replace-objects", "--bare", "--literal-pathspecs",
  "--glob-pathspecs", "--noglob-pathspecs", "--no-optional-locks",
]);

// Flags whose values are directory paths that change where git operates.
const GIT_DIR_FLAGS = new Set(["-C", "--git-dir", "--work-tree"]);

/**
 * Extract directory paths from git global flags (-C, --git-dir, --work-tree).
 * These control where git operates and should be checked against path guards.
 */
export function extractGitDirPaths(tokens: string[]): string[] {
  const paths: string[] = [];
  let i = 1;
  while (i < tokens.length) {
    const tok = tokens[i];
    if (GIT_DIR_FLAGS.has(tok) && i + 1 < tokens.length) {
      paths.push(tokens[i + 1]);
      i += 2;
    } else if (tok.startsWith("--") && tok.includes("=")) {
      // Handle --flag=value joined form for dir flags
      const eq = tok.indexOf("=");
      const flag = tok.slice(0, eq);
      if (GIT_DIR_FLAGS.has(flag)) {
        paths.push(tok.slice(eq + 1));
      }
      i += 1; // joined form is a single token
    } else if (isValueFlag(tok)) {
      i += tok.includes("=") ? 1 : 2; // joined form is single token
    } else if (GIT_BOOLEAN_FLAGS.has(tok)) {
      i += 1;
    } else {
      break; // reached subcommand
    }
  }
  return paths;
}

/**
 * Strip git global flags (e.g. -C <dir>, --no-pager) from token list.
 * Preserves 'git' as first token followed by the subcommand and its args.
 */
export function stripGitGlobalFlags(tokens: string[]): string[] {
  const result = [tokens[0]]; // keep "git"
  let i = 1;
  while (i < tokens.length) {
    const tok = tokens[i];
    if (isValueFlag(tok)) {
      i += tok.includes("=") ? 1 : 2; // joined form is single token
    } else if (GIT_BOOLEAN_FLAGS.has(tok)) {
      i += 1; // skip flag only
    } else {
      // Reached the subcommand — append rest as-is.
      result.push(...tokens.slice(i));
      break;
    }
  }
  return result;
}

// Dangerous git -c config keys that can execute arbitrary commands.
const DANGEROUS_GIT_CONFIGS = new Set([
  "core.hookspath",
  "core.sshcommand",
  "credential.helper",
  "core.askpass",
  "core.gitproxy",
]);

export function checkDangerousGitConfig(tokens: string[]): string | null {
  for (let i = 1; i < tokens.length; i++) {
    if (tokens[i] === "-c" && i + 1 < tokens.length) {
      const configKey = tokens[i + 1].split("=")[0].toLowerCase();
      if (DANGEROUS_GIT_CONFIGS.has(configKey)) {
        return LANG_EXEC;
      }
    }
  }
  return null;
}

/** Return the more dangerous of two action types (by default policy). */
function stricterType(a: string, b: string): string {
  const policies = DEFAULT_POLICIES as Record<string, Decision>;
  const aRank = STRICTNESS[policies[a] ?? "ask"] ?? 2;
  const bRank = STRICTNESS[policies[b] ?? "ask"] ?? 2;
  return bRank > aRank ? b : a;
}

// ==============================================================================
// git (flag-dependent subcommand classification)
// ==============================================================================

const GIT_PUSH_FORCE_FLAGS = new Set(["--force", "-f", "--force-with-lease", "--force-if-includes"]);
const GIT_CHECKOUT_DISCARD_TOKENS = new Set([".", "--", "HEAD", "--force", "-f", "--ours", "--theirs", "-B"]);
const GIT_SWITCH_DISCARD_TOKENS = new Set(["--discard-changes", "--force", "-f"]);

const GIT_SAFE_SUBCOMMANDS = new Set([
  "status", "log", "diff", "show", "describe", "shortlog",
  "archive", "blame", "grep", "annotate", "bisect", "bugreport",
  "diagnose", "difftool", "fsck", "help", "instaweb", "gitweb", "gitk",
  "ls-files", "ls-tree", "ls-remote", "rev-parse", "rev-list",
  "name-rev", "cat-file", "count-objects", "for-each-ref",
  "merge-base", "symbolic-ref", "var", "verify-pack",
]);

export function classifyGit(tokens: string[]): string | null {
  if (tokens.length < 2 || tokens[0] !== "git") return null;

  const sub = tokens[1];
  const args = tokens.slice(2);

  if (sub === "tag") {
    return args.length === 0 ? GIT_SAFE : GIT_WRITE;
  }

  if (sub === "branch") {
    if (!args.length) return GIT_SAFE;
    let branchResult: string = GIT_WRITE;
    let hasListFlag = false;
    for (const a of args) {
      if (["-a", "-r", "--list", "-v", "-vv"].includes(a)) hasListFlag = true;
      else if (a === "-d") branchResult = stricterType(branchResult, GIT_DISCARD);
      else if (a === "-D") branchResult = stricterType(branchResult, GIT_HISTORY_REWRITE);
    }
    if (hasListFlag && branchResult === GIT_WRITE) return GIT_SAFE;
    return branchResult;
  }

  if (sub === "config") {
    for (const a of args) {
      if (["--get", "--list", "--get-all", "--get-regexp"].includes(a)) return GIT_SAFE;
      if (["--unset", "--unset-all", "--replace-all"].includes(a)) return GIT_WRITE;
    }
    const nonFlag = args.filter((a) => !a.startsWith("-"));
    return nonFlag.length <= 1 ? GIT_SAFE : GIT_WRITE;
  }

  if (sub === "reset") {
    return args.includes("--hard") ? GIT_DISCARD : GIT_WRITE;
  }

  if (sub === "push") {
    for (const a of args) {
      if (GIT_PUSH_FORCE_FLAGS.has(a)) return GIT_HISTORY_REWRITE;
      if (a.startsWith("+") && a.length > 1) return GIT_HISTORY_REWRITE;
    }
    return GIT_WRITE;
  }

  if (sub === "add") {
    if (args.includes("--dry-run") || args.includes("-n")) return GIT_SAFE;
    if (args.includes("--force") || args.includes("-f")) return GIT_WRITE;
    return GIT_WRITE;
  }

  if (sub === "rm") {
    return args.includes("--cached") ? GIT_WRITE : GIT_DISCARD;
  }

  if (sub === "clean") {
    return (args.includes("--dry-run") || args.includes("-n")) ? GIT_SAFE : GIT_HISTORY_REWRITE;
  }

  if (sub === "reflog") {
    if (args.length && (args[0] === "delete" || args[0] === "expire")) {
      return GIT_DISCARD;
    }
    return GIT_SAFE;
  }

  if (sub === "checkout") {
    for (const a of args) {
      if (GIT_CHECKOUT_DISCARD_TOKENS.has(a)) return GIT_DISCARD;
    }
    return GIT_WRITE;
  }

  if (sub === "switch") {
    for (const a of args) {
      if (GIT_SWITCH_DISCARD_TOKENS.has(a)) return GIT_DISCARD;
    }
    return GIT_WRITE;
  }

  if (sub === "restore") {
    return args.includes("--staged") ? GIT_WRITE : GIT_DISCARD;
  }

  if (sub === "commit") {
    return args.includes("--amend") ? GIT_HISTORY_REWRITE : GIT_WRITE;
  }

  // git remote add/set-url configure network endpoints
  if (sub === "remote") {
    if (args.length > 0 && (args[0] === "add" || args[0] === "set-url")) return NETWORK_WRITE;
    if (args.length > 0 && (args[0] === "remove" || args[0] === "rm" || args[0] === "rename")) return GIT_WRITE;
    return GIT_SAFE;
  }

  // Read-only subcommands
  if (GIT_SAFE_SUBCOMMANDS.has(sub)) {
    return GIT_SAFE;
  }

  return null;
}
