import * as T from "./taxonomy.js";

// ==============================================================================
// Git Global Flag Stripping
// ==============================================================================

// Git global flags that consume a value argument.
const GIT_VALUE_FLAGS = new Set(["-C", "--git-dir", "--work-tree", "--namespace", "-c"]);

// Git global flags that are standalone (no value argument).
const GIT_BOOLEAN_FLAGS = new Set([
  "--no-pager", "--no-replace-objects", "--bare", "--literal-pathspecs",
  "--glob-pathspecs", "--noglob-pathspecs", "--no-optional-locks",
]);

/**
 * Strip git global flags (e.g. -C <dir>, --no-pager) from token list.
 * Preserves 'git' as first token followed by the subcommand and its args.
 */
export function stripGitGlobalFlags(tokens: string[]): string[] {
  const result = [tokens[0]]; // keep "git"
  let i = 1;
  while (i < tokens.length) {
    const tok = tokens[i];
    if (GIT_VALUE_FLAGS.has(tok)) {
      i += 2; // skip flag + its value
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

// ==============================================================================
// Flag Classifier Entry Point
// ==============================================================================

/** Run flag-dependent classifiers. Returns action type or null (use prefix table). */
export function classifyWithFlags(tokens: string[]): string | null {
  if (!tokens.length) return null;

  // Git: strip global flags first
  let normalized = tokens;
  if (tokens[0] === "git") {
    normalized = stripGitGlobalFlags(tokens);
  }

  return (
    classifyFind(normalized) ??
    classifySed(normalized) ??
    classifyAwk(normalized) ??
    classifyTar(normalized) ??
    classifyGit(normalized) ??
    classifyCurl(normalized) ??
    classifyWget(normalized) ??
    classifyHttpie(normalized) ??
    classifyGlobalInstall(normalized)
  );
}

// ==============================================================================
// find
// ==============================================================================

function classifyFind(tokens: string[]): string | null {
  if (!tokens.length || tokens[0] !== "find") return null;

  let worst = T.FILESYSTEM_READ;
  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i];

    if (tok === "-delete") return T.FILESYSTEM_DELETE;

    // -exec/-execdir/-ok: classify the command that follows
    if (tok === "-exec" || tok === "-execdir" || tok === "-ok") {
      // Collect tokens until the terminating ; or +
      const execTokens: string[] = [];
      for (let j = i + 1; j < tokens.length; j++) {
        if (tokens[j] === ";" || tokens[j] === "+") break;
        // Skip {} placeholder
        if (tokens[j] === "{}") continue;
        execTokens.push(tokens[j]);
      }
      if (execTokens.length) {
        // Classify the inner command via prefix table + flag classifiers
        const innerType = classifyExecTokens(execTokens);
        worst = stricterType(worst, innerType);
      } else {
        // No tokens after -exec: conservative default
        return T.FILESYSTEM_DELETE;
      }
    }
  }
  return worst;
}

/** Classify tokens from a find -exec clause using the same pipeline as stages. */
function classifyExecTokens(tokens: string[]): string {
  // Try flag classifiers first (handles things like sed -i)
  const flagResult = classifyWithFlags(tokens);
  if (flagResult) return flagResult;
  // Fall back to prefix table
  return T.classifyTokens(tokens);
}

// Rank action types by how restrictive their default policy is.
// Derived from DEFAULT_POLICIES so new action types are handled automatically.
const DECISION_RANK: Record<string, number> = { allow: 0, context: 1, ask: 2, block: 3 };

/** Return the more dangerous of two action types (by default policy). */
function stricterType(a: string, b: string): string {
  const aRank = DECISION_RANK[T.DEFAULT_POLICIES[a] ?? "ask"] ?? 2;
  const bRank = DECISION_RANK[T.DEFAULT_POLICIES[b] ?? "ask"] ?? 2;
  return bRank > aRank ? b : a;
}

// ==============================================================================
// sed
// ==============================================================================

function classifySed(tokens: string[]): string | null {
  if (!tokens.length || tokens[0] !== "sed") return null;
  for (const tok of tokens.slice(1)) {
    // -i/-I or -i.bak/-I.bak (GNU lowercase, BSD uppercase)
    if (tok.startsWith("-i") || tok.startsWith("-I")) {
      return T.FILESYSTEM_WRITE;
    }
    // --in-place or --in-place=.bak (GNU long form)
    if (tok.startsWith("--in-place")) {
      return T.FILESYSTEM_WRITE;
    }
    // Combined short flags: -ni, -nI, -ein, etc.
    if (tok.startsWith("-") && !tok.startsWith("--") && (tok.includes("i") || tok.includes("I"))) {
      return T.FILESYSTEM_WRITE;
    }
  }
  return T.FILESYSTEM_READ;
}

// ==============================================================================
// awk
// ==============================================================================

const AWK_COMMANDS = new Set(["awk", "gawk", "mawk", "nawk"]);
const AWK_DANGEROUS_PATTERNS = ["system(", "| getline", "|&", '| "', "print >"];

function classifyAwk(tokens: string[]): string | null {
  if (!tokens.length || !AWK_COMMANDS.has(tokens[0])) return null;
  for (const tok of tokens.slice(1)) {
    if (tok.startsWith("-")) continue;
    if (AWK_DANGEROUS_PATTERNS.some((p) => tok.includes(p))) {
      return T.LANG_EXEC;
    }
  }
  return null;
}

// ==============================================================================
// tar
// ==============================================================================

function classifyTar(tokens: string[]): string | null {
  if (!tokens.length || tokens[0] !== "tar") return null;

  let foundRead = false;
  let foundWrite = false;
  const args = tokens.slice(1);

  if (!args.length) return T.FILESYSTEM_WRITE; // Conservative default

  // Check if first arg is a bare mode string (no leading dash): tf, czf, xf
  const first = args[0];
  if (first && !first.startsWith("-")) {
    if ([..."cxru"].some((c) => first.includes(c))) {
      foundWrite = true;
    } else if (first.includes("t")) {
      foundRead = true;
    }
  }

  // Check all flag arguments
  for (const tok of args) {
    if (tok.startsWith("-") && tok.length > 1 && tok[1] !== "-") {
      // Short flags: -tf, -czf, -xf, etc.
      const letters = tok.slice(1);
      if (letters.includes("t")) foundRead = true;
      if ([..."cxru"].some((c) => letters.includes(c))) foundWrite = true;
    } else if (tok.startsWith("--")) {
      if (tok === "--list") foundRead = true;
      if (["--create", "--extract", "--append", "--update", "--get", "--delete"].includes(tok)) {
        foundWrite = true;
      }
    }
  }

  if (foundWrite) return T.FILESYSTEM_WRITE;
  if (foundRead) return T.FILESYSTEM_READ;
  return T.FILESYSTEM_WRITE; // Conservative default
}

// ==============================================================================
// curl
// ==============================================================================

const CURL_DATA_FLAGS = new Set([
  "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
  "-F", "--form", "--form-string", "-T", "--upload-file", "--json",
]);
const CURL_DATA_LONG_PREFIXES = [
  "--data=", "--data-raw=", "--data-binary=", "--data-urlencode=",
  "--form=", "--form-string=", "--upload-file=", "--json=",
];
const CURL_METHOD_FLAGS = new Set(["-X", "--request"]);
const WRITE_METHODS = new Set(["POST", "PUT", "DELETE", "PATCH"]);

function classifyCurl(tokens: string[]): string | null {
  if (!tokens.length || tokens[0] !== "curl") return null;

  let hasData = false;
  let hasWriteMethod = false;

  let i = 1;
  while (i < tokens.length) {
    const tok = tokens[i];

    // Standalone data flags
    if (CURL_DATA_FLAGS.has(tok)) {
      hasData = true;
      i += 1;
      continue;
    }

    // =joined long data flags
    if (CURL_DATA_LONG_PREFIXES.some((p) => tok.startsWith(p))) {
      hasData = true;
      i += 1;
      continue;
    }

    // Method flags: -X METHOD, --request METHOD, --request=METHOD
    if (CURL_METHOD_FLAGS.has(tok)) {
      if (i + 1 < tokens.length) {
        const method = tokens[i + 1].toUpperCase();
        if (WRITE_METHODS.has(method)) {
          hasWriteMethod = true;
        }
      }
      i += 2;
      continue;
    }
    if (tok.startsWith("--request=")) {
      const method = tok.split("=", 2)[1].toUpperCase();
      if (WRITE_METHODS.has(method)) {
        hasWriteMethod = true;
      }
      i += 1;
      continue;
    }

    // Combined short flags: -sXPOST, -XPOST, etc.
    if (tok.startsWith("-") && !tok.startsWith("--") && tok.length > 1) {
      const letters = tok.slice(1);
      if (letters.includes("X")) {
        const xIdx = letters.indexOf("X");
        const rest = letters.slice(xIdx + 1);
        // Extract method: chars after X until non-alpha
        const methodChars: string[] = [];
        for (const c of rest) {
          if (/[a-zA-Z]/.test(c)) {
            methodChars.push(c);
          } else {
            break;
          }
        }
        if (methodChars.length) {
          const method = methodChars.join("").toUpperCase();
          if (WRITE_METHODS.has(method)) {
            hasWriteMethod = true;
          }
        } else if (i + 1 < tokens.length) {
          // X is last char in combined flags, method is next token
          const method = tokens[i + 1].toUpperCase();
          if (WRITE_METHODS.has(method)) {
            hasWriteMethod = true;
          }
          i += 2;
          continue;
        }
      }
    }

    i += 1;
  }

  if (hasData) return T.NETWORK_WRITE;
  if (hasWriteMethod) return T.NETWORK_WRITE;
  return T.NETWORK_OUTBOUND;
}

// ==============================================================================
// wget
// ==============================================================================

function classifyWget(tokens: string[]): string | null {
  if (!tokens.length || tokens[0] !== "wget") return null;

  let hasData = false;
  let hasWriteMethod = false;

  let i = 1;
  while (i < tokens.length) {
    const tok = tokens[i];

    // --post-data, --post-file (standalone or =joined)
    if (tok === "--post-data" || tok === "--post-file") {
      hasData = true;
      i += 2; // skip value
      continue;
    }
    if (tok.startsWith("--post-data=") || tok.startsWith("--post-file=")) {
      hasData = true;
      i += 1;
      continue;
    }

    // --method METHOD or --method=METHOD
    if (tok === "--method") {
      if (i + 1 < tokens.length) {
        const method = tokens[i + 1].toUpperCase();
        if (WRITE_METHODS.has(method)) {
          hasWriteMethod = true;
        }
      }
      i += 2;
      continue;
    }
    if (tok.startsWith("--method=")) {
      const method = tok.split("=", 2)[1].toUpperCase();
      if (WRITE_METHODS.has(method)) {
        hasWriteMethod = true;
      }
      i += 1;
      continue;
    }

    i += 1;
  }

  if (hasData) return T.NETWORK_WRITE;
  if (hasWriteMethod) return T.NETWORK_WRITE;
  return T.NETWORK_OUTBOUND;
}

// ==============================================================================
// httpie (http, https, xh, xhs)
// ==============================================================================

const HTTPIE_CMDS = new Set(["http", "https", "xh", "xhs"]);
const HTTPIE_METHODS = new Set(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]);

function classifyHttpie(tokens: string[]): string | null {
  if (!tokens.length || !HTTPIE_CMDS.has(tokens[0])) return null;

  const args = tokens.slice(1);
  let hasForm = false;
  let hasWriteMethod = false;
  let hasDataItem = false;
  let foundUrl = false;

  for (const arg of args) {
    // Check for --form / -f
    if (arg === "--form" || arg === "-f") {
      hasForm = true;
      continue;
    }

    // Skip other flags
    if (arg.startsWith("-")) continue;

    // First non-flag arg: check if it's an uppercase method
    if (!foundUrl && HTTPIE_METHODS.has(arg.toUpperCase())) {
      if (WRITE_METHODS.has(arg.toUpperCase())) {
        hasWriteMethod = true;
      }
      continue;
    }

    if (!foundUrl) {
      foundUrl = true;
      continue;
    }

    // After URL: check for data item patterns (key=value, key:=value, key@file)
    if (arg.includes("=") || arg.includes(":=") || arg.includes("@")) {
      hasDataItem = true;
    }
  }

  if (hasWriteMethod) return T.NETWORK_WRITE;
  if (hasForm) return T.NETWORK_WRITE;
  if (hasDataItem) return T.NETWORK_WRITE;
  return T.NETWORK_OUTBOUND;
}

// ==============================================================================
// Global Install Detection
// ==============================================================================

const GLOBAL_INSTALL_FLAGS = new Set(["-g", "--global", "--system", "--target", "--root"]);
const GLOBAL_INSTALL_CMDS = new Set(["npm", "pnpm", "bun", "pip", "pip3", "cargo", "gem"]);

function classifyGlobalInstall(tokens: string[]): string | null {
  if (!tokens.length || !GLOBAL_INSTALL_CMDS.has(tokens[0])) return null;
  for (const tok of tokens.slice(1)) {
    if (GLOBAL_INSTALL_FLAGS.has(tok)) {
      return T.UNKNOWN;
    }
  }
  return null;
}

// ==============================================================================
// git (flag-dependent subcommand classification)
// ==============================================================================

const GIT_PUSH_FORCE_FLAGS = new Set(["--force", "-f", "--force-with-lease", "--force-if-includes"]);
const GIT_CHECKOUT_DISCARD_TOKENS = new Set([".", "--", "HEAD", "--force", "-f", "--ours", "--theirs", "-B"]);
const GIT_SWITCH_DISCARD_TOKENS = new Set(["--discard-changes", "--force", "-f"]);

function classifyGit(tokens: string[]): string | null {
  if (tokens.length < 2 || tokens[0] !== "git") return null;

  const sub = tokens[1];
  const args = tokens.slice(2);

  if (sub === "tag") {
    return args.length === 0 ? T.GIT_SAFE : T.GIT_WRITE;
  }

  if (sub === "branch") {
    if (!args.length) return T.GIT_SAFE;
    for (const a of args) {
      if (["-a", "-r", "--list", "-v", "-vv"].includes(a)) return T.GIT_SAFE;
      if (a === "-d") return T.GIT_DISCARD;
      if (a === "-D") return T.GIT_HISTORY_REWRITE;
    }
    return T.GIT_WRITE;
  }

  if (sub === "config") {
    for (const a of args) {
      if (["--get", "--list", "--get-all", "--get-regexp"].includes(a)) return T.GIT_SAFE;
      if (["--unset", "--unset-all", "--replace-all"].includes(a)) return T.GIT_WRITE;
    }
    // Count non-flag args: 0-1 = read (get), 2+ = write (set)
    const nonFlag = args.filter((a) => !a.startsWith("-"));
    return nonFlag.length <= 1 ? T.GIT_SAFE : T.GIT_WRITE;
  }

  if (sub === "reset") {
    return args.includes("--hard") ? T.GIT_DISCARD : T.GIT_WRITE;
  }

  if (sub === "push") {
    for (const a of args) {
      if (GIT_PUSH_FORCE_FLAGS.has(a)) return T.GIT_HISTORY_REWRITE;
      // +refspec means force push
      if (a.startsWith("+") && a.length > 1) return T.GIT_HISTORY_REWRITE;
    }
    return T.GIT_WRITE;
  }

  if (sub === "add") {
    if (args.includes("--dry-run") || args.includes("-n")) return T.GIT_SAFE;
    if (args.includes("--force") || args.includes("-f")) return T.GIT_DISCARD;
    return T.GIT_WRITE;
  }

  if (sub === "rm") {
    return args.includes("--cached") ? T.GIT_WRITE : T.GIT_DISCARD;
  }

  if (sub === "clean") {
    return (args.includes("--dry-run") || args.includes("-n")) ? T.GIT_SAFE : T.GIT_HISTORY_REWRITE;
  }

  if (sub === "reflog") {
    if (args.length && (args[0] === "delete" || args[0] === "expire")) {
      return T.GIT_DISCARD;
    }
    return T.GIT_SAFE;
  }

  if (sub === "checkout") {
    for (const a of args) {
      if (GIT_CHECKOUT_DISCARD_TOKENS.has(a)) return T.GIT_DISCARD;
    }
    return T.GIT_WRITE;
  }

  if (sub === "switch") {
    for (const a of args) {
      if (GIT_SWITCH_DISCARD_TOKENS.has(a)) return T.GIT_DISCARD;
    }
    return T.GIT_WRITE;
  }

  if (sub === "restore") {
    return args.includes("--staged") ? T.GIT_WRITE : T.GIT_DISCARD;
  }

  if (sub === "commit") {
    return args.includes("--amend") ? T.GIT_HISTORY_REWRITE : T.GIT_WRITE;
  }

  // Read-only subcommands: return git_safe so that global-flag stripping
  // (e.g. git -C /tmp status) produces a correct classification without
  // needing to fall through to the prefix table.
  if (GIT_SAFE_SUBCOMMANDS.has(sub)) {
    return T.GIT_SAFE;
  }

  return null;
}

const GIT_SAFE_SUBCOMMANDS = new Set([
  "status", "log", "diff", "show", "remote", "describe", "shortlog",
  "archive", "blame", "grep", "annotate", "bisect", "bugreport",
  "diagnose", "difftool", "fsck", "help", "instaweb", "gitweb", "gitk",
  "ls-files", "ls-tree", "ls-remote", "rev-parse", "rev-list",
  "name-rev", "cat-file", "count-objects", "for-each-ref",
  "merge-base", "symbolic-ref", "var", "verify-pack",
]);
