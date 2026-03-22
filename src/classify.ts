import { PROCSUB_PLACEHOLDER } from "./ast-walk.js";
import * as T from "./taxonomy.js";
import { STRICTNESS } from "./types.js";

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
    } else if (GIT_VALUE_FLAGS.has(tok)) {
      i += 2; // skip non-dir value flags (-c, --namespace)
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

// Dispatch map: O(1) lookup by command name instead of calling 12 classifiers.
// Multi-command classifiers have one entry per command name they handle.
type Classifier = (tokens: string[]) => string | null;
const FLAG_CLASSIFIERS: Record<string, Classifier> = {};

function registerClassifier(commands: string[], fn: Classifier): void {
  for (const cmd of commands) FLAG_CLASSIFIERS[cmd] = fn;
}

// Registrations are deferred until after all classifier functions are defined
// (see bottom of this section). The `initClassifiers()` call populates the map.
let classifiersInitialized = false;
function initClassifiers(): void {
  if (classifiersInitialized) return;
  classifiersInitialized = true;
  registerClassifier(["find"], classifyFind);
  registerClassifier(["sed"], classifySed);
  registerClassifier(["awk", "gawk", "mawk", "nawk"], classifyAwk);
  registerClassifier(["tar"], classifyTar);
  registerClassifier(["git"], classifyGit);
  registerClassifier(["gh"], classifyGhApi);
  registerClassifier(["curl"], classifyCurl);
  registerClassifier(["wget"], classifyWget);
  registerClassifier(["http", "https", "xh", "xhs"], classifyHttpie);
  registerClassifier(["npm", "pnpm", "bun", "pip", "pip3", "cargo", "gem"], classifyGlobalInstall);
  registerClassifier(["tee"], classifyTee);
  registerClassifier(["python", "python3", "node", "ruby"], classifyInlineCode);
  // bun is already registered via classifyGlobalInstall; inlineCode also handles it
  // but globalInstall takes priority since it's registered first.
}

/** Run flag-dependent classifiers. Returns action type or null (use prefix table). */
export function classifyWithFlags(tokens: string[]): string | null {
  if (!tokens.length) return null;
  initClassifiers();

  // Git: strip global flags first
  let normalized = tokens;
  if (tokens[0] === "git") {
    normalized = stripGitGlobalFlags(tokens);
  }

  const classifier = FLAG_CLASSIFIERS[normalized[0]];
  if (!classifier) return null;

  // Some commands need multiple classifiers tried in sequence.
  // gh needs ghApi; bun needs both globalInstall and inlineCode.
  const result = classifier(normalized);
  if (result !== null) return result;

  // Fallback: try inlineCode if the primary classifier returned null
  // (handles bun -e when bun's primary classifier is globalInstall).
  if (normalized[0] in INLINE_CODE_CMDS) {
    return classifyInlineCode(normalized);
  }
  return null;
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

/** Return the more dangerous of two action types (by default policy). */
function stricterType(a: string, b: string): string {
  const aRank = STRICTNESS[T.DEFAULT_POLICIES[a] ?? "ask"] ?? 2;
  const bRank = STRICTNESS[T.DEFAULT_POLICIES[b] ?? "ask"] ?? 2;
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
// gh api
// ==============================================================================

// gh api uses --method/-X for HTTP method (default GET).
// Body flags (-f, --field, -F, --raw-field, --input) flip the default to POST.
const GH_API_METHOD_FLAGS = new Set(["--method", "-X"]);
const GH_API_BODY_FLAGS = new Set(["-f", "--field", "-F", "--raw-field", "--input"]);
// Known flags that consume a value argument (skip to avoid misclassification)
const GH_API_VALUE_FLAGS = new Set(["-H", "--header", "--jq", "-t", "--template", "--cache"]);

function classifyGhApi(tokens: string[]): string | null {
  if (tokens.length < 2 || tokens[0] !== "gh" || tokens[1] !== "api") return null;

  let explicitMethod: string | null = null;
  let hasBody = false;

  let i = 2;
  while (i < tokens.length) {
    const tok = tokens[i];

    if (GH_API_METHOD_FLAGS.has(tok) && i + 1 < tokens.length) {
      explicitMethod = tokens[i + 1].toUpperCase();
      i += 2;
      continue;
    }
    if (tok.startsWith("--method=")) {
      explicitMethod = tok.split("=", 2)[1].toUpperCase();
      i += 1;
      continue;
    }

    const eqIdx = tok.indexOf("=");
    const flagPart = eqIdx >= 0 ? tok.slice(0, eqIdx) : tok;
    if (GH_API_BODY_FLAGS.has(flagPart)) {
      hasBody = true;
      i += eqIdx >= 0 ? 1 : 2; // =joined: skip flag only; separate: skip flag + value
      continue;
    }

    // Skip known flags that consume a value argument
    if (GH_API_VALUE_FLAGS.has(flagPart)) {
      i += eqIdx >= 0 ? 1 : 2;
      continue;
    }

    i += 1;
  }

  const method = explicitMethod ?? (hasBody ? "POST" : "GET");

  // Classification: DELETE → git_history_rewrite (destructive, irreversible),
  // GET/HEAD → git_safe (read-only), POST/PUT/PATCH → git_write (mutating).
  if (method === "DELETE") return T.GIT_HISTORY_REWRITE;
  if (method === "GET" || method === "HEAD") return T.GIT_SAFE;
  return T.GIT_WRITE;
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

    // Standalone data flags (consume the value argument too)
    if (CURL_DATA_FLAGS.has(tok)) {
      hasData = true;
      i += 2;
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

// ==============================================================================
// Tee: process-substitution-only targets are not real file writes
// ==============================================================================

/**
 * If `tee` only writes to process substitutions (no real file paths),
 * classify as filesystem_read instead of letting the trie return
 * filesystem_write.
 */
function classifyTee(tokens: string[]): string | null {
  if (tokens[0] !== "tee") return null;
  // Check non-flag arguments: are they all process-sub placeholders?
  let hasRealTarget = false;
  for (let i = 1; i < tokens.length; i++) {
    if (tokens[i].startsWith("-")) continue; // skip flags
    if (tokens[i] === PROCSUB_PLACEHOLDER) continue;
    hasRealTarget = true;
    break;
  }
  // If every target is a process substitution (or there are none), this
  // tee invocation just reads stdin without writing to any real file.
  if (!hasRealTarget) return T.FILESYSTEM_READ;
  return null;
}

// ==============================================================================
// Inline Code (python -c, node -e, ruby -e)
// ==============================================================================

// Maps command → flag that introduces inline code, so we can extract the payload.
const INLINE_CODE_CMDS: Record<string, string[]> = {
  python: ["-c"],
  python3: ["-c"],
  node: ["-e", "--eval"],
  bun: ["-e", "--eval"],
  ruby: ["-e"],
};

// Python modules that are safe to import (no filesystem mutation, no network,
// no subprocess spawning). Covers the one-liners LLMs typically generate.
const PYTHON_SAFE_MODULES = new Set([
  "abc", "argparse", "ast", "base64", "binascii", "bisect", "calendar",
  "cmath", "codecs", "collections", "colorsys", "contextlib", "copy",
  "csv", "dataclasses", "datetime", "decimal", "difflib", "enum",
  "fractions", "functools", "hashlib", "heapq", "hmac", "html",
  "inspect", "io", "itertools", "json", "keyword", "locale", "math",
  "operator", "os.path", "pathlib", "pprint", "random", "re",
  "statistics", "string", "struct", "sys", "textwrap", "time",
  "timeit", "token", "tokenize", "traceback", "types", "typing",
  "unicodedata", "unittest.mock", "uuid", "xml.etree.ElementTree",
  "zlib",
]);

// Python builtins / patterns that indicate dangerous operations.
const PYTHON_DANGEROUS = [
  // Execution
  "eval(", "exec(", "compile(",
  // Dynamic import
  "__import__(",
  // Subprocess / OS
  "os.system(", "os.popen(", "os.exec", "os.spawn", "os.remove(",
  "os.unlink(", "os.rmdir(", "os.rename(", "os.makedirs(",
  "os.mkdir(", "os.chmod(", "os.chown(", "os.kill(",
  "subprocess", "shutil",
  // Network
  "urllib", "http.client", "requests", "socket", "ftplib",
  "smtplib", "xmlrpc",
  // File mutation via open()
  "open(",
  // Reflection tricks
  "getattr(", "setattr(", "delattr(",
  "__builtins__", "__class__", "__subclasses__",
];

// Node globals / requires that are safe.
const NODE_SAFE_REQUIRES = new Set([
  "assert", "buffer", "crypto", "events", "os", "path", "perf_hooks",
  "querystring", "stream", "string_decoder", "url", "util", "zlib",
]);

// Node patterns that indicate dangerous operations.
const NODE_DANGEROUS = [
  "eval(", "Function(",
  "execSync(", "spawnSync(", "exec(",
  "process.exit(", "process.kill(",
];

// Node modules that are dangerous to require.
const NODE_DANGEROUS_MODULES = new Set([
  "child_process", "cluster", "dgram", "dns", "net", "tls",
  "http", "https", "http2", "fs",
]);

// Ruby safe requires.
const RUBY_SAFE_REQUIRES = new Set([
  "json", "pp", "set", "date", "pathname", "securerandom",
  "base64", "digest", "erb", "optparse", "ostruct", "time",
  "yaml", "csv", "uri", "shellwords", "stringio", "strscan",
  "bigdecimal", "matrix", "prime", "ipaddr",
]);

// Ruby patterns that indicate dangerous operations.
const RUBY_DANGEROUS = [
  "system(", "exec(", "spawn(",
  "`",       // backtick execution
  "%x(",     // alternate backtick syntax
  "IO.popen(", "Open3",
  "Kernel.system(", "Kernel.exec(",
  "File.delete(", "File.unlink(", "FileUtils",
  "Net::HTTP", "Net::FTP", "Net::SMTP",
  "eval(",
  "send(",
];

/**
 * Classify inline code execution (python -c, node -e, bun -e, ruby -e).
 *
 * If the payload only uses known-safe modules and avoids dangerous patterns,
 * returns PACKAGE_RUN (allow). This covers the common LLM pattern of running
 * one-liners like `python3 -c "import json; print(json.dumps(x))"`.
 *
 * Returns null (fall through to trie → LANG_EXEC → ask) if:
 * - the payload contains unresolved variables, dangerous patterns, or
 *   unknown imports
 * - we can't extract the payload
 */
function classifyInlineCode(tokens: string[]): string | null {
  if (tokens.length < 3) return null;

  const cmd = tokens[0];
  const expectedFlag = INLINE_CODE_CMDS[cmd];
  if (!expectedFlag) return null;

  // Find the inline flag and extract the payload.
  let flagIdx = -1;
  for (const flag of expectedFlag) {
    flagIdx = tokens.indexOf(flag);
    if (flagIdx >= 0) break;
  }
  if (flagIdx < 0 || flagIdx + 1 >= tokens.length) return null;

  const payload = tokens[flagIdx + 1];

  // Reject if payload contains unresolved shell variables — we can't
  // see the actual code.
  if (payload.includes("$") || payload.includes("`")) return null;

  if (cmd === "python" || cmd === "python3") {
    return classifyPythonPayload(payload);
  }
  if (cmd === "node" || cmd === "bun") {
    return classifyNodePayload(payload);
  }
  if (cmd === "ruby") {
    return classifyRubyPayload(payload);
  }
  return null;
}

function classifyPythonPayload(code: string): string | null {
  // Check for dangerous patterns first (fast reject).
  for (const pattern of PYTHON_DANGEROUS) {
    if (code.includes(pattern)) return null;
  }

  // Extract all imports and verify they're on the allowlist.
  // Matches: import foo, import foo.bar, from foo import ...,
  //          from foo.bar import ...
  const importRe = /(?:^|;|\n)\s*(?:import|from)\s+([\w.]+)/g;
  let match: RegExpExecArray | null;
  while ((match = importRe.exec(code)) !== null) {
    const mod = match[1];
    // Check the full module name and the top-level package.
    if (!PYTHON_SAFE_MODULES.has(mod) && !PYTHON_SAFE_MODULES.has(mod.split(".")[0])) {
      return null;
    }
  }

  return T.PACKAGE_RUN;
}

function classifyNodePayload(code: string): string | null {
  for (const pattern of NODE_DANGEROUS) {
    if (code.includes(pattern)) return null;
  }

  // Extract require() calls and check against both allowlist and blocklist.
  // Also catch template literal requires: require(`child_process`).
  const requireRe = /require\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g;
  let match: RegExpExecArray | null;
  while ((match = requireRe.exec(code)) !== null) {
    const mod = match[1];
    if (NODE_DANGEROUS_MODULES.has(mod)) return null;
    if (!NODE_SAFE_REQUIRES.has(mod)) return null;
  }

  // Reject computed requires: require("child" + "_process"), require(variable).
  if (/require\s*\([^)]*\+/.test(code)) return null;
  if (/require\s*\(\s*[a-zA-Z_$]/.test(code)) return null;

  // Check for dynamic import().
  if (/\bimport\s*\(/.test(code)) return null;

  return T.PACKAGE_RUN;
}

function classifyRubyPayload(code: string): string | null {
  for (const pattern of RUBY_DANGEROUS) {
    if (code.includes(pattern)) return null;
  }

  // Extract require/require_relative calls.
  const requireRe = /require(?:_relative)?\s*['"]([^'"]+)['"]/g;
  let match: RegExpExecArray | null;
  while ((match = requireRe.exec(code)) !== null) {
    const mod = match[1];
    if (!RUBY_SAFE_REQUIRES.has(mod)) return null;
  }

  // File.open / File.read / File.write patterns.
  if (/File\.\s*(?:write|open|new)/.test(code)) return null;

  return T.PACKAGE_RUN;
}

// ==============================================================================
// Script Execution (node script.js, python app.py, ruby tool.rb)
// ==============================================================================

// Interpreters that can run script files. When the first non-flag argument
// looks like a file path, classify as script_exec rather than unknown.
const SCRIPT_INTERPRETERS = new Set([
  "node", "python", "python3", "ruby", "perl", "php",
  "bun", "deno", "ts-node", "tsx",
]);

// Per-interpreter flags that consume a following value argument. Without
// this, the flag's value would be misidentified as the script path.
const INTERPRETER_VALUE_FLAGS: Record<string, Set<string>> = {
  node: new Set(["--require", "-r", "--loader", "--import", "--input-type", "--conditions", "-C"]),
  bun: new Set(["--require", "-r", "--loader", "--import", "--conditions"]),
  deno: new Set(["--import-map", "--lock", "--config", "-c", "--reload", "--allow-read", "--allow-write", "--allow-net"]),
  python: new Set(["-m", "-W", "-X", "--check-hash-based-pycs"]),
  python3: new Set(["-m", "-W", "-X", "--check-hash-based-pycs"]),
  ruby: new Set(["-r", "-I", "-e", "-E", "--encoding"]),
  perl: new Set(["-I", "-M", "-m", "-e", "-E"]),
  php: new Set(["-d", "-c", "-z"]),
};

export function classifyScriptExec(tokens: string[]): string | null {
  if (tokens.length < 2) return null;
  if (!SCRIPT_INTERPRETERS.has(tokens[0])) return null;

  const valueFlags = INTERPRETER_VALUE_FLAGS[tokens[0]];

  // Find the first non-flag argument after the command name.
  // Skip flags and their value arguments.
  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i];
    if (tok === "--") {
      // Everything after -- is positional; next token is the script.
      if (i + 1 < tokens.length) return isProjectPath(tokens[i + 1]) ? T.SCRIPT_EXEC : null;
      return null;
    }
    if (tok.startsWith("-")) {
      // Skip the value argument for known value-consuming flags.
      if (valueFlags?.has(tok)) i++;
      continue;
    }
    // Found a non-flag argument: this is the script path.
    // Only classify as script_exec for relative paths (project scripts).
    // Absolute and ~ paths could be anywhere and stay as unknown (ask).
    return isProjectPath(tok) ? T.SCRIPT_EXEC : null;
  }
  return null;
}

/** Relative paths are assumed to be project-local; absolute and ~ paths are not. */
function isProjectPath(scriptPath: string): boolean {
  return !scriptPath.startsWith("/") && !scriptPath.startsWith("~");
}
