import { PACKAGE_RUN } from "../taxonomy.js";

// ==============================================================================
// Inline Code (python -c, node -e, ruby -e)
// ==============================================================================

// Maps command → flag that introduces inline code, so we can extract the payload.
export const INLINE_CODE_CMDS: Record<string, string[]> = {
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
export function classifyInlineCode(tokens: string[]): string | null {
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

  return PACKAGE_RUN;
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

  return PACKAGE_RUN;
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

  return PACKAGE_RUN;
}
