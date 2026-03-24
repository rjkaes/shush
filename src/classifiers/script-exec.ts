import { SCRIPT_EXEC } from "../taxonomy.js";

// ==============================================================================
// Script Execution (node script.js, python app.py, ruby tool.rb)
// ==============================================================================

// Interpreters that can run script files. When the first non-flag argument
// looks like a file path, classify as script_exec rather than unknown.
const SCRIPT_INTERPRETERS = new Set([
  "node", "python", "python3", "ruby", "perl", "php",
  "bun", "deno", "ts-node", "tsx",
]);

/** Normalize versioned interpreter names: python3.11 -> python3, node18 -> node. */
function normalizeInterpreter(cmd: string): string | null {
  if (SCRIPT_INTERPRETERS.has(cmd)) return cmd;
  // python3.11 -> python3
  const dotStripped = cmd.replace(/\.\d+$/, "");
  if (SCRIPT_INTERPRETERS.has(dotStripped)) return dotStripped;
  // node18 -> node
  const numStripped = cmd.replace(/\d+$/, "");
  if (SCRIPT_INTERPRETERS.has(numStripped)) return numStripped;
  return null;
}

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
  const interpreter = normalizeInterpreter(tokens[0]);
  if (!interpreter) return null;

  const valueFlags = INTERPRETER_VALUE_FLAGS[interpreter];

  // Find the first non-flag argument after the command name.
  // Skip flags and their value arguments.
  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i];
    if (tok === "--") {
      // Everything after -- is positional; next token is the script.
      if (i + 1 < tokens.length) return isProjectPath(tokens[i + 1]) ? SCRIPT_EXEC : null;
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
    return isProjectPath(tok) ? SCRIPT_EXEC : null;
  }
  return null;
}

/** Relative paths are assumed to be project-local; absolute and ~ paths are not. */
function isProjectPath(scriptPath: string): boolean {
  return !scriptPath.startsWith("/") && !scriptPath.startsWith("~");
}
