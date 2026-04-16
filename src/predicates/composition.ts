// src/predicates/composition.ts
// Pure composition predicates factored out of src/composition.ts.
// No side effects; suitable for Z3 proof harnesses and unit testing.

import type { PipelineOperator, StageResult } from "../types.js";
import { cmdBasename } from "../types.js";
import { isExecSink, DECODE_COMMANDS } from "../taxonomy.js";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const PIPE_OPERATORS: ReadonlySet<PipelineOperator> = new Set(["|"]);
export const RESET_OPERATORS: ReadonlySet<PipelineOperator> = new Set(["&&", "||", ";", ""]);

export function operatorResetsPipeline(op: PipelineOperator): boolean {
  return RESET_OPERATORS.has(op);
}

// Exec sinks and the flags that make them run inline code (from the
// argument) rather than reading code from stdin. When an exec sink has
// one of these flags, piped input is just data, not code to execute.
export const INLINE_CODE_FLAGS: Record<string, Set<string>> = {
  bash: new Set(["-c"]),
  sh: new Set(["-c"]),
  dash: new Set(["-c"]),
  zsh: new Set(["-c"]),
  fish: new Set(["-c"]),
  python: new Set(["-c"]),
  python3: new Set(["-c"]),
  node: new Set(["-e", "--eval"]),
  bun: new Set(["-e", "--eval"]),
  deno: new Set(["eval"]),
  ruby: new Set(["-e"]),
  perl: new Set(["-e", "-E"]),
  php: new Set(["-r"]),
  pwsh: new Set(["-Command", "-c"]),
  powershell: new Set(["-Command", "-c"]),
};

/** Check if a stage is an exec sink (bash, python, etc.). */
export function isExecSinkStage(sr: StageResult): boolean {
  if (sr.tokens.length === 0) return false;
  const cmd = cmdBasename(sr.tokens[0]);
  return isExecSink(cmd);
}

/**
 * Check if an exec sink already knows what code to run, meaning piped
 * input is data, not executable code. True when the interpreter has:
 * - an inline code flag (-e, -c, --eval), or
 * - a script file argument (classified as script_exec)
 */
export function execSinkIgnoresStdin(sr: StageResult): boolean {
  if (sr.actionType === "script_exec") return true;
  const cmd = cmdBasename(sr.tokens[0]);
  const flags = INLINE_CODE_FLAGS[cmd];
  if (!flags) return false;
  // Only ignore stdin when the inline code flag has an actual code argument.
  // bash -c 'code' ignores stdin; bash -c (no arg, from xargs) does not.
  for (let i = 0; i < sr.tokens.length; i++) {
    if (flags.has(sr.tokens[i]) && i + 1 < sr.tokens.length) return true;
  }
  return false;
}

/** Check if tokens represent a decode command (base64 -d, xxd -r, etc.). */
export function isDecodeStage(tokens: string[]): boolean {
  if (tokens.length === 0) return false;
  const cmd = tokens[0];
  for (const [decodeCmd, flag] of DECODE_COMMANDS) {
    if (cmd !== decodeCmd) continue;
    if (flag === null) return true;
    if (tokens.includes(flag)) return true;
  }
  // openssl enc -d is a decode command (equivalent to base64 -d)
  if (cmd === "openssl" && tokens.includes("enc") && tokens.includes("-d")) return true;
  // perl with MIME::Base64 decode
  if (cmd === "perl" && tokens.some(t => t.includes("decode_base64") || t.includes("MIME::Base64"))) return true;
  return false;
}

// Read data/classify_full/*.json once; cache.
// Returns: map command name -> set of action types it is classified as (write-y actions only).
let cachedWriteEmitters: Map<string, Set<string>> | null = null;

const WRITE_ACTIONS = new Set(["filesystem_write", "filesystem_delete", "disk_destructive"]);

/**
 * Scan data/classify_full/*.json and return a map of command name ->
 * set of write-flavoured action types (filesystem_write, filesystem_delete,
 * disk_destructive) that the command is classified under.
 *
 * Results are cached after the first call. Pass `dataDir` to override
 * the default location (used by tests / Z3 harnesses).
 */
export function writeEmittersFromData(dataDir?: string): Map<string, Set<string>> {
  if (!dataDir && cachedWriteEmitters) return cachedWriteEmitters;
  const dir = dataDir ?? path.resolve(
    fileURLToPath(new URL("../..", import.meta.url)),
    "data", "classify_full",
  );
  const out = new Map<string, Set<string>>();
  for (const file of readdirSync(dir)) {
    if (!file.endsWith(".json")) continue;
    const cmd = file.replace(/\.json$/, "");
    const contents = JSON.parse(readFileSync(path.join(dir, file), "utf-8")) as Record<string, unknown>;
    const actions = new Set<string>();
    for (const key of Object.keys(contents)) {
      if (WRITE_ACTIONS.has(key)) actions.add(key);
    }
    if (actions.size > 0) out.set(cmd, actions);
  }
  if (!dataDir) cachedWriteEmitters = out;
  return out;
}
