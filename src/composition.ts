// src/composition.ts

import type { Decision, Stage, StageResult, ShushConfig } from "./types.js";
import { EXEC_SINKS, DECODE_COMMANDS } from "./taxonomy.js";
import { isHookPath, isSensitive, resolvePath } from "./path-guard.js";

/** Check if a stage reads from a sensitive path. */
function isSensitiveRead(sr: StageResult, config?: ShushConfig): boolean {
  if (sr.actionType !== "filesystem_read") return false;
  for (const tok of sr.tokens.slice(1)) {
    if (tok.startsWith("-")) continue;
    const resolved = resolvePath(tok);
    if (isHookPath(resolved)) return true;
    if (isSensitive(resolved, config).matched) return true;
  }
  return false;
}

/** Check if a stage is an exec sink (bash, python, etc.). */
function isExecSinkStage(sr: StageResult): boolean {
  return sr.tokens.length > 0 && EXEC_SINKS.has(sr.tokens[0]);
}

/** Check if tokens represent a decode command (base64 -d, xxd -r, etc.). */
function isDecodeStage(tokens: string[]): boolean {
  if (tokens.length === 0) return false;
  const cmd = tokens[0];
  for (const [decodeCmd, flag] of DECODE_COMMANDS) {
    if (cmd !== decodeCmd) continue;
    if (flag === null) return true;
    if (tokens.includes(flag)) return true;
  }
  return false;
}

/**
 * Check pipe composition rules.
 * Returns [decision, reason, rule] where decision is "" if no rule triggered.
 */
export function checkComposition(
  stageResults: StageResult[],
  stages: Stage[],
  config?: ShushConfig,
): [Decision | "", string, string] {
  if (stageResults.length < 2) return ["", "", ""];

  for (let i = 0; i < stageResults.length - 1; i++) {
    // Only check pipe compositions (not && or ||)
    if (i < stages.length && stages[i].operator !== "|") continue;

    const left = stageResults[i];
    const right = stageResults[i + 1];

    // sensitive_read | network -> block (exfiltration)
    if (
      isSensitiveRead(left, config) &&
      (right.actionType === "network_outbound" || right.actionType === "network_write")
    ) {
      return [
        "block",
        `data exfiltration: ${right.tokens[0]} receives sensitive input`,
        "sensitive_read | network",
      ];
    }

    // network | exec -> block (remote code execution)
    if (
      (left.actionType === "network_outbound" || left.actionType === "network_write") &&
      isExecSinkStage(right)
    ) {
      return [
        "block",
        `remote code execution: ${right.tokens[0]} receives network input`,
        "network | exec",
      ];
    }

    // decode | exec -> block (obfuscation)
    if (isDecodeStage(left.tokens) && isExecSinkStage(right)) {
      return [
        "block",
        `obfuscated execution: ${right.tokens[0]} receives decoded input`,
        "decode | exec",
      ];
    }

    // any_read | exec -> ask
    if (left.actionType === "filesystem_read" && isExecSinkStage(right)) {
      return [
        "ask",
        `local code execution: ${right.tokens[0]} receives file input`,
        "read | exec",
      ];
    }
  }

  return ["", "", ""];
}
