// src/composition.ts

import type { Decision, Stage, StageResult, ShushConfig } from "./types.js";
import { isHookPath, isSensitive, resolvePath } from "./path-guard.js";
import {
  isExecSinkStage,
  execSinkIgnoresStdin,
  isDecodeStage,
} from "./predicates/composition.js";

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

  // Track data-flow properties across the entire command chain.
  //
  // Pipe operators (|) carry stdin from left to right: literal data flow.
  // Non-pipe operators (&&, ||, ;, newline) do not carry stdin, but the
  // attacker can still smuggle data via filesystem side-effects (a file
  // downloaded by curl, env vars, argv). We therefore *persist* these
  // flags across non-pipe operators and downgrade the resulting decision
  // from `block` to `ask` for indirect flow.
  //
  // The `sensitive_read | network` exfiltration rule is the exception:
  // leaking data does not require stdin, so it stays `block` for any
  // operator.
  let seenSensitiveRead = false;
  let seenNetworkSource = false;
  let seenDecode = false;
  let seenAnyRead = false;

  for (let i = 0; i < stageResults.length - 1; i++) {
    const left = stageResults[i];
    const isPipe = i < stages.length && stages[i].operator === "|";

    // Accumulate properties from the left stage
    if (isSensitiveRead(left, config)) seenSensitiveRead = true;
    if (left.actionType === "network_outbound" || left.actionType === "network_write")
      seenNetworkSource = true;
    if (isDecodeStage(left.tokens)) seenDecode = true;
    if (left.actionType === "filesystem_read") seenAnyRead = true;

    const right = stageResults[i + 1];

    // sensitive_read | ... | network -> block (exfiltration)
    if (
      seenSensitiveRead &&
      (right.actionType === "network_outbound" || right.actionType === "network_write")
    ) {
      return [
        "block",
        `data exfiltration: ${right.tokens[0]} receives sensitive input`,
        "sensitive_read | network",
      ];
    }

    // network | exec  -> block (literal stdin: remote code execution)
    // network ; exec  -> ask   (indirect: file/env smuggle)
    // For pipes, skip when exec has inline code flag: stdin is data, not
    // code. For non-pipe operators there is no stdin, so the exclusion
    // does not apply: the threat is the file the exec sink reads next.
    if (
      seenNetworkSource &&
      isExecSinkStage(right) &&
      (!isPipe || !execSinkIgnoresStdin(right))
    ) {
      return [
        isPipe ? "block" : "ask",
        `remote code execution: ${right.tokens[0]} follows network source`,
        isPipe ? "network | exec" : "network ; exec",
      ];
    }

    // decode | exec -> block (obfuscation via stdin)
    // decode ; exec -> ask   (indirect obfuscation via filesystem/env)
    // Same rationale as above: only check execSinkIgnoresStdin for pipes.
    if (
      seenDecode &&
      isExecSinkStage(right) &&
      (!isPipe || !execSinkIgnoresStdin(right))
    ) {
      return [
        isPipe ? "block" : "ask",
        `obfuscated execution: ${right.tokens[0]} follows decode`,
        isPipe ? "decode | exec" : "decode ; exec",
      ];
    }

    // any_read | exec -> ask (local code execution)
    // any_read ; exec -> ask (same severity; persisted across operators)
    // Same rationale as above: only check execSinkIgnoresStdin for pipes.
    if (
      seenAnyRead &&
      isExecSinkStage(right) &&
      (!isPipe || !execSinkIgnoresStdin(right))
    ) {
      return [
        "ask",
        `local code execution: ${right.tokens[0]} follows file read`,
        isPipe ? "read | exec" : "read ; exec",
      ];
    }
  }

  return ["", "", ""];
}
