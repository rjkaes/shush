// src/evaluate.ts
//
// Platform-agnostic classification core. Both the Claude Code hook
// (hooks/pretooluse.ts) and the OpenCode plugin (plugins/opencode.ts)
// delegate to this module.

import { classifyCommand } from "./bash-guard.js";
import { checkPath, checkProjectBoundary } from "./path-guard.js";
import {
  scanContent,
  isCredentialSearch,
  formatContentMessage,
} from "./content-guard.js";
import type { Decision, ShushConfig, EvalInput, EvalResult } from "./types.js";
import { EMPTY_CONFIG } from "./types.js";

/** Shared path + boundary + content check for file-writing tools. */
function checkFileWrite(
  toolName: string,
  filePath: string,
  content: string,
  projectRoot: string | null,
  config: ShushConfig,
): { decision: Decision; reason: string } {
  let decision: Decision = "allow";
  let reason = "";

  const pathResult = checkPath(toolName, filePath, config);
  if (pathResult) {
    decision = pathResult.decision;
    reason = pathResult.reason;
  }
  if (decision === "allow") {
    const boundaryResult = checkProjectBoundary(
      toolName,
      filePath,
      projectRoot,
    );
    if (boundaryResult) {
      decision = boundaryResult.decision;
      reason = boundaryResult.reason;
    }
  }
  if (decision !== "block") {
    const matches = scanContent(content);
    if (matches.length > 0) {
      const contentReason = formatContentMessage(toolName, matches);
      // Append content findings to existing reason when path already flagged.
      reason = reason ? `${reason}; ${contentReason}` : contentReason;
      if (decision === "allow" || decision === "context") {
        decision = "ask";
      }
    }
  }
  return { decision, reason };
}

/**
 * Classify a tool call and return a decision.
 *
 * This is the shared core used by both the Claude Code PreToolUse hook
 * and the OpenCode plugin. It dispatches to the appropriate guard
 * module based on tool name and returns the strictest decision.
 */
export function evaluate(
  input: EvalInput,
  config: ShushConfig = EMPTY_CONFIG,
): EvalResult {
  const { toolName, toolInput, cwd: projectRoot } = input;

  let decision: Decision = "allow";
  let reason = "";

  switch (toolName) {
    case "Bash": {
      const command = (toolInput.command as string) ?? "";
      const result = classifyCommand(command, 0, config);
      decision = result.finalDecision;
      reason = result.reason;
      break;
    }
    case "Read": {
      const filePath = (toolInput.file_path as string) ?? "";
      const pathResult = checkPath("Read", filePath, config);
      if (pathResult) {
        decision = pathResult.decision;
        reason = pathResult.reason;
      }
      break;
    }
    case "Write": {
      const result = checkFileWrite(
        "Write",
        (toolInput.file_path as string) ?? "",
        (toolInput.content as string) ?? "",
        projectRoot,
        config,
      );
      decision = result.decision;
      reason = result.reason;
      break;
    }
    case "Edit": {
      const result = checkFileWrite(
        "Edit",
        (toolInput.file_path as string) ?? "",
        (toolInput.new_string as string) ?? "",
        projectRoot,
        config,
      );
      decision = result.decision;
      reason = result.reason;
      break;
    }
    case "Glob": {
      const globPath = (toolInput.path as string) ?? "";
      const globPattern = (toolInput.pattern as string) ?? "";
      // Check both path and pattern for sensitive locations.
      for (const p of [globPath, globPattern]) {
        if (!p) continue;
        const pathResult = checkPath("Glob", p, config);
        if (pathResult) {
          decision = pathResult.decision;
          reason = pathResult.reason;
          break;
        }
      }
      break;
    }
    case "Grep": {
      const path = (toolInput.path as string) ?? "";
      const pattern = (toolInput.pattern as string) ?? "";
      if (path) {
        const pathResult = checkPath("Grep", path, config);
        if (pathResult) {
          decision = pathResult.decision;
          reason = pathResult.reason;
        }
      }
      if (decision === "allow" && isCredentialSearch(pattern)) {
        decision = "ask";
        reason = "Grep pattern looks like credential search";
      }
      break;
    }
  }

  return { decision, reason };
}
