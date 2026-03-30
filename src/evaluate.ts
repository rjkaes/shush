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
import { EMPTY_CONFIG, stricter } from "./types.js";

/**
 * Check whether a tool name matches any pattern in the allow list.
 * Patterns support `*` as a wildcard matching any sequence of characters.
 */
function isToolAllowed(toolName: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (globMatch(pattern, toolName)) return true;
  }
  return false;
}

/** Simple glob match: `*` matches any substring, everything else is literal. */
function globMatch(pattern: string, text: string): boolean {
  const parts = pattern.split("*");
  if (parts.length === 1) return pattern === text;
  // Check prefix
  if (!text.startsWith(parts[0])) return false;
  // Check suffix
  if (!text.endsWith(parts[parts.length - 1])) return false;
  // Check middle parts appear in order
  let pos = parts[0].length;
  for (let i = 1; i < parts.length - 1; i++) {
    const idx = text.indexOf(parts[i], pos);
    if (idx < 0) return false;
    pos = idx + parts[i].length;
  }
  return true;
}

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
  let actionType: string | undefined;
  let reason = "";

  switch (toolName) {
    case "Bash": {
      const command = (toolInput.command as string) ?? "";
      const result = classifyCommand(command, 0, config);
      decision = result.finalDecision;
      actionType = result.actionType;
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
    case "MultiEdit": {
      // MultiEdit applies multiple edits to a single file.
      const filePath = (toolInput.file_path as string) ?? "";
      const edits = (toolInput.edits as Array<{ old_string: string; new_string: string }>) ?? [];
      const allContent = edits.map((e) => e.new_string ?? "").join("\n");
      const result = checkFileWrite("MultiEdit", filePath, allContent, projectRoot, config);
      decision = result.decision;
      reason = result.reason;
      break;
    }
    case "NotebookEdit": {
      const notebookPath = (toolInput.notebook_path as string) ?? "";
      const newSource = (toolInput.new_source as string) ?? "";
      const result = checkFileWrite("NotebookEdit", notebookPath, newSource, projectRoot, config);
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
      // Project boundary check (same as Write/Edit).
      if (decision === "allow" && globPath) {
        const boundaryResult = checkProjectBoundary("Glob", globPath, projectRoot);
        if (boundaryResult) {
          decision = boundaryResult.decision;
          reason = boundaryResult.reason;
        }
      }
      break;
    }
    case "Grep": {
      const grepPath = (toolInput.path as string) ?? "";
      const pattern = (toolInput.pattern as string) ?? "";
      if (grepPath) {
        const pathResult = checkPath("Grep", grepPath, config);
        if (pathResult) {
          decision = pathResult.decision;
          reason = pathResult.reason;
        }
        // Project boundary check (same as Write/Edit).
        if (decision === "allow") {
          const boundaryResult = checkProjectBoundary("Grep", grepPath, projectRoot);
          if (boundaryResult) {
            decision = boundaryResult.decision;
            reason = boundaryResult.reason;
          }
        }
      }
      if (decision === "allow" && isCredentialSearch(pattern)) {
        decision = "ask";
        reason = "Grep pattern looks like credential search";
      }
      break;
    }
    default: {
      // Generic MCP tool guard: any tool starting with mcp__ is a
      // third-party MCP server call. Default to "ask" so the user
      // confirms before unknown external tools execute.
      if (toolName.startsWith("mcp__") && !isToolAllowed(toolName, config.allowTools ?? [])) {
        decision = "ask";
        reason = `MCP tool call: ${toolName} (unclassified third-party tool)`;
      }
      break;
    }
  }

  return { decision, actionType, reason };
}
