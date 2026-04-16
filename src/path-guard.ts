// src/path-guard.ts

import path from "node:path";
import type { Decision, ShushConfig } from "./types.js";
import {
  resolvePath, friendlyPath, isHookPath, isSensitive, resolveReal,
  HOOK_BLOCK_TOOLS, HOOK_READONLY_TOOLS,
} from "./predicates/path.js";

export { resolvePath, friendlyPath, isHookPath, isSensitive } from "./predicates/path.js";

/** Check a path for hook/sensitive violations. Returns decision dict or null (= allow). */
export function checkPath(
  toolName: string,
  rawPath: string,
  config?: ShushConfig,
): { decision: Decision; reason: string } | null {
  if (!rawPath) return null;

  // Detect ~user paths (e.g., ~root/.ssh/id_rsa) and check their
  // relative component against sensitive dirs by substituting ~.
  if (/^~[a-zA-Z0-9_]/.test(rawPath) && rawPath.includes("/")) {
    const slashIdx = rawPath.indexOf("/");
    const afterUser = rawPath.slice(slashIdx);
    const pseudoPath = "~" + afterUser;
    const pseudoResolved = resolvePath(pseudoPath);
    const sens = isSensitive(pseudoResolved, config);
    if (sens.matched) {
      return {
        decision: sens.policy,
        reason: `${toolName} targets sensitive path: ${sens.pattern}`,
      };
    }
  }

  const resolved = resolvePath(rawPath);

  // Hook self-protection: Write/Edit get block
  if (isHookPath(resolved)) {
    if (HOOK_BLOCK_TOOLS.has(toolName)) {
      return {
        decision: "block",
        reason: `${toolName} targets hook directory: ~/.claude/hooks/ (self-modification blocked)`,
      };
    }
    // Read-only tools can inspect hooks without prompting
    if (HOOK_READONLY_TOOLS.has(toolName)) {
      return null;
    }
    return {
      decision: "ask",
      reason: `${toolName} targets hook directory: ~/.claude/hooks/`,
    };
  }

  // Sensitive paths
  const { matched, pattern, policy } = isSensitive(resolved, config);
  if (matched) {
    return {
      decision: policy,
      reason: `${toolName} targets sensitive path: ${pattern}`,
    };
  }

  return null;
}

/** Check if path is outside project root. Returns decision dict or null (= allow). */
export function checkProjectBoundary(
  toolName: string,
  rawPath: string,
  projectRoot: string | null,
  allowedPaths?: string[],
): { decision: Decision; reason: string } | null {
  if (!rawPath) return null;

  const resolved = resolvePath(rawPath);

  if (allowedPaths) {
    for (const raw of allowedPaths) {
      const allowed = resolvePath(raw);
      if (resolved === allowed || resolved.startsWith(allowed + path.sep)) {
        return null; // inside allowed path, no boundary violation
      }
    }
  }

  if (projectRoot === null) {
    return {
      decision: "ask",
      reason: `${toolName} outside project (no git root): ${friendlyPath(resolved)}`,
    };
  }

  const realRoot = resolveReal(projectRoot);
  if (resolved === realRoot || resolved.startsWith(realRoot + path.sep)) {
    return null; // inside project
  }

  return {
    decision: "ask",
    reason: `${toolName} outside project: ${friendlyPath(resolved)}`,
  };
}
