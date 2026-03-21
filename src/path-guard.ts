// src/path-guard.ts

import { homedir } from "node:os";
import path from "node:path";
import type { Decision, ShushConfig } from "./types.js";

const HOME = homedir();
const HOOKS_DIR = path.resolve(HOME, ".claude", "hooks");

// Sensitive directories and files: [resolved_path, display_name, policy]
const SENSITIVE_DIRS: Array<[string, string, Decision]> = [
  [path.resolve(HOME, ".ssh"), "~/.ssh", "block"],
  [path.resolve(HOME, ".gnupg"), "~/.gnupg", "block"],
  [path.resolve(HOME, ".git-credentials"), "~/.git-credentials", "block"],
  [path.resolve(HOME, ".netrc"), "~/.netrc", "block"],
  [path.resolve("/etc/shadow"), "/etc/shadow", "block"],
  [path.resolve("/etc/master.passwd"), "/etc/master.passwd", "block"],
  [path.resolve(HOME, ".aws"), "~/.aws", "ask"],
  [path.resolve(HOME, ".config", "gcloud"), "~/.config/gcloud", "ask"],
  [path.resolve(HOME, ".claude", "settings.json"), "~/.claude/settings.json", "ask"],
  [path.resolve(HOME, ".claude", "settings.local.json"), "~/.claude/settings.local.json", "ask"],
];

// Sensitive basenames: [basename, display_name, policy]
const SENSITIVE_BASENAMES: Array<[string, string, Decision]> = [
  [".env", ".env", "ask"],
  [".env.local", ".env.local", "ask"],
  [".env.production", ".env.production", "ask"],
  [".npmrc", ".npmrc", "ask"],
  [".pypirc", ".pypirc", "ask"],
];

/** Expand ~ and resolve to absolute canonical path. */
export function resolvePath(raw: string): string {
  if (!raw) return "";
  const expanded = raw.startsWith("~") ? path.join(HOME, raw.slice(1)) : raw;
  return path.resolve(expanded);
}

/** Replace home directory prefix with ~ for display. */
export function friendlyPath(resolved: string): string {
  if (resolved.startsWith(HOME + path.sep)) {
    return "~" + resolved.slice(HOME.length);
  }
  if (resolved === HOME) return "~";
  return resolved;
}

/** Check if path targets ~/.claude/hooks/ (self-protection). */
export function isHookPath(resolved: string): boolean {
  if (!resolved) return false;
  return resolved === HOOKS_DIR || resolved.startsWith(HOOKS_DIR + path.sep);
}

/** Check path against sensitive dirs and basenames. */
export function isSensitive(resolved: string, config?: ShushConfig): { matched: boolean; pattern: string; policy: Decision } {
  if (!resolved) return { matched: false, pattern: "", policy: "allow" };

  // Check directory patterns
  for (const [dirPath, display, policy] of SENSITIVE_DIRS) {
    if (resolved === dirPath || resolved.startsWith(dirPath + path.sep)) {
      return { matched: true, pattern: display, policy };
    }
  }

  // Check basename patterns
  const basename = path.basename(resolved);
  for (const [name, display, policy] of SENSITIVE_BASENAMES) {
    if (basename === name) {
      return { matched: true, pattern: display, policy };
    }
  }

  // Check config-defined sensitive paths
  if (config) {
    for (const [rawPath, policy] of Object.entries(config.sensitivePaths)) {
      const configResolved = resolvePath(rawPath);
      if (resolved === configResolved || resolved.startsWith(configResolved + path.sep)) {
        return { matched: true, pattern: rawPath, policy };
      }
    }
  }

  return { matched: false, pattern: "", policy: "allow" };
}

/** Check a path for hook/sensitive violations. Returns decision dict or null (= allow). */
export function checkPath(
  toolName: string,
  rawPath: string,
  config?: ShushConfig,
): { decision: Decision; reason: string } | null {
  if (!rawPath) return null;

  const resolved = resolvePath(rawPath);

  // Hook self-protection: Write/Edit get block
  if (isHookPath(resolved)) {
    const hookBlockTools = new Set(["Write", "Edit"]);
    if (hookBlockTools.has(toolName)) {
      return {
        decision: "block",
        reason: `${toolName} targets hook directory: ~/.claude/hooks/ (self-modification blocked)`,
      };
    }
    // Read-only tools can inspect hooks without prompting
    const readOnlyTools = new Set(["Read", "Glob", "Grep"]);
    if (readOnlyTools.has(toolName)) {
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
): { decision: Decision; reason: string } | null {
  if (!rawPath) return null;

  const resolved = resolvePath(rawPath);

  if (projectRoot === null) {
    return {
      decision: "ask",
      reason: `${toolName} outside project (no git root): ${friendlyPath(resolved)}`,
    };
  }

  const realRoot = path.resolve(projectRoot);
  if (resolved === realRoot || resolved.startsWith(realRoot + path.sep)) {
    return null; // inside project
  }

  return {
    decision: "ask",
    reason: `${toolName} outside project: ${friendlyPath(resolved)}`,
  };
}
