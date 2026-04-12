// src/path-guard.ts

import { homedir } from "node:os";
import path from "node:path";
import { realpathSync } from "node:fs";
import type { Decision, ShushConfig, SensitivePathEntry, WriteTool, ReadTool } from "./types.js";

const IS_MACOS = process.platform === "darwin";
const HOME = homedir();

/**
 * Resolve symlinks by walking up ancestors until one exists.
 * Returns the realpath of the deepest existing ancestor joined
 * with the remaining tail segments.
 */
function realpathWalk(resolved: string): string {
  try { return realpathSync(resolved); } catch { /* continue */ }
  // Walk up until we find an existing ancestor
  let current = resolved;
  const tail: string[] = [];
  while (true) {
    const parent = path.dirname(current);
    if (parent === current) break; // reached root
    tail.unshift(path.basename(current));
    try {
      return path.join(realpathSync(parent), ...tail);
    } catch {
      current = parent;
    }
  }
  return resolved;
}

/** path.resolve + symlink resolution with ancestor walk for non-existent paths. */
function resolveReal(...segments: string[]): string {
  return realpathWalk(path.resolve(...segments));
}

const HOOKS_DIR = path.resolve(HOME, ".claude", "hooks");
const HOOKS_DIR_REAL = resolveReal(HOME, ".claude", "hooks");

// Sensitive directories and files: [resolved_path, display_name, policy]
const SENSITIVE_DIRS: SensitivePathEntry[] = [
  { resolved: resolveReal(HOME, ".ssh"), display: "~/.ssh", policy: "block" },
  { resolved: resolveReal(HOME, ".gnupg"), display: "~/.gnupg", policy: "block" },
  { resolved: resolveReal(HOME, ".git-credentials"), display: "~/.git-credentials", policy: "block" },
  { resolved: resolveReal(HOME, ".netrc"), display: "~/.netrc", policy: "block" },
  { resolved: resolveReal("/etc/shadow"), display: "/etc/shadow", policy: "block" },
  { resolved: resolveReal("/etc/master.passwd"), display: "/etc/master.passwd", policy: "block" },
  { resolved: resolveReal(HOME, ".aws"), display: "~/.aws", policy: "ask" },
  { resolved: resolveReal(HOME, ".config", "gcloud"), display: "~/.config/gcloud", policy: "ask" },
  { resolved: resolveReal(HOME, ".docker", "config.json"), display: "~/.docker/config.json", policy: "block" },
  { resolved: resolveReal(HOME, ".kube", "config"), display: "~/.kube/config", policy: "block" },
  { resolved: resolveReal(HOME, ".config", "gh", "hosts.yml"), display: "~/.config/gh/hosts.yml", policy: "block" },
  { resolved: resolveReal(HOME, ".claude", "settings.json"), display: "~/.claude/settings.json", policy: "ask" },
  { resolved: resolveReal(HOME, ".claude", "settings.local.json"), display: "~/.claude/settings.local.json", policy: "ask" },
  { resolved: resolveReal(HOME, ".config", "op"), display: "~/.config/op", policy: "ask" },
  { resolved: resolveReal(HOME, ".vault-token"), display: "~/.vault-token", policy: "ask" },
  { resolved: resolveReal(HOME, ".config", "hub"), display: "~/.config/hub", policy: "ask" },
  { resolved: resolveReal(HOME, ".terraform.d", "credentials.tfrc.json"), display: "~/.terraform.d/credentials.tfrc.json", policy: "ask" },
  { resolved: resolveReal(HOME, ".local", "share", "keyrings"), display: "~/.local/share/keyrings", policy: "ask" },
  { resolved: resolveReal(HOME, ".password-store"), display: "~/.password-store", policy: "ask" },
];

// Sensitive basenames: [basename, display_name, policy]
// Tool sets for hook-path protection (hoisted to avoid per-call allocation).
const HOOK_BLOCK_TOOLS: Set<string> = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"] satisfies WriteTool[]);
const HOOK_READONLY_TOOLS: Set<string> = new Set(["Read", "Glob", "Grep"] satisfies ReadTool[]);

const SENSITIVE_BASENAMES: SensitivePathEntry[] = [
  { resolved: ".env", display: ".env", policy: "ask" },
  { resolved: ".env.local", display: ".env.local", policy: "ask" },
  { resolved: ".env.production", display: ".env.production", policy: "ask" },
  { resolved: ".npmrc", display: ".npmrc", policy: "ask" },
  { resolved: ".pypirc", display: ".pypirc", policy: "ask" },
];

/** Expand ~, $HOME, ${HOME} and resolve to absolute canonical path. */
export function resolvePath(raw: string): string {
  if (!raw) return "";
  // Truncate at first null byte (C-string truncation attacks)
  let cleaned = raw.includes("\0") ? raw.slice(0, raw.indexOf("\0")) : raw;
  // Expand $HOME and ${HOME} to home directory (before ~ expansion,
  // since $HOME/... doesn't start with ~).
  cleaned = cleaned.replace(/\$\{HOME\}/g, HOME).replace(/\$HOME(?=\/|$)/g, HOME);
  // Expand ~ or ~/... (not ~user paths, which need OS lookup).
  const expanded = (cleaned === "~" || cleaned.startsWith("~/"))
    ? path.join(HOME, cleaned.slice(1))
    : cleaned;
  let resolved = path.resolve(expanded);
  // Strip /proc/self/root prefix (Linux symlink to /)
  if (resolved.startsWith("/proc/self/root/")) {
    resolved = resolved.slice("/proc/self/root".length);
  }
  // Resolve symlinks walking up ancestors for non-existent paths
  resolved = realpathWalk(resolved);
  return resolved;
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
  // Check both logical and symlink-resolved paths
  for (const dir of [HOOKS_DIR, HOOKS_DIR_REAL]) {
    if (resolved === dir || resolved.startsWith(dir + path.sep)) return true;
  }
  return false;
}

/** Check path against sensitive dirs and basenames. */
export function isSensitive(resolved: string, config?: ShushConfig): { matched: boolean; pattern: string; policy: Decision } {
  if (!resolved) return { matched: false, pattern: "", policy: "allow" };

  // Case-insensitive comparison on macOS (HFS+/APFS default)
  const cmp = IS_MACOS ? resolved.toLowerCase() : resolved;

  // Check directory patterns
  for (const { resolved: dirPath, display, policy } of SENSITIVE_DIRS) {
    const dirCmp = IS_MACOS ? dirPath.toLowerCase() : dirPath;
    if (cmp === dirCmp || cmp.startsWith(dirCmp + path.sep)) {
      return { matched: true, pattern: display, policy };
    }
  }

  // Check basename patterns
  const basename = path.basename(resolved);
  const basenameCmp = IS_MACOS ? basename.toLowerCase() : basename;
  for (const { resolved: name, display, policy } of SENSITIVE_BASENAMES) {
    const nameCmp = IS_MACOS ? name.toLowerCase() : name;
    if (basenameCmp === nameCmp) {
      return { matched: true, pattern: display, policy };
    }
  }

  // Catch .env.* variants (.env.backup, .env.staging, .env.test, etc.)
  // but not .env.example (which typically contains placeholder values)
  if (/^\.env\..+$/.test(basename) && basename !== ".env.example") {
    return { matched: true, pattern: ".env.*", policy: "ask" };
  }

  // Check config-defined sensitive paths
  if (config) {
    for (const [rawPath, policy] of Object.entries(config.sensitivePaths)) {
      const configResolved = resolvePath(rawPath);
      const configCmp = IS_MACOS ? configResolved.toLowerCase() : configResolved;
      if (cmp === configCmp || cmp.startsWith(configCmp + path.sep)) {
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
): { decision: Decision; reason: string } | null {
  if (!rawPath) return null;

  const resolved = resolvePath(rawPath);

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

