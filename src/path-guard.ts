// src/path-guard.ts

import { homedir } from "node:os";
import path from "node:path";
import { realpathSync } from "node:fs";
import type { Decision, ShushConfig } from "./types.js";

const IS_MACOS = process.platform === "darwin";
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
  [path.resolve(HOME, ".docker", "config.json"), "~/.docker/config.json", "block"],
  [path.resolve(HOME, ".kube", "config"), "~/.kube/config", "block"],
  [path.resolve(HOME, ".config", "gh", "hosts.yml"), "~/.config/gh/hosts.yml", "block"],
  [path.resolve(HOME, ".claude", "settings.json"), "~/.claude/settings.json", "ask"],
  [path.resolve(HOME, ".claude", "settings.local.json"), "~/.claude/settings.local.json", "ask"],
  [path.resolve(HOME, ".config", "op"), "~/.config/op", "ask"],
  [path.resolve(HOME, ".vault-token"), "~/.vault-token", "ask"],
  [path.resolve(HOME, ".config", "hub"), "~/.config/hub", "ask"],
  [path.resolve(HOME, ".terraform.d", "credentials.tfrc.json"), "~/.terraform.d/credentials.tfrc.json", "ask"],
  [path.resolve(HOME, ".local", "share", "keyrings"), "~/.local/share/keyrings", "ask"],
  [path.resolve(HOME, ".password-store"), "~/.password-store", "ask"],
];

// Sensitive basenames: [basename, display_name, policy]
// Tool sets for hook-path protection (hoisted to avoid per-call allocation).
const HOOK_BLOCK_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);
const HOOK_READONLY_TOOLS = new Set(["Read", "Glob", "Grep"]);

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
  // Truncate at first null byte (C-string truncation attacks)
  let cleaned = raw.includes("\0") ? raw.slice(0, raw.indexOf("\0")) : raw;
  // Only expand ~ or ~/... (not ~user paths, which need OS lookup).
  const expanded = (cleaned === "~" || cleaned.startsWith("~/"))
    ? path.join(HOME, cleaned.slice(1))
    : cleaned;
  let resolved = path.resolve(expanded);
  // Strip /proc/self/root prefix (Linux symlink to /)
  if (resolved.startsWith("/proc/self/root/")) {
    resolved = resolved.slice("/proc/self/root".length);
  }
  // Resolve symlinks so that e.g. ~/innocent-link -> ~/.ssh/id_rsa
  // is caught by sensitive-path checks. Only when the target exists;
  // Write targets may not exist yet.
  try {
    resolved = realpathSync(resolved);
  } catch {
    // Path does not exist yet (e.g. a new file being written).
  }
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
  return resolved === HOOKS_DIR || resolved.startsWith(HOOKS_DIR + path.sep);
}

/** Check path against sensitive dirs and basenames. */
export function isSensitive(resolved: string, config?: ShushConfig): { matched: boolean; pattern: string; policy: Decision } {
  if (!resolved) return { matched: false, pattern: "", policy: "allow" };

  // Case-insensitive comparison on macOS (HFS+/APFS default)
  const cmp = IS_MACOS ? resolved.toLowerCase() : resolved;

  // Check directory patterns
  for (const [dirPath, display, policy] of SENSITIVE_DIRS) {
    const dirCmp = IS_MACOS ? dirPath.toLowerCase() : dirPath;
    if (cmp === dirCmp || cmp.startsWith(dirCmp + path.sep)) {
      return { matched: true, pattern: display, policy };
    }
  }

  // Check basename patterns
  const basename = path.basename(resolved);
  const basenameCmp = IS_MACOS ? basename.toLowerCase() : basename;
  for (const [name, display, policy] of SENSITIVE_BASENAMES) {
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

  const realRoot = path.resolve(projectRoot);
  if (resolved === realRoot || resolved.startsWith(realRoot + path.sep)) {
    return null; // inside project
  }

  return {
    decision: "ask",
    reason: `${toolName} outside project: ${friendlyPath(resolved)}`,
  };
}

