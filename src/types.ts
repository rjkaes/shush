// src/types.ts

import ACTION_TYPES_JSON from "../data/types.json";

// ---------------------------------------------------------------------------
// ActionType: derived from data/types.json keys (single source of truth)
// ---------------------------------------------------------------------------

/** The recognized action types, derived at compile time from data/types.json. */
export type ActionType = keyof typeof ACTION_TYPES_JSON;

/** Runtime lookup table keyed by ActionType -> human description. */
export const ACTION_TYPES: Record<ActionType, string> = ACTION_TYPES_JSON;

/** Type guard: narrow a runtime string to ActionType after validation. */
export function isActionType(key: string): key is ActionType {
  return key in ACTION_TYPES_JSON;
}

// ---------------------------------------------------------------------------
// Decision: internal 4-level severity
// ---------------------------------------------------------------------------

/** The four decision levels, ordered by strictness. */
export type Decision = "allow" | "context" | "ask" | "block";

export const STRICTNESS: Record<Decision, number> = {
  allow: 0,
  context: 1,
  ask: 2,
  block: 3,
};

/**
 * A Decision that has passed through stricter() or asFinal().
 * Alias for Decision; marks fields that must be the product of
 * monotonic escalation (ClassifyResult.finalDecision).
 */
export type FinalDecision = Decision;

/** Seed a FinalDecision at the start of an escalation chain. */
export function asFinal(d: Decision): FinalDecision {
  return d;
}

/** Pick the more restrictive of two decisions. */
export function stricter(a: Decision, b: Decision): FinalDecision {
  return (STRICTNESS[a] >= STRICTNESS[b] ? a : b) as FinalDecision;
}

// ---------------------------------------------------------------------------
// PermissionDecision: external hook boundary (3-level)
// ---------------------------------------------------------------------------

/** Decision type for Claude Code hook output (no "context" or "block"). */
export type PermissionDecision = "allow" | "deny" | "ask";

/** Map internal Decision to the hook wire format. */
export function toPermissionDecision(d: Decision): PermissionDecision {
  if (d === "block") return "deny";
  if (d === "context") return "allow";
  return d;
}

// ---------------------------------------------------------------------------
// PipelineOperator
// ---------------------------------------------------------------------------

/** Shell operators that separate pipeline stages. */
export type PipelineOperator = "|" | "&&" | "||" | ";" | "";

// ---------------------------------------------------------------------------
// Tool name types for path-guard dispatch
// ---------------------------------------------------------------------------

/** Tools that path-guard handles directly. */
export type FileToolName =
  | "Read" | "Write" | "Edit" | "MultiEdit" | "NotebookEdit"
  | "Glob" | "Grep";

/** File-writing tools: hook-path writes are blocked. */
export type WriteTool = "Write" | "Edit" | "MultiEdit" | "NotebookEdit";

/** Read-only file tools: hook-path reads are silently allowed. */
export type ReadTool = "Read" | "Glob" | "Grep";

// ---------------------------------------------------------------------------
// SensitivePathEntry
// ---------------------------------------------------------------------------

/** A sensitive path with named fields (replaces positional tuples). */
export interface SensitivePathEntry {
  resolved: string;
  display: string;
  policy: Decision;
}

// ---------------------------------------------------------------------------
// Stage / StageResult / ClassifyResult
// ---------------------------------------------------------------------------

/** A single stage in a pipeline (one command between | operators). */
export interface Stage {
  /** Command tokens (first is the command name). */
  tokens: string[];
  /** The operator that follows this stage. */
  operator: PipelineOperator;
  /** Redirect target path, if > or >> was detected. */
  redirectTarget?: string;
  /** True if >> (append), false if > (truncate). */
  redirectAppend?: boolean;
  /** Env var assignments prefixing the command (e.g., `PAGER=less git log`). */
  envAssignments?: string[];
}

/** Classification result for a single pipeline stage. */
export interface StageResult {
  tokens: string[];
  actionType: string;
  decision: Decision;
  reason: string;
}

/** Overall classification result for a full command string. */
export interface ClassifyResult {
  command: string;
  stages: StageResult[];
  finalDecision: FinalDecision;
  /** The action type of the stage that drove `finalDecision`. */
  actionType: string;
  reason: string;
  compositionRule?: string;
}

// ---------------------------------------------------------------------------
// HookInput / HookOutput
// ---------------------------------------------------------------------------

/** Hook input from Claude Code (stdin JSON). */
export interface HookInput {
  tool_name: string;
  tool_input: Record<string, unknown>;
  session_id?: string;
  cwd?: string;
}

/** Hook output written to stdout. */
export interface HookOutput {
  hookSpecificOutput?: {
    hookEventName: "PreToolUse";
    permissionDecision: PermissionDecision;
    permissionDecisionReason?: string;
    updatedInput?: Record<string, unknown>;
  };
}

// ---------------------------------------------------------------------------
// ShushConfig
// ---------------------------------------------------------------------------

/** User configuration loaded from YAML files. */
export interface ShushConfig {
  /** Action type -> policy override (e.g., `{ filesystem_delete: "ask" }`). */
  actions: Record<string, Decision>;
  /** Path -> policy (e.g., `{ "~/.kube": "ask" }`). Paths are unexpanded. */
  sensitivePaths: Record<string, Decision>;
  /** Action type -> prefix patterns (e.g., `{ db_destructive: ["psql -c DROP"] }`). */
  classify: Record<string, string[]>;
  /** Tool name patterns to always allow (glob-style `*` wildcards). */
  allowTools?: string[];
  /** MCP tool name pattern -> param names containing file paths. */
  mcpPathParams?: Record<string, string[]>;
  /** Glob pattern -> message to append when decision is ask/block. */
  messages?: Record<string, string>;
  /** Glob patterns for redirect targets that should not escalate to filesystem_write. */
  allowRedirects?: string[];
  /** MCP tool glob pattern -> message. Matched tools are blocked with the message. */
  denyTools?: Record<string, string>;
  /** Glob pattern -> message to show after command completes (PostToolUse). */
  afterMessages?: Record<string, string>;
}

/** No-op config: no overrides, no custom paths, no custom classifications. */
export const EMPTY_CONFIG: ShushConfig = {
  actions: {},
  sensitivePaths: {},
  classify: {},
  allowTools: [],
  mcpPathParams: {},
  messages: {},
  allowRedirects: [],
  denyTools: {},
  afterMessages: {},
};

// ---------------------------------------------------------------------------
// EvalInput / EvalResult
// ---------------------------------------------------------------------------

/** Platform-agnostic input for the shared classification core. */
export interface EvalInput {
  toolName: string;
  toolInput: Record<string, unknown>;
  cwd: string | null;
}

/** Classification result from the shared core. */
export interface EvalResult {
  decision: Decision;
  /** The action type that drove the decision (Bash tool only). */
  actionType?: string;
  reason: string;
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/** Simple glob matching: `*` matches any sequence of characters. */
export function globMatch(pattern: string, text: string): boolean {
  const parts = pattern.split("*");
  if (parts.length === 1) return pattern === text;
  if (!text.startsWith(parts[0])) return false;
  if (!text.endsWith(parts[parts.length - 1])) return false;
  let pos = parts[0].length;
  for (let i = 1; i < parts.length - 1; i++) {
    const idx = text.indexOf(parts[i], pos);
    if (idx < 0) return false;
    pos = idx + parts[i].length;
  }
  return true;
}

/** Extract the basename from a possibly path-qualified command name. */
export function cmdBasename(cmd: string): string {
  const slash = cmd.lastIndexOf("/");
  return slash >= 0 ? cmd.slice(slash + 1) : cmd;
}

/**
 * Strip version suffixes from command names so that versioned
 * interpreters (python3.12, node22, bash5.2) match EXEC_SINKS.
 * Tries progressive stripping: .N.N -> trailing digits.
 */
export function normalizeVersionedCmd(cmd: string): string {
  // Strip .N.N.N suffixes: python3.12.1 -> python3, bash5.2 -> bash5
  let normalized = cmd.replace(/(\d)(\.\d+)+$/, "$1");
  // Strip trailing digits: bash5 -> bash, node22 -> node
  // But preserve meaningful ones like python3 (check won't reach here if
  // the caller already found a match with the first normalization).
  if (normalized === cmd) {
    normalized = cmd.replace(/\d+$/, "");
  }
  return normalized;
}
