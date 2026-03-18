// src/types.ts

/** The four decision levels, ordered by strictness. */
export type Decision = "allow" | "context" | "ask" | "block";

export const STRICTNESS: Record<Decision, number> = {
  allow: 0,
  context: 1,
  ask: 2,
  block: 3,
};

/** Pick the more restrictive of two decisions. */
export function stricter(a: Decision, b: Decision): Decision {
  return STRICTNESS[a] >= STRICTNESS[b] ? a : b;
}

/** A single stage in a pipeline (one command between | operators). */
export interface Stage {
  /** Command tokens (first is the command name). */
  tokens: string[];
  /** The operator that follows this stage: "|", "&&", "||", ";", or "". */
  operator: string;
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
  defaultPolicy: Decision;
  decision: Decision;
  reason: string;
}

/** Overall classification result for a full command string. */
export interface ClassifyResult {
  command: string;
  stages: StageResult[];
  finalDecision: Decision;
  reason: string;
  compositionRule?: string;
}

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
    permissionDecision: "allow" | "deny" | "ask";
    permissionDecisionReason?: string;
    updatedInput?: Record<string, unknown>;
  };
}

/** User configuration loaded from YAML files. */
export interface ShushConfig {
  /** Action type -> policy override (e.g., `{ filesystem_delete: "ask" }`). */
  actions: Record<string, Decision>;
  /** Path -> policy (e.g., `{ "~/.kube": "ask" }`). Paths are unexpanded. */
  sensitivePaths: Record<string, Decision>;
  /** Action type -> prefix patterns (e.g., `{ db_destructive: ["psql -c DROP"] }`). */
  classify: Record<string, string[]>;
}

/** No-op config: no overrides, no custom paths, no custom classifications. */
export const EMPTY_CONFIG: ShushConfig = {
  actions: {},
  sensitivePaths: {},
  classify: {},
};
