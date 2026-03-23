// test/eval-helpers.ts
//
// Shared helpers for evaluate-based tests. Each helper constructs an
// EvalInput for a specific tool and calls evaluate(), returning the
// { decision, reason } result.

import { evaluate } from "../src/evaluate";
import type { Decision, ShushConfig } from "../src/types";

export function bash(command: string, config?: ShushConfig) {
  return evaluate(
    { toolName: "Bash", toolInput: { command }, cwd: "/tmp/project" },
    config,
  );
}

export function read(file_path: string, config?: ShushConfig) {
  return evaluate(
    { toolName: "Read", toolInput: { file_path }, cwd: "/tmp/project" },
    config,
  );
}

export function write(
  file_path: string,
  content: string,
  cwd?: string | null,
  config?: ShushConfig,
) {
  return evaluate(
    { toolName: "Write", toolInput: { file_path, content }, cwd: cwd ?? "/tmp/project" },
    config,
  );
}

export function edit(file_path: string, new_string: string, config?: ShushConfig) {
  return evaluate(
    { toolName: "Edit", toolInput: { file_path, new_string }, cwd: "/tmp/project" },
    config,
  );
}

export function glob(pathStr: string, pattern?: string, config?: ShushConfig) {
  return evaluate(
    { toolName: "Glob", toolInput: { path: pathStr, pattern: pattern ?? "" }, cwd: "/tmp/project" },
    config,
  );
}

export function grep(pathStr: string, pattern: string, config?: ShushConfig) {
  return evaluate(
    { toolName: "Grep", toolInput: { path: pathStr, pattern }, cwd: "/tmp/project" },
    config,
  );
}

// Decision severity ordering: allow < context < ask < block
const STRICTNESS: Record<Decision, number> = {
  allow: 0,
  context: 1,
  ask: 2,
  block: 3,
};

export function atLeast(actual: Decision, minimum: Decision): boolean {
  return STRICTNESS[actual] >= STRICTNESS[minimum];
}
