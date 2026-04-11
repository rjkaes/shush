import { describe, expect, test } from "bun:test";
import { bash, atLeast } from "./eval-helpers";
import type { ShushConfig } from "../src/types";

// =============================================================================
// P0: Config messages — attach user-facing messages to ask/block decisions
// =============================================================================

describe("config messages", () => {
  test("message appended to block reason when pattern matches", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      messages: {
        "python *": "Use uv run python instead",
      },
    };
    const result = bash("python -c 'import os'", config);
    expect(result.decision).not.toBe("allow");
    expect(result.reason).toContain("Use uv run python instead");
  });

  test("message appended to ask reason when pattern matches", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      messages: {
        "git push --force *": "Force-pushing rewrites history",
      },
    };
    const result = bash("git push --force origin main", config);
    expect(result.decision).not.toBe("allow");
    expect(result.reason).toContain("Force-pushing rewrites history");
  });

  test("no message when pattern does not match", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      messages: {
        "python *": "Use uv run python instead",
      },
    };
    const result = bash("git status", config);
    expect(result.decision).toBe("allow");
    expect(result.reason).not.toContain("Use uv run python");
  });

  test("no message appended when decision is allow", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      messages: {
        "ls *": "This should not appear",
      },
    };
    const result = bash("ls -la", config);
    expect(result.decision).toBe("allow");
    expect(result.reason).not.toContain("This should not appear");
  });

  test("glob wildcard matches partial commands", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      messages: {
        "rm -rf *": "Think twice before recursive delete",
      },
    };
    const result = bash("rm -rf /tmp/data", config);
    expect(result.reason).toContain("Think twice before recursive delete");
  });

  test("first matching pattern wins", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      messages: {
        "rm *": "Generic rm message",
        "rm -rf *": "Specific rf message",
      },
    };
    const result = bash("rm -rf /tmp/data", config);
    expect(result.reason).toContain("Generic rm message");
  });
});
