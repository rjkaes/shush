import { describe, expect, test } from "bun:test";
import { evaluate } from "../src/evaluate";
import type { ShushConfig } from "../src/types";

// =============================================================================
// P2a: Config deny_tools — block specific MCP tools with message
// =============================================================================

function mcp(toolName: string, config: ShushConfig) {
  return evaluate(
    { toolName, toolInput: {}, cwd: "/tmp/project" },
    config,
  );
}

describe("config deny_tools", () => {
  test("denied MCP tool returns block with message", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      denyTools: {
        "mcp__*__delete_*": "Deletions not allowed",
      },
    };
    const result = mcp("mcp__github__delete_repo", config);
    expect(result.decision).toBe("block");
    expect(result.reason).toContain("Deletions not allowed");
  });

  test("deny_tools checked before allow_tools", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: ["mcp__github__*"],
      mcpPathParams: {},
      denyTools: {
        "mcp__github__delete_*": "No deletes",
      },
    };
    // Even though allow_tools matches, deny_tools should win
    const result = mcp("mcp__github__delete_repo", config);
    expect(result.decision).toBe("block");
    expect(result.reason).toContain("No deletes");
  });

  test("non-matching deny pattern falls through to allow_tools", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: ["mcp__github__*"],
      mcpPathParams: {},
      denyTools: {
        "mcp__*__delete_*": "No deletes",
      },
    };
    const result = mcp("mcp__github__get_issue", config);
    expect(result.decision).toBe("allow");
  });

  test("unmatched tool with no allow or deny gets ask", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      denyTools: {
        "mcp__dangerous__*": "Blocked",
      },
    };
    const result = mcp("mcp__unknown__tool", config);
    expect(result.decision).toBe("ask");
  });

  test("deny_tools does not affect non-MCP tools", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      denyTools: {
        "Bash": "Should not match",
      },
    };
    const result = evaluate(
      { toolName: "Bash", toolInput: { command: "ls" }, cwd: "/tmp/project" },
      config,
    );
    expect(result.decision).toBe("allow");
  });

  test("glob pattern with single wildcard matches", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      denyTools: {
        "mcp__filesystem__write_file": "Use Write tool",
      },
    };
    const result = mcp("mcp__filesystem__write_file", config);
    expect(result.decision).toBe("block");
    expect(result.reason).toContain("Use Write tool");
  });
});
