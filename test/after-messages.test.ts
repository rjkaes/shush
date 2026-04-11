import { describe, expect, test } from "bun:test";
import { evaluate } from "../src/evaluate";
import type { ShushConfig, EvalInput } from "../src/types";

// =============================================================================
// P2b: PostToolUse after messages — feedback after command completes
// =============================================================================

// afterMessages are checked by a separate function that returns the message
// to display (or null). The PostToolUse hook calls this.

describe("after messages matching", () => {
  // Import the function we'll create
  const { matchAfterMessage } = require("../src/after-messages") as {
    matchAfterMessage: (command: string, config: ShushConfig) => string | null;
  };

  test("matching pattern returns message", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      afterMessages: {
        "git push *": "Check CI status",
      },
    };
    expect(matchAfterMessage("git push origin main", config)).toBe("Check CI status");
  });

  test("non-matching command returns null", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      afterMessages: {
        "git push *": "Check CI status",
      },
    };
    expect(matchAfterMessage("git status", config)).toBeNull();
  });

  test("bare command matches pattern without wildcard", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      afterMessages: {
        "npm publish": "Update changelog",
      },
    };
    expect(matchAfterMessage("npm publish", config)).toBe("Update changelog");
  });

  test("first matching pattern wins", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      afterMessages: {
        "git *": "Generic git message",
        "git push *": "Specific push message",
      },
    };
    expect(matchAfterMessage("git push origin main", config)).toBe("Generic git message");
  });

  test("empty afterMessages returns null", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      afterMessages: {},
    };
    expect(matchAfterMessage("git push", config)).toBeNull();
  });

  test("undefined afterMessages returns null", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
    };
    expect(matchAfterMessage("git push", config)).toBeNull();
  });
});
