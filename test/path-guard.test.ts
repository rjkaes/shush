import { describe, expect, test } from "bun:test";
import { checkPath, checkProjectBoundary, isHookPath } from "../src/path-guard";

describe("checkPath", () => {
  test("allows normal project paths", () => {
    expect(checkPath("Read", "./src/index.ts")).toBeNull();
  });

  test("blocks ~/.ssh access", () => {
    const result = checkPath("Read", "~/.ssh/id_rsa");
    expect(result).not.toBeNull();
    expect(result!.decision).toBe("block");
  });

  test("asks for ~/.aws access", () => {
    const result = checkPath("Read", "~/.aws/credentials");
    expect(result).not.toBeNull();
    expect(result!.decision).toBe("ask");
  });

  test("asks for .env files", () => {
    const result = checkPath("Read", "/some/path/.env");
    expect(result).not.toBeNull();
    expect(result!.decision).toBe("ask");
  });

  test("blocks Write to hook directory", () => {
    const result = checkPath("Write", "~/.claude/hooks/guard.py");
    expect(result).not.toBeNull();
    expect(result!.decision).toBe("block");
  });
});

describe("isHookPath", () => {
  test("detects ~/.claude/hooks paths", () => {
    const { join } = require("node:path");
    const home = require("node:os").homedir();
    expect(isHookPath(join(home, ".claude", "hooks", "test.sh"))).toBe(true);
  });

  test("rejects other paths", () => {
    expect(isHookPath("/tmp/safe.txt")).toBe(false);
  });
});
