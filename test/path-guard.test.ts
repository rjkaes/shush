import { describe, expect, test } from "bun:test";
import { homedir } from "node:os";
import path from "node:path";
import { checkPath, checkProjectBoundary, isHookPath, resolvePath } from "../src/path-guard";

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

  test("allows Read on hook directory", () => {
    expect(checkPath("Read", "~/.claude/hooks/guard.py")).toBeNull();
  });
  test("allows Glob on hook directory", () => {
    expect(checkPath("Glob", "~/.claude/hooks/")).toBeNull();
  });
  test("allows Grep on hook directory", () => {
    expect(checkPath("Grep", "~/.claude/hooks/guard.py")).toBeNull();
  });
  test("asks for Bash on hook directory", () => {
    const result = checkPath("Bash", "~/.claude/hooks/guard.py");
    expect(result).not.toBeNull();
    expect(result!.decision).toBe("ask");
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

describe("cross-platform path handling", () => {
  const home = homedir();

  test("resolvePath expands ~ to real home directory", () => {
    const resolved = resolvePath("~/.ssh/id_rsa");
    expect(resolved.startsWith(home)).toBe(true);
    expect(path.isAbsolute(resolved)).toBe(true);
  });

  test("home directory is non-empty and absolute", () => {
    expect(home.length).toBeGreaterThan(0);
    expect(path.isAbsolute(home)).toBe(true);
  });

  test("sensitive path detection works with homedir", () => {
    const result = checkPath("Read", "~/.ssh/id_rsa");
    expect(result).not.toBeNull();
    expect(result!.decision).toBe("block");
  });

  test("isHookPath matches native path separators", () => {
    const hookPath = path.join(home, ".claude", "hooks", "guard.sh");
    expect(isHookPath(hookPath)).toBe(true);
  });

  test("isHookPath rejects paths outside hooks dir", () => {
    const otherPath = path.join(home, ".claude", "settings.json");
    expect(isHookPath(otherPath)).toBe(false);
  });
});
