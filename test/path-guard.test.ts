import { describe, expect, test, beforeAll, afterAll } from "bun:test";
import { homedir } from "node:os";
import path from "node:path";
import { existsSync, mkdirSync, symlinkSync, rmSync } from "node:fs";
import { checkPath, checkProjectBoundary, isHookPath, resolvePath } from "../src/path-guard";
import { read, write } from "./eval-helpers";

describe("checkPath", () => {
  test("allows normal project paths", () => {
    expect(read("./src/index.ts").decision).toBe("allow");
  });

  test("blocks ~/.ssh access", () => {
    expect(read("~/.ssh/id_rsa").decision).toBe("block");
  });

  test("asks for ~/.aws access", () => {
    expect(read("~/.aws/credentials").decision).toBe("ask");
  });

  test("blocks /etc/shadow access", () => {
    expect(read("/etc/shadow").decision).toBe("block");
  });

  test("blocks /etc/master.passwd access", () => {
    expect(read("/etc/master.passwd").decision).toBe("block");
  });

  test("blocks ~/.docker/config.json access", () => {
    expect(read("~/.docker/config.json").decision).toBe("block");
  });

  test("blocks ~/.kube/config access", () => {
    expect(read("~/.kube/config").decision).toBe("block");
  });

  test("blocks ~/.config/gh/hosts.yml access", () => {
    expect(read("~/.config/gh/hosts.yml").decision).toBe("block");
  });

  test("asks for .env files", () => {
    expect(read("/some/path/.env").decision).toBe("ask");
  });

  test("blocks Write to hook directory", () => {
    expect(write("~/.claude/hooks/guard.py", "content").decision).toBe("block");
  });

  test("allows Read on hook directory", () => {
    expect(read("~/.claude/hooks/guard.py").decision).toBe("allow");
  });
  // Glob, Grep, and Bash on hook directory can't be fully tested through
  // evaluate because the project boundary check fires on paths outside the
  // project root. Keep these as internal checkPath tests.
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

describe("checkProjectBoundary", () => {
  const projectRoot = "/home/user/myproject";

  test("file inside project root returns null (allowed)", () => {
    expect(checkProjectBoundary("Read", "/home/user/myproject/src/index.ts", projectRoot)).toBeNull();
  });

  test("file outside project root returns ask", () => {
    const result = checkProjectBoundary("Read", "/tmp/secret.txt", projectRoot);
    expect(result).not.toBeNull();
    expect(result!.decision).toBe("ask");
    expect(result!.reason).toContain("outside project");
  });

  test("null projectRoot returns ask", () => {
    const result = checkProjectBoundary("Write", "/home/user/myproject/file.ts", null);
    expect(result).not.toBeNull();
    expect(result!.decision).toBe("ask");
    expect(result!.reason).toContain("no git root");
  });

  test("exact project root path returns null", () => {
    expect(checkProjectBoundary("Read", "/home/user/myproject", projectRoot)).toBeNull();
  });

  test("nested subdirectory inside project returns null", () => {
    expect(
      checkProjectBoundary("Edit", "/home/user/myproject/src/deep/nested/file.ts", projectRoot),
    ).toBeNull();
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
    expect(read("~/.ssh/id_rsa").decision).toBe("block");
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

describe("symlink resolution", () => {
  const tmpDir = path.join(homedir(), ".shush-test-symlinks");
  const home = homedir();
  const sshTarget = path.join(home, ".ssh");
  const linkPath = path.join(tmpDir, "innocent-link");
  // CI runners may not have ~/.ssh; create it so symlinks resolve.
  let createdSshDir = false;

  beforeAll(() => {
    if (!existsSync(sshTarget)) {
      mkdirSync(sshTarget, { recursive: true });
      createdSshDir = true;
    }
    mkdirSync(tmpDir, { recursive: true });
    try {
      symlinkSync(sshTarget, linkPath);
    } catch {
      // Link may already exist from a prior aborted run
    }
  });

  afterAll(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    if (createdSshDir) {
      rmSync(sshTarget, { recursive: true, force: true });
    }
  });

  test("resolvePath follows symlinks to real target", () => {
    const resolved = resolvePath(linkPath);
    expect(resolved).toBe(sshTarget);
  });

  test("checkPath catches symlink pointing to ~/.ssh", () => {
    const result = checkPath("Read", linkPath);
    expect(result).not.toBeNull();
    expect(result!.decision).toBe("block");
    expect(result!.reason).toContain(".ssh");
  });

  test("checkPath catches symlink to sensitive file inside ~/.ssh", () => {
    const keyLink = path.join(tmpDir, "key-link");
    const keyTarget = path.join(sshTarget, "id_rsa");
    // Ensure the target file exists so realpathSync can resolve the symlink.
    if (!existsSync(keyTarget)) {
      Bun.write(keyTarget, "");
    }
    try {
      symlinkSync(keyTarget, keyLink);
    } catch {
      // May already exist
    }
    const result = checkPath("Read", keyLink);
    expect(result).not.toBeNull();
    expect(result!.decision).toBe("block");
  });

  test("resolvePath handles non-existent target gracefully", () => {
    const resolved = resolvePath("/tmp/does-not-exist-shush-test.txt");
    // On Windows, path.resolve() prepends the current drive letter to
    // absolute Unix-style paths (e.g. "D:\tmp\...").
    const expected = path.resolve("/tmp/does-not-exist-shush-test.txt");
    expect(resolved).toBe(expected);
  });
});
