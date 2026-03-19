import { describe, expect, test } from "bun:test";
import { prefixMatch, getPolicy, classifyTokens } from "../src/taxonomy";

describe("prefixMatch", () => {
  test("matches exact prefix", () => {
    expect(prefixMatch(["git", "status"], [
      { prefix: ["git", "status"], actionType: "git_safe" },
    ])).toBe("git_safe");
  });

  test("matches longest prefix first", () => {
    expect(prefixMatch(["git", "push", "--force"], [
      { prefix: ["git"], actionType: "git_write" },
      { prefix: ["git", "push"], actionType: "git_write" },
    ])).toBe("git_write");
  });

  test("returns unknown for no match", () => {
    expect(prefixMatch(["mystery"], [])).toBe("unknown");
  });
});

describe("getPolicy", () => {
  test("returns allow for filesystem_read", () => {
    expect(getPolicy("filesystem_read")).toBe("allow");
  });

  test("returns block for obfuscated", () => {
    expect(getPolicy("obfuscated")).toBe("block");
  });

  test("returns ask for unknown types", () => {
    expect(getPolicy("nonexistent_type")).toBe("ask");
  });
});

describe("classifyTokens", () => {
  test("classifies 'ls' as filesystem_read", () => {
    expect(classifyTokens(["ls"])).toBe("filesystem_read");
  });

  test("classifies 'rm' as filesystem_delete", () => {
    expect(classifyTokens(["rm", "foo.txt"])).toBe("filesystem_delete");
  });

  test("classifies 'git status' as git_safe", () => {
    expect(classifyTokens(["git", "status"])).toBe("git_safe");
  });

  test("classifies 'ssh' as network_outbound", () => {
    expect(classifyTokens(["ssh", "host"])).toBe("network_outbound");
  });

  test("returns unknown for unrecognized command", () => {
    expect(classifyTokens(["mysterycommand"])).toBe("unknown");
  });

  test("normalizes absolute paths: /usr/bin/rm → rm", () => {
    expect(classifyTokens(["/usr/bin/rm", "file"])).toBe("filesystem_delete");
  });

  test("classifies 'gh pr create' as git_write", () => {
    expect(classifyTokens(["gh", "pr", "create"])).toBe("git_write");
  });

  test("classifies 'gh pr list' as git_safe", () => {
    expect(classifyTokens(["gh", "pr", "list"])).toBe("git_safe");
  });

  test("classifies 'gh repo delete' as git_history_rewrite", () => {
    expect(classifyTokens(["gh", "repo", "delete"])).toBe("git_history_rewrite");
  });

  test("classifies 'gh issue create' as git_write", () => {
    expect(classifyTokens(["gh", "issue", "create"])).toBe("git_write");
  });

  test("classifies 'gh issue delete' as git_history_rewrite", () => {
    expect(classifyTokens(["gh", "issue", "delete"])).toBe("git_history_rewrite");
  });
});
