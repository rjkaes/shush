import { describe, expect, test } from "bun:test";
import { classifyWithFlags } from "../src/classify";

describe("git flag classifier", () => {
  test("git push → git_write", () => {
    expect(classifyWithFlags(["git", "push"])).toBe("git_write");
  });
  test("git push --force → git_history_rewrite", () => {
    expect(classifyWithFlags(["git", "push", "--force"])).toBe("git_history_rewrite");
  });
  test("git push -f → git_history_rewrite", () => {
    expect(classifyWithFlags(["git", "push", "-f"])).toBe("git_history_rewrite");
  });
  test("git reset --hard → git_discard", () => {
    expect(classifyWithFlags(["git", "reset", "--hard"])).toBe("git_discard");
  });
  test("git reset → git_write", () => {
    expect(classifyWithFlags(["git", "reset"])).toBe("git_write");
  });
  test("git branch -d → git_discard", () => {
    expect(classifyWithFlags(["git", "branch", "-d", "feature"])).toBe("git_discard");
  });
  test("git branch -D → git_history_rewrite", () => {
    expect(classifyWithFlags(["git", "branch", "-D", "feature"])).toBe("git_history_rewrite");
  });
  test("git branch (list) → git_safe", () => {
    expect(classifyWithFlags(["git", "branch"])).toBe("git_safe");
  });
  test("git checkout . → git_discard", () => {
    expect(classifyWithFlags(["git", "checkout", "."])).toBe("git_discard");
  });
  test("git add --dry-run → git_safe", () => {
    expect(classifyWithFlags(["git", "add", "--dry-run"])).toBe("git_safe");
  });
  test("git clean → git_history_rewrite", () => {
    expect(classifyWithFlags(["git", "clean"])).toBe("git_history_rewrite");
  });
  test("git clean -n → git_safe", () => {
    expect(classifyWithFlags(["git", "clean", "-n"])).toBe("git_safe");
  });
  test("strips git -C flag", () => {
    expect(classifyWithFlags(["git", "-C", "/tmp", "status"])).toBe("git_safe");
  });
});

describe("curl flag classifier", () => {
  test("curl url → network_outbound", () => {
    expect(classifyWithFlags(["curl", "https://example.com"])).toBe("network_outbound");
  });
  test("curl -X POST → network_write", () => {
    expect(classifyWithFlags(["curl", "-X", "POST", "https://example.com"])).toBe("network_write");
  });
  test("curl --data → network_write", () => {
    expect(classifyWithFlags(["curl", "--data", "foo", "https://example.com"])).toBe("network_write");
  });
  test("curl -d → network_write", () => {
    expect(classifyWithFlags(["curl", "-d", "foo", "https://example.com"])).toBe("network_write");
  });
});

describe("find flag classifier", () => {
  test("find . → filesystem_read", () => {
    expect(classifyWithFlags(["find", "."])).toBe("filesystem_read");
  });
  test("find -delete → filesystem_delete", () => {
    expect(classifyWithFlags(["find", ".", "-delete"])).toBe("filesystem_delete");
  });
  test("find -exec rm → filesystem_delete", () => {
    expect(classifyWithFlags(["find", ".", "-exec", "rm", "{}", ";"])).toBe("filesystem_delete");
  });
  test("find -exec grep → filesystem_read", () => {
    expect(classifyWithFlags(["find", ".", "-type", "f", "-exec", "grep", "-l", "pattern", "{}", "+"])).toBe("filesystem_read");
  });
  test("find -execdir cat → filesystem_read", () => {
    expect(classifyWithFlags(["find", ".", "-execdir", "cat", "{}", ";"])).toBe("filesystem_read");
  });
  test("find -exec sed -i → filesystem_write", () => {
    expect(classifyWithFlags(["find", ".", "-exec", "sed", "-i", "s/a/b/", "{}", ";"])).toBe("filesystem_write");
  });
  test("find -exec with no command → filesystem_delete (conservative)", () => {
    expect(classifyWithFlags(["find", ".", "-exec"])).toBe("filesystem_delete");
  });
});

describe("sed flag classifier", () => {
  test("sed (read) → filesystem_read", () => {
    expect(classifyWithFlags(["sed", "s/a/b/"])).toBe("filesystem_read");
  });
  test("sed -i → filesystem_write", () => {
    expect(classifyWithFlags(["sed", "-i", "s/a/b/", "file"])).toBe("filesystem_write");
  });
});

describe("non-flag commands return null", () => {
  test("ls returns null (use prefix table)", () => {
    expect(classifyWithFlags(["ls"])).toBeNull();
  });
});
