// Delete command path-guard equivalence tests.
// Verifies that rm and find -delete get the same sensitive-path,
// hook-path, and project-boundary checks as Write/Edit file tools.

import { describe, expect, test } from "bun:test";
import { bash, atLeast } from "./eval-helpers";

describe("rm path-guard equivalence", () => {
  test("rm ~/.ssh/id_rsa -> block (sensitive path)", () => {
    expect(atLeast(bash("rm ~/.ssh/id_rsa").decision, "block")).toBe(true);
  });

  test("rm -rf ~/.ssh -> block (sensitive directory)", () => {
    expect(atLeast(bash("rm -rf ~/.ssh").decision, "block")).toBe(true);
  });

  test("rm -f ~/.ssh/known_hosts -> block (sensitive path)", () => {
    expect(atLeast(bash("rm -f ~/.ssh/known_hosts").decision, "block")).toBe(true);
  });

  test("rm ~/.gnupg/secring.gpg -> block (sensitive path)", () => {
    expect(atLeast(bash("rm ~/.gnupg/secring.gpg").decision, "block")).toBe(true);
  });

  test("rm /etc/shadow -> block (sensitive path)", () => {
    expect(atLeast(bash("rm /etc/shadow").decision, "block")).toBe(true);
  });

  test("rm stale.log -> context (in-project, non-sensitive)", () => {
    const result = bash("rm stale.log");
    // Non-sensitive in-project file: filesystem_delete -> context
    expect(result.decision).toBe("context");
  });

  test("rm -rf node_modules -> context (in-project directory)", () => {
    const result = bash("rm -rf node_modules");
    expect(result.decision).toBe("context");
  });
});

describe("find -delete path-guard equivalence", () => {
  test("find ~/.ssh -delete -> block (sensitive search root)", () => {
    expect(atLeast(bash("find ~/.ssh -delete").decision, "block")).toBe(true);
  });

  test("find ~/.ssh -name '*.pub' -delete -> block (sensitive root)", () => {
    expect(atLeast(bash("find ~/.ssh -name '*.pub' -delete").decision, "block")).toBe(true);
  });

  test("find ~/.gnupg -name '*.gpg' -delete -> block (sensitive root)", () => {
    expect(atLeast(bash("find ~/.gnupg -name '*.gpg' -delete").decision, "block")).toBe(true);
  });

  test("find . -name '*.pyc' -delete -> context (in-project)", () => {
    const result = bash("find . -name '*.pyc' -delete");
    // . is project-relative, non-sensitive -> filesystem_delete -> context
    expect(result.decision).toBe("context");
  });

  test("find /tmp/build -name '*.o' -delete -> context (non-sensitive)", () => {
    const result = bash("find /tmp/build -name '*.o' -delete");
    // /tmp is not a sensitive path -> filesystem_delete -> context
    expect(result.decision).toBe("context");
  });

  test("find ~/.ssh ~/.gnupg -delete -> block (multiple sensitive roots)", () => {
    expect(atLeast(bash("find ~/.ssh ~/.gnupg -delete").decision, "block")).toBe(true);
  });
});

describe("find -exec rm path-guard equivalence", () => {
  test("find ~/.ssh -exec rm {} ; -> block (sensitive root)", () => {
    expect(atLeast(bash("find ~/.ssh -exec rm {} \\;").decision, "block")).toBe(true);
  });

  test("find . -name '*.tmp' -exec rm {} ; -> context (in-project)", () => {
    const result = bash("find . -name '*.tmp' -exec rm {} \\;");
    expect(result.decision).toBe("context");
  });
});
