// test/parity-writes.test.ts
// Unit regression tests for G1: bash write-emitter commands targeting sensitive
// paths must produce a decision of at least "ask" — matching the policy that
// applies when the equivalent file tool (Write/Edit) targets the same path.
import { describe, test, expect } from "bun:test";
import { evaluate } from "../src/evaluate.js";
import { EMPTY_CONFIG } from "../src/types.js";
import { homedir } from "node:os";
import path from "node:path";

const HOME = homedir();

function evalBash(cmd: string) {
  return evaluate({ toolName: "Bash", toolInput: { command: cmd }, cwd: null }, EMPTY_CONFIG);
}

describe("G1 bash/file write parity (unit regressions)", () => {
  test("dd of=~/.ssh/config is at least ask", () => {
    const out = evalBash(`dd of='${path.join(HOME, ".ssh", "config")}'`);
    expect(["ask", "block"]).toContain(out.decision);
  });

  test("tee -a ~/.aws/credentials is at least ask", () => {
    const out = evalBash(`cat x | tee -a '${path.join(HOME, ".aws", "credentials")}'`);
    expect(["ask", "block"]).toContain(out.decision);
  });

  test("ln -sf /etc/passwd ~/x is at least ask", () => {
    const out = evalBash(`ln -sf /etc/passwd '${path.join(HOME, "x")}'`);
    expect(["ask", "block"]).toContain(out.decision);
  });

  test("install -m 644 src ~/.ssh/authorized_keys is at least ask", () => {
    const out = evalBash(`install -m 644 src '${path.join(HOME, ".ssh", "authorized_keys")}'`);
    expect(["ask", "block"]).toContain(out.decision);
  });
});
