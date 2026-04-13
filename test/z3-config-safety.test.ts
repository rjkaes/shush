import { describe, expect, test } from "bun:test";
import { runProof } from "./z3-run";

describe("z3 config safety proofs", () => {
  const results = runProof("test/z3-proofs/config-safety.ts");

  test("CS1: config can tighten policies, never loosen", () => {
    expect(results.find((r) => r.name === "CS1")?.result).toBe("unsat");
  });
  test("CS2a: allowedPaths does not weaken sensitive_block", () => {
    expect(results.find((r) => r.name === "CS2a")?.result).toBe("unsat");
  });
  test("CS2b: allowedPaths does not weaken sensitive_ask", () => {
    expect(results.find((r) => r.name === "CS2b")?.result).toBe("unsat");
  });
});
