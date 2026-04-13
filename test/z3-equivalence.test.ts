import { describe, expect, test } from "bun:test";
import { runProof } from "./z3-run";

describe("z3 equivalence proofs", () => {
  const results = runProof("test/z3-proofs/equivalence.ts");

  test("E1: redirect-to-sensitive >= Write-to-sensitive", () => {
    expect(results.find((r) => r.name === "E1")?.result).toBe("unsat");
  });
  test("E2: cat-sensitive >= Read-sensitive", () => {
    expect(results.find((r) => r.name === "E2")?.result).toBe("unsat");
  });
  test("E3: stricter is commutative", () => {
    expect(results.find((r) => r.name === "E3")?.result).toBe("unsat");
  });
  test("E4: stricter is associative", () => {
    expect(results.find((r) => r.name === "E4")?.result).toBe("unsat");
  });
});
