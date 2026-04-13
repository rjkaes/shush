import { describe, expect, test } from "bun:test";
import { runProof } from "./z3-run";

describe("z3 extended equivalence proofs", () => {
  const results = runProof("test/z3-proofs/equiv-extended.ts");

  test("EX1: tee-to-sensitive >= Write-to-sensitive", () => {
    expect(results.find((r) => r.name === "EX1")?.result).toBe("unsat");
  });
  test("EX2: cp-to-sensitive >= Write-to-sensitive", () => {
    expect(results.find((r) => r.name === "EX2")?.result).toBe("unsat");
  });
  test("EX3: mv-to-sensitive >= Write-to-sensitive", () => {
    expect(results.find((r) => r.name === "EX3")?.result).toBe("unsat");
  });
  test("EX4: chmod-on-sensitive >= Write-to-sensitive", () => {
    expect(results.find((r) => r.name === "EX4")?.result).toBe("unsat");
  });
});
