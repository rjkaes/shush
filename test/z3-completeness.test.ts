import { describe, expect, test } from "bun:test";
import { runProof } from "./z3-run";

describe("z3 completeness proofs", () => {
  const results = runProof("test/z3-proofs/completeness.ts");

  test("C1: all action types map to valid decisions", () => {
    expect(results.find((r) => r.name === "C1")?.result).toBe("unsat");
  });
  test("C2: policy function is deterministic", () => {
    expect(results.find((r) => r.name === "C2")?.result).toBe("unsat");
  });
  test("C3: PathGuard pipeline has no decision gaps", () => {
    expect(results.find((r) => r.name === "C3")?.result).toBe("unsat");
  });
  test("C4: unknown commands never get Allow", () => {
    expect(results.find((r) => r.name === "C4")?.result).toBe("unsat");
  });
});
