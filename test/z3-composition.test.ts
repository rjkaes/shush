import { describe, expect, test } from "bun:test";
import { runProof } from "./z3-run";

describe("z3 composition proofs", () => {
  const results = runProof("test/z3-proofs/composition.ts");

  test("X1: network | exec always blocks", () => {
    expect(results.find((r) => r.name === "X1")?.result).toBe("unsat");
  });
  test("X2: sensitive read | network always blocks", () => {
    expect(results.find((r) => r.name === "X2")?.result).toBe("unsat");
  });
  test("X3: decode | exec always blocks", () => {
    expect(results.find((r) => r.name === "X3")?.result).toBe("unsat");
  });
  test("X4: escalation never lowers severity", () => {
    expect(results.find((r) => r.name === "X4")?.result).toBe("unsat");
  });
  test("X5: pipeline result >= max of stages", () => {
    expect(results.find((r) => r.name === "X5")?.result).toBe("unsat");
  });
  test("X6: composition rules never produce Allow", () => {
    expect(results.find((r) => r.name === "X6")?.result).toBe("unsat");
  });
});
