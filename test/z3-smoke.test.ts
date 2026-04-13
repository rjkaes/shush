import { describe, expect, test } from "bun:test";
import { runProof } from "./z3-run";

describe("z3 smoke", () => {
  const results = runProof("test/z3-proofs/smoke.ts");

  test("UNSAT for contradiction", () => {
    const r = results.find((r) => r.name === "contradiction");
    expect(r?.result).toBe("unsat");
  });

  test("SAT for satisfiable constraints", () => {
    const r = results.find((r) => r.name === "satisfiable");
    expect(r?.result).toBe("sat");
  });
});
