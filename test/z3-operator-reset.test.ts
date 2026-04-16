import { describe, expect, test } from "bun:test";
import { runProof } from "./z3-run";

describe("Z3 G4 operator-reset proof", () => {
  const results = runProof("test/z3-proofs/operator-reset.ts");

  test("G4: net-source × reset-op × exec-sink always yield >= Ask", () => {
    expect(results.find((r) => r.name === "G4")?.result).toBe("unsat");
  });
});
