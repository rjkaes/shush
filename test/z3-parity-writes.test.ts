import { describe, expect, test } from "bun:test";
import { runProof } from "./z3-run";

describe("Z3 G1 parity proof", () => {
  const results = runProof("test/z3-proofs/parity-writes.ts");

  test("G1: bash write-emitters × sensitive paths always yield >= Ask", () => {
    expect(results.find((r) => r.name === "G1")?.result).toBe("unsat");
  });
});
