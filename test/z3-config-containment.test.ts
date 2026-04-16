import { describe, expect, test } from "bun:test";
import { runProof } from "./z3-run";

describe("Z3 G7 config-containment proof", () => {
  const results = runProof("test/z3-proofs/config-containment.ts");

  test("G7: no user config loosening can drop sensitive-path Write below Ask", () => {
    expect(results.find((r) => r.name === "G7")?.result).toBe("unsat");
  });
});
