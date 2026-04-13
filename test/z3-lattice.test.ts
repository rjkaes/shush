import { describe, expect, test } from "bun:test";
import { runProof } from "./z3-run";

describe("z3 lattice proofs", () => {
  const results = runProof("test/z3-proofs/lattice.ts");

  test("L1: idempotency — stricter(a, a) = a", () => {
    expect(results.find((r) => r.name === "L1")?.result).toBe("unsat");
  });
  test("L2: identity — stricter(allow, x) = x", () => {
    expect(results.find((r) => r.name === "L2")?.result).toBe("unsat");
  });
  test("L3: total order — all decisions comparable", () => {
    expect(results.find((r) => r.name === "L3")?.result).toBe("unsat");
  });
  test("L4: no gaps — decisions exactly {0,1,2,3}", () => {
    expect(results.find((r) => r.name === "L4")?.result).toBe("unsat");
  });
  test("L5: policy partition — 7 allow, 4 context, 10 ask, 1 block", () => {
    expect(results.find((r) => r.name === "L5")?.result).toBe("unsat");
  });
});
