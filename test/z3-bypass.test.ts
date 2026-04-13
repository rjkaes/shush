import { describe, expect, test } from "bun:test";
import { runProof } from "./z3-run";

describe("z3 bypass proofs", () => {
  const results = runProof("test/z3-proofs/bypass.ts");

  test("B1: sensitive-block paths never yield Allow", () => {
    expect(results.find((r) => r.name === "B1")?.result).toBe("unsat");
  });
  test("B2: sensitive-ask + write tool yields at least Ask", () => {
    expect(results.find((r) => r.name === "B2")?.result).toBe("unsat");
  });
  test("B3: hook path + write tool always Blocks", () => {
    expect(results.find((r) => r.name === "B3")?.result).toBe("unsat");
  });
  test("B4: config overrides cannot lower sensitive below Ask", () => {
    expect(results.find((r) => r.name === "B4")?.result).toBe("unsat");
  });
  test("B5: depth exhaustion never allows", () => {
    expect(results.find((r) => r.name === "B5")?.result).toBe("unsat");
  });
});
