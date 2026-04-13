import { describe, expect, test } from "bun:test";
import { runProof } from "./z3-run";

describe("z3 dippy-gap proofs", () => {
  const results = runProof("test/z3-proofs/dippy-gaps.ts");

  test("D1: find -delete pipeline always >= Context", () => {
    expect(results.find((r) => r.name === "D1")?.result).toBe("unsat");
  });
  test("D2: git global flag stripping preserves classification", () => {
    expect(results.find((r) => r.name === "D2")?.result).toBe("unsat");
  });
  test("D3: parse failures never produce Allow", () => {
    expect(results.find((r) => r.name === "D3")?.result).toBe("unsat");
  });
  test("D4: rm sensitive path >= Write sensitive path", () => {
    expect(results.find((r) => r.name === "D4")?.result).toBe("unsat");
  });
  test("D5: find -delete sensitive root >= Write sensitive root", () => {
    expect(results.find((r) => r.name === "D5")?.result).toBe("unsat");
  });
});
