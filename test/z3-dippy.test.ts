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
  test("D6: network_outbound sensitive path >= Read sensitive path", () => {
    expect(results.find((r) => r.name === "D6")?.result).toBe("unsat");
  });
  test("D7: git clone sensitive dest >= Write sensitive path", () => {
    expect(results.find((r) => r.name === "D7")?.result).toBe("unsat");
  });
  test("D8: docker -v sensitive mount >= Write sensitive path", () => {
    expect(results.find((r) => r.name === "D8")?.result).toBe("unsat");
  });
  test("D9: universal path-check guarantee (stricter never weakens path policy)", () => {
    expect(results.find((r) => r.name === "D9")?.result).toBe("unsat");
  });
  test("M1: shell unwrapping never downgrades a decision", () => {
    expect(results.find((r) => r.name === "M1")?.result).toBe("unsat");
  });
  test("M2: config overrides can't loosen sensitive-path decisions", () => {
    expect(results.find((r) => r.name === "M2")?.result).toBe("unsat");
  });
  test("M4: hook self-protection (stricter(any, block) = block)", () => {
    expect(results.find((r) => r.name === "M4")?.result).toBe("unsat");
  });
});
