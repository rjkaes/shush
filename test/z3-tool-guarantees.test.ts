import { describe, expect, test } from "bun:test";
import { runProof } from "./z3-run";

describe("z3 tool guarantees", () => {
  const results = runProof("test/z3-proofs/tool-guarantees.ts");

  test("TG1a: hook + write tool -> Block", () => {
    expect(results.find((r) => r.name === "TG1a")?.result).toBe("unsat");
  });

  test("TG1b: hook + mcp_write tool -> Block", () => {
    expect(results.find((r) => r.name === "TG1b")?.result).toBe("unsat");
  });

  test("TG1c: hook + read tool -> Allow", () => {
    expect(results.find((r) => r.name === "TG1c")?.result).toBe("unsat");
  });

  test("TG2a: content guard ceiling is Ask", () => {
    expect(results.find((r) => r.name === "TG2a")?.result).toBe("unsat");
  });

  test("TG2b: read tool unaffected by content scan", () => {
    expect(results.find((r) => r.name === "TG2b")?.result).toBe("unsat");
  });

  test("TG3a: read tool has no boundary check", () => {
    expect(results.find((r) => r.name === "TG3a")?.result).toBe("unsat");
  });

  test("TG3b: write tool gets boundary check", () => {
    expect(results.find((r) => r.name === "TG3b")?.result).toBe("unsat");
  });

  test("TG3c: write tool gets content scan", () => {
    expect(results.find((r) => r.name === "TG3c")?.result).toBe("unsat");
  });
});
