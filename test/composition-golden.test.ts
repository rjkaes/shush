import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { classifyCommand } from "../src/bash-guard";

const lines = readFileSync(
  join(import.meta.dir, "fixtures", "composition-golden.txt"),
  "utf8",
)
  .split("\n")
  .map((l) => l.trim())
  .filter((l) => l.length > 0 && !l.startsWith("#"));

describe("G4 golden corpus: benign multi-stage commands stay permissive", () => {
  test("corpus has at least 100 entries", () => {
    expect(lines.length).toBeGreaterThanOrEqual(100);
  });

  for (const line of lines) {
    test(`benign: ${line}`, () => {
      const result = classifyCommand(line);
      expect(["allow", "context"]).toContain(result.finalDecision);
    });
  }
});
