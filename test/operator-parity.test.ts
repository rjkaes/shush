import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PIPE_OPERATORS, RESET_OPERATORS } from "../src/predicates/composition";
import { extractStages } from "../src/ast-walk";

describe("operator parity", () => {
  test("every operator ast-walk emits is covered by a predicate set", () => {
    const corpusPath = join(import.meta.dir, "fixtures", "operator-corpus.txt");
    const corpus = readFileSync(corpusPath, "utf8")
      .split("\n").filter(l => l.trim().length > 0);
    const seen = new Set<string>();
    for (const line of corpus) {
      for (const stage of extractStages(line).stages) {
        if (stage.operator) seen.add(stage.operator);
      }
    }
    const covered = new Set<string>([...PIPE_OPERATORS, ...RESET_OPERATORS]);
    const missing = [...seen].filter(op => !covered.has(op));
    expect(missing).toEqual([]);
    expect(seen.size).toBeGreaterThan(0);
    for (const op of ["|", "&&", "||", ";"]) {
      expect(seen).toContain(op);
    }
  });
});
