import { describe, test, expect } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join, basename } from "node:path";
import { CLASSIFY_FULL_TABLE } from "../data/classify-full.js";
import type { PrefixEntry } from "../data/classify-full.js";

describe("classifier drift detection", () => {
  test("generated table matches JSON source files", async () => {
    const inputDir = join(import.meta.dir, "..", "data", "classify_full");
    const entries = await readdir(inputDir);
    const jsonFiles = entries.filter((f) => f.endsWith(".json")).sort();

    const allEntries: PrefixEntry[] = [];

    for (const file of jsonFiles) {
      const actionType = basename(file, ".json");
      const raw = JSON.parse(
        await readFile(join(inputDir, file), "utf-8"),
      ) as string[][];

      for (const prefix of raw) {
        allEntries.push({ prefix, actionType });
      }
    }

    // Sort: longest prefix first, then byte-order ascending on joined prefix.
    allEntries.sort((a, b) => {
      const lenDiff = b.prefix.length - a.prefix.length;
      if (lenDiff !== 0) return lenDiff;
      const aKey = a.prefix.join(" ");
      const bKey = b.prefix.join(" ");
      return aKey < bKey ? -1 : aKey > bKey ? 1 : 0;
    });

    try {
      expect(allEntries).toEqual(CLASSIFY_FULL_TABLE);
    } catch {
      throw new Error(
        "Classifier table is out of date. Run: bun run scripts/generate-classifiers.ts",
      );
    }
  });
});
