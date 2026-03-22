import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "fs";
import { join, basename } from "path";
import type { Decision } from "../src/types";

const DATA_DIR = join(import.meta.dir, "..", "data");
const CLASSIFY_DIR = join(DATA_DIR, "classify_full");

const typesJson: Record<string, string> = JSON.parse(
  readFileSync(join(DATA_DIR, "types.json"), "utf-8"),
);
const policiesJson: Record<string, string> = JSON.parse(
  readFileSync(join(DATA_DIR, "policies.json"), "utf-8"),
);

const VALID_DECISIONS: Decision[] = ["allow", "context", "ask", "block"];

const classifyFiles = readdirSync(CLASSIFY_DIR).filter((f) =>
  f.endsWith(".json"),
);

/** Compare two string arrays element-by-element (lexicographic). */
function compareEntries(a: string[], b: string[]): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}

describe("classify_full JSON structure", () => {
  for (const file of classifyFiles) {
    test(`${file} parses as an array of string arrays`, () => {
      const raw = readFileSync(join(CLASSIFY_DIR, file), "utf-8");
      const parsed = JSON.parse(raw);
      expect(Array.isArray(parsed)).toBe(true);
      for (const entry of parsed) {
        expect(Array.isArray(entry)).toBe(true);
        for (const element of entry) {
          expect(typeof element).toBe("string");
        }
      }
    });
  }
});

describe("classify_full filenames match types.json keys", () => {
  for (const file of classifyFiles) {
    const actionType = basename(file, ".json");
    test(`${actionType} exists in types.json`, () => {
      expect(typesJson).toHaveProperty(actionType);
    });
  }
});

describe("types.json and policies.json key parity", () => {
  test("every types.json key has a policies.json entry", () => {
    for (const key of Object.keys(typesJson)) {
      expect(policiesJson).toHaveProperty(key);
    }
  });

  test("every policies.json key has a types.json entry", () => {
    for (const key of Object.keys(policiesJson)) {
      expect(typesJson).toHaveProperty(key);
    }
  });
});

describe("policies.json values are valid Decisions", () => {
  for (const [key, value] of Object.entries(policiesJson)) {
    test(`${key} policy "${value}" is a valid Decision`, () => {
      expect(VALID_DECISIONS).toContain(value as Decision);
    });
  }
});

describe("no duplicate prefix entries within a single file", () => {
  for (const file of classifyFiles) {
    test(`${file} has no internal duplicates`, () => {
      const parsed: string[][] = JSON.parse(
        readFileSync(join(CLASSIFY_DIR, file), "utf-8"),
      );
      const seen = new Set<string>();
      const duplicates: string[] = [];
      for (const entry of parsed) {
        const key = JSON.stringify(entry);
        if (seen.has(key)) {
          duplicates.push(key);
        }
        seen.add(key);
      }
      expect(duplicates).toEqual([]);
    });
  }
});

describe("no duplicate prefix entries across files", () => {
  test("each prefix appears in exactly one file", () => {
    const seen = new Map<string, string>();
    const duplicates: string[] = [];
    for (const file of classifyFiles) {
      const parsed: string[][] = JSON.parse(
        readFileSync(join(CLASSIFY_DIR, file), "utf-8"),
      );
      for (const entry of parsed) {
        const key = JSON.stringify(entry);
        const prev = seen.get(key);
        if (prev !== undefined) {
          duplicates.push(`${key} in both ${prev} and ${file}`);
        }
        seen.set(key, file);
      }
    }
    expect(duplicates).toEqual([]);
  });
});

describe("entries within each file are sorted", () => {
  for (const file of classifyFiles) {
    test(`${file} entries are in alphabetical order`, () => {
      const parsed: string[][] = JSON.parse(
        readFileSync(join(CLASSIFY_DIR, file), "utf-8"),
      );
      const unsorted: string[] = [];
      for (let i = 1; i < parsed.length; i++) {
        if (compareEntries(parsed[i - 1], parsed[i]) > 0) {
          unsorted.push(
            `${JSON.stringify(parsed[i - 1])} should come after ${JSON.stringify(parsed[i])}`,
          );
        }
      }
      expect(unsorted).toEqual([]);
    });
  }
});
