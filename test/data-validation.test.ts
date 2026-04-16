import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "fs";
import { join } from "path";
import type { Decision } from "../src/types";
import { entryPrefix } from "./classify-entry-helpers";

const DATA_DIR = join(import.meta.dir, "..", "data");
const CLASSIFY_DIR = join(DATA_DIR, "classify_full");

const typesJson: Record<string, string> = JSON.parse(
  readFileSync(join(DATA_DIR, "types.json"), "utf-8"),
);
const policiesJson: Record<string, string> = JSON.parse(
  readFileSync(join(DATA_DIR, "policies.json"), "utf-8"),
);

const VALID_DECISIONS: Decision[] = ["allow", "context", "ask", "block"];

/** All command JSON files under classify_full/. */
const commandFiles = readdirSync(CLASSIFY_DIR)
  .filter((f) => f.endsWith(".json"))
  .sort();

/** Read and parse a command file. Returns the full object including flag_rules. */
function readCommandFile(file: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(CLASSIFY_DIR, file), "utf-8"));
}

/** Return only the prefix entries (action type -> entry arrays), excluding flag_rules. */
function prefixEntries(
  parsed: Record<string, unknown>,
): Record<string, unknown[]> {
  const { flag_rules: _, ...rest } = parsed;
  return rest as Record<string, unknown[]>;
}


/** Compare two string arrays element-by-element (lexicographic). */
function compareEntries(a: string[], b: string[]): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}

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

describe("command files are valid JSON objects keyed by action type", () => {
  for (const file of commandFiles) {
    test(`${file} is valid`, () => {
      const parsed = readCommandFile(file);
      expect(typeof parsed).toBe("object");
      expect(parsed).not.toBeNull();
      expect(Array.isArray(parsed)).toBe(false);

      for (const [actionType, entries] of Object.entries(
        prefixEntries(parsed),
      )) {
        expect(typesJson).toHaveProperty(actionType);
        expect(Array.isArray(entries)).toBe(true);
        for (const entry of entries) {
          const prefix = entryPrefix(entry);
          expect(prefix.length).toBeGreaterThan(0);
          for (const element of prefix) {
            expect(typeof element).toBe("string");
          }
        }
      }
    });
  }
});

describe("command filenames match top-level command in entries", () => {
  for (const file of commandFiles) {
    test(`${file} entries start with "${file.replace(".json", "")}"`, () => {
      const cmd = file.replace(".json", "");
      const parsed = prefixEntries(readCommandFile(file));
      for (const entries of Object.values(parsed)) {
        for (const entry of entries) {
          const prefix = entryPrefix(entry);
          expect(prefix[0]).toBe(cmd);
        }
      }
    });
  }
});

describe("no duplicate prefix entries within a command file", () => {
  for (const file of commandFiles) {
    test(`${file} has no internal duplicates`, () => {
      const parsed = prefixEntries(readCommandFile(file));
      const seen = new Set<string>();
      const duplicates: string[] = [];
      for (const [actionType, entries] of Object.entries(parsed)) {
        for (const entry of entries) {
          const key = JSON.stringify(entryPrefix(entry));
          if (seen.has(key)) duplicates.push(`${key} in ${actionType}`);
          seen.add(key);
        }
      }
      expect(duplicates).toEqual([]);
    });
  }
});

describe("no duplicate prefix entries across command files", () => {
  test("each prefix appears in exactly one file and action type", () => {
    const seen = new Map<string, string>();
    const duplicates: string[] = [];
    for (const file of commandFiles) {
      const parsed = prefixEntries(readCommandFile(file));
      for (const [actionType, entries] of Object.entries(parsed)) {
        for (const entry of entries) {
          const key = JSON.stringify(entryPrefix(entry));
          const prev = seen.get(key);
          if (prev !== undefined) {
            duplicates.push(`${key} in both ${prev} and ${file}:${actionType}`);
          }
          seen.set(key, `${file}:${actionType}`);
        }
      }
    }
    expect(duplicates).toEqual([]);
  });
});

describe("entries within each action type are sorted", () => {
  for (const file of commandFiles) {
    const parsed = prefixEntries(readCommandFile(file));
    for (const [actionType, entries] of Object.entries(parsed)) {
      test(`${file} -> ${actionType} entries are in alphabetical order`, () => {
        const unsorted: string[] = [];
        for (let i = 1; i < entries.length; i++) {
          const prev = entryPrefix(entries[i - 1]);
          const curr = entryPrefix(entries[i]);
          if (compareEntries(prev, curr) > 0) {
            unsorted.push(
              `${JSON.stringify(curr)} should come before ${JSON.stringify(prev)}`,
            );
          }
        }
        expect(unsorted).toEqual([]);
      });
    }
  }
});

describe("action type keys within each command file are sorted", () => {
  for (const file of commandFiles) {
    test(`${file} action types are alphabetically sorted`, () => {
      const parsed = prefixEntries(readCommandFile(file));
      const keys = Object.keys(parsed);
      const sorted = [...keys].sort();
      expect(keys).toEqual(sorted);
    });
  }
});
