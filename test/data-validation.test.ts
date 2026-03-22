import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "fs";
import { join } from "path";
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

/** All action-type directories under classify_full/. */
const actionDirs = readdirSync(CLASSIFY_DIR).filter((d) =>
  statSync(join(CLASSIFY_DIR, d)).isDirectory(),
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

/** Read all entries from a per-command JSON file. */
function readCommandFile(actionType: string, file: string): string[][] {
  return JSON.parse(
    readFileSync(join(CLASSIFY_DIR, actionType, file), "utf-8"),
  );
}

/** List all command JSON files in an action-type directory. */
function commandFiles(actionType: string): string[] {
  return readdirSync(join(CLASSIFY_DIR, actionType))
    .filter((f) => f.endsWith(".json"))
    .sort();
}

describe("action-type directories match types.json keys", () => {
  for (const dir of actionDirs) {
    test(`${dir} exists in types.json`, () => {
      expect(typesJson).toHaveProperty(dir);
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

describe("command files are valid JSON arrays of string arrays", () => {
  for (const actionType of actionDirs) {
    for (const file of commandFiles(actionType)) {
      test(`${actionType}/${file} is valid`, () => {
        const parsed = readCommandFile(actionType, file);
        expect(Array.isArray(parsed)).toBe(true);
        for (const entry of parsed) {
          expect(Array.isArray(entry)).toBe(true);
          for (const element of entry) {
            expect(typeof element).toBe("string");
          }
        }
      });
    }
  }
});

describe("command filenames match top-level command in entries", () => {
  for (const actionType of actionDirs) {
    for (const file of commandFiles(actionType)) {
      test(`${actionType}/${file} entries start with "${file.replace(".json", "")}"`, () => {
        const cmd = file.replace(".json", "");
        const parsed = readCommandFile(actionType, file);
        for (const entry of parsed) {
          expect(entry[0]).toBe(cmd);
        }
      });
    }
  }
});

describe("no duplicate prefix entries within a command file", () => {
  for (const actionType of actionDirs) {
    for (const file of commandFiles(actionType)) {
      test(`${actionType}/${file} has no internal duplicates`, () => {
        const parsed = readCommandFile(actionType, file);
        const seen = new Set<string>();
        const duplicates: string[] = [];
        for (const entry of parsed) {
          const key = JSON.stringify(entry);
          if (seen.has(key)) duplicates.push(key);
          seen.add(key);
        }
        expect(duplicates).toEqual([]);
      });
    }
  }
});

describe("no duplicate prefix entries across action types", () => {
  test("each prefix appears in exactly one action type", () => {
    const seen = new Map<string, string>();
    const duplicates: string[] = [];
    for (const actionType of actionDirs) {
      for (const file of commandFiles(actionType)) {
        const parsed = readCommandFile(actionType, file);
        for (const entry of parsed) {
          const key = JSON.stringify(entry);
          const prev = seen.get(key);
          if (prev !== undefined) {
            duplicates.push(`${key} in both ${prev} and ${actionType}/${file}`);
          }
          seen.set(key, `${actionType}/${file}`);
        }
      }
    }
    expect(duplicates).toEqual([]);
  });
});

describe("entries within each command file are sorted", () => {
  for (const actionType of actionDirs) {
    for (const file of commandFiles(actionType)) {
      test(`${actionType}/${file} entries are in alphabetical order`, () => {
        const parsed = readCommandFile(actionType, file);
        const unsorted: string[] = [];
        for (let i = 1; i < parsed.length; i++) {
          if (compareEntries(parsed[i - 1], parsed[i]) > 0) {
            unsorted.push(
              `${JSON.stringify(parsed[i])} should come before ${JSON.stringify(parsed[i - 1])}`,
            );
          }
        }
        expect(unsorted).toEqual([]);
      });
    }
  }
});

