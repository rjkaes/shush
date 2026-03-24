// build-trie.ts
//
// Compiles data/classify_full/<command>.json into a pre-built trie at
// data/classifier-trie.json. Run at build time so the trie does not need
// to be reconstructed on every CLI invocation.
//
// Each command file is a JSON object keyed by action type, where each value
// is an array of string-array prefixes. Action types are validated against
// data/types.json.
//
// Usage: bun run scripts/build-trie.ts

import { readdirSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dir, "..");
const INPUT_DIR = resolve(ROOT, "data", "classify_full");
const TYPES_FILE = resolve(ROOT, "data", "types.json");
const OUTPUT_FILE = resolve(ROOT, "data", "classifier-trie.json");

interface TrieNode {
  [key: string]: TrieNode | string | undefined;
  _?: string; // action type, present only on terminal nodes
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

/**
 * Normalize a parsed command file: sort action-type keys alphabetically,
 * and sort prefix arrays within each action type lexicographically.
 * Returns the sorted object (new reference).
 */
function normalizeCommandFile(
  raw: Record<string, string[][]>,
): Record<string, string[][]> {
  const sorted: Record<string, string[][]> = {};
  for (const key of Object.keys(raw).sort()) {
    sorted[key] = [...raw[key]].sort(compareEntries);
  }
  return sorted;
}

async function main(): Promise<void> {
  // Load valid action types for validation
  const validTypes = new Set(
    Object.keys(await Bun.file(TYPES_FILE).json()),
  );

  const cmdFiles = readdirSync(INPUT_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort();

  const root: TrieNode = {};
  const actionTypesSeen = new Set<string>();

  for (const cmdFile of cmdFiles) {
    const raw = await Bun.file(resolve(INPUT_DIR, cmdFile)).json();

    // Validate top-level shape: object keyed by action type
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      throw new Error(
        `${cmdFile}: expected JSON object keyed by action type`,
      );
    }

    for (const [actionType, prefixes] of Object.entries(raw)) {
      // Validate action type against types.json
      if (!validTypes.has(actionType)) {
        throw new Error(
          `${cmdFile}: unknown action type "${actionType}". ` +
            `Valid types: ${[...validTypes].sort().join(", ")}`,
        );
      }

      // Validate prefix arrays
      if (
        !Array.isArray(prefixes) ||
        !prefixes.every(
          (arr: unknown) =>
            Array.isArray(arr) &&
            arr.length > 0 &&
            arr.every((s: unknown) => typeof s === "string"),
        )
      ) {
        throw new Error(
          `${cmdFile}.${actionType}: expected non-empty array of string arrays`,
        );
      }

      for (const prefix of prefixes as string[][]) {
        let node = root;
        for (const token of prefix) {
          if (!(token in node) || typeof node[token] === "string") {
            node[token] = {};
          }
          node = node[token] as TrieNode;
        }
        node._ = actionType;
      }

      actionTypesSeen.add(actionType);
    }

    // Normalize sort order and rewrite the source file so that
    // contributors don't need to maintain sort order by hand.
    const normalized = normalizeCommandFile(raw as Record<string, string[][]>);
    const canonical = JSON.stringify(normalized, null, 2) + "\n";
    const filePath = resolve(INPUT_DIR, cmdFile);
    const current = await Bun.file(filePath).text();
    if (current !== canonical) {
      await Bun.write(filePath, canonical);
    }
  }

  await Bun.write(OUTPUT_FILE, JSON.stringify(root, null, 2) + "\n");

  console.log(
    `Built ${OUTPUT_FILE} from ${cmdFiles.length} command files ` +
      `covering ${actionTypesSeen.size} action types.`,
  );
}

await main();
