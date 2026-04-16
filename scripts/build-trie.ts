// build-trie.ts
//
// Compiles data/classify_full/<command>.json into a pre-built trie at
// data/classifier-trie.json. Run at build time so the trie does not need
// to be reconstructed on every CLI invocation.
//
// Each command file is a JSON object keyed by action type, where each value
// is an array of entries. Each entry is either:
//   - a string array:            ["cmd", "sub"]
//   - an object with pathArgs:   { prefix: ["cmd", "sub"], pathArgs: [-1] }
//
// The special key "flag_rules" is reserved for flag-rule data (handled by
// build-flag-rules.ts) and is skipped by the trie builder. Action types are
// validated against data/types.json.
//
// Usage: bun run scripts/build-trie.ts

import { readdirSync } from "node:fs";
import { resolve } from "node:path";
import { parseClassifyEntry } from "../src/taxonomy.js";

const ROOT = resolve(import.meta.dir, "..");
const INPUT_DIR = resolve(ROOT, "data", "classify_full");
const TYPES_FILE = resolve(ROOT, "data", "types.json");
const OUTPUT_FILE = resolve(ROOT, "data", "classifier-trie.json");

interface TrieNode {
  [key: string]: TrieNode | string | number[] | undefined;
  _?: string;   // action type, present only on terminal nodes
  _p?: number[]; // pathArgs indices, present only when non-empty
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

/** Extract the prefix array from a raw entry (array or object form). */
function rawPrefix(entry: unknown): string[] {
  if (Array.isArray(entry)) return entry as string[];
  if (entry !== null && typeof entry === "object") {
    const obj = entry as { prefix?: unknown };
    if (Array.isArray(obj.prefix)) return obj.prefix as string[];
  }
  return [];
}

/**
 * Normalize a parsed command file: sort action-type keys alphabetically,
 * and sort prefix arrays within each action type lexicographically.
 * Returns the sorted object (new reference).
 *
 * Entries may be bare string arrays or {prefix, pathArgs} objects.
 * Sorting is by prefix for consistency.
 */
function normalizeCommandFile(
  raw: Record<string, unknown[]>,
): Record<string, unknown[]> {
  const sorted: Record<string, unknown[]> = {};
  for (const key of Object.keys(raw).sort()) {
    sorted[key] = [...raw[key]].sort((a, b) =>
      compareEntries(rawPrefix(a), rawPrefix(b)),
    );
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
      // Skip flag_rules — handled by build-flag-rules.ts
      if (actionType === "flag_rules") continue;

      // Validate action type against types.json
      if (!validTypes.has(actionType)) {
        throw new Error(
          `${cmdFile}: unknown action type "${actionType}". ` +
            `Valid types: ${[...validTypes].sort().join(", ")}`,
        );
      }

      // Validate and iterate entries (array-of-entries)
      if (!Array.isArray(prefixes)) {
        throw new Error(
          `${cmdFile}.${actionType}: expected array of entries`,
        );
      }

      for (const rawEntry of prefixes as unknown[]) {
        // Delegate parsing and validation to parseClassifyEntry.
        // This accepts both bare string arrays and {prefix, pathArgs} objects.
        let entry;
        try {
          entry = parseClassifyEntry(rawEntry);
        } catch (err) {
          throw new Error(
            `${cmdFile}.${actionType}: ${(err as Error).message}`,
          );
        }

        if (entry.prefix.length === 0) {
          throw new Error(
            `${cmdFile}.${actionType}: prefix must be non-empty`,
          );
        }

        let node = root;
        for (const token of entry.prefix) {
          if (!(token in node) || typeof node[token] === "string" || Array.isArray(node[token])) {
            node[token] = {};
          }
          node = node[token] as TrieNode;
        }
        node._ = actionType;
        // Only store _p when pathArgs is non-empty to keep the trie compact.
        if (entry.pathArgs.length > 0) {
          node._p = entry.pathArgs as number[];
        } else {
          delete node._p;
        }
      }

      actionTypesSeen.add(actionType);
    }

    // Normalize sort order and rewrite the source file so that
    // contributors don't need to maintain sort order by hand.
    // Separate flag_rules (opaque to the trie builder) from prefix entries.
    const { flag_rules, ...prefixEntries } = raw as Record<string, unknown>;
    const normalized: Record<string, unknown> = normalizeCommandFile(
      prefixEntries as Record<string, unknown[]>,
    );
    if (flag_rules !== undefined) {
      normalized.flag_rules = flag_rules;
    }
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
