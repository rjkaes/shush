// build-trie.ts
//
// Compiles data/classify_full/<action_type>/<command>.json into a pre-built
// trie at data/classifier-trie.json. Run at build time so the trie does not
// need to be reconstructed on every CLI invocation.
//
// Each action type is a directory under data/classify_full/. Inside each
// directory, per-command JSON files contain arrays of string-array prefixes
// (e.g. [["git", "status"], ["git", "log", "--oneline"]]).
//
// Usage: bun run scripts/build-trie.ts

import { readdirSync, statSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dir, "..");
const INPUT_DIR = resolve(ROOT, "data", "classify_full");
const OUTPUT_FILE = resolve(ROOT, "data", "classifier-trie.json");

interface TrieNode {
  [key: string]: TrieNode | string | undefined;
  _?: string; // action type, present only on terminal nodes
}

async function main(): Promise<void> {
  const actionDirs = readdirSync(INPUT_DIR)
    .filter((d) => statSync(resolve(INPUT_DIR, d)).isDirectory())
    .sort();

  const root: TrieNode = {};
  let totalFiles = 0;

  for (const actionType of actionDirs) {
    const dir = resolve(INPUT_DIR, actionType);
    const cmdFiles = readdirSync(dir)
      .filter((f) => f.endsWith(".json"))
      .sort();

    for (const cmdFile of cmdFiles) {
      const raw = await Bun.file(resolve(dir, cmdFile)).json();

      if (
        !Array.isArray(raw) ||
        !raw.every(
          (arr: unknown) =>
            Array.isArray(arr) && arr.every((s: unknown) => typeof s === "string"),
        )
      ) {
        throw new Error(`${actionType}/${cmdFile}: expected JSON array of string arrays`);
      }

      for (const prefix of raw as string[][]) {
        let node = root;
        for (const token of prefix) {
          if (!(token in node) || typeof node[token] === "string") {
            node[token] = {};
          }
          node = node[token] as TrieNode;
        }
        node._ = actionType;
      }

      totalFiles++;
    }
  }

  await Bun.write(OUTPUT_FILE, JSON.stringify(root, null, 2) + "\n");

  console.log(
    `Built ${OUTPUT_FILE} from ${totalFiles} command files across ${actionDirs.length} action types.`,
  );
}

await main();
