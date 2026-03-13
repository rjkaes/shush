// build-trie.ts
//
// Compiles data/classify_full/*.json into a pre-built trie at
// data/classifier-trie.json. Run at build time so the trie does not
// need to be reconstructed on every CLI invocation.
//
// Usage: bun run scripts/build-trie.ts

import { readdir } from "node:fs/promises";
import { basename, resolve } from "node:path";

const ROOT = resolve(import.meta.dir, "..");
const INPUT_DIR = resolve(ROOT, "data", "classify_full");
const OUTPUT_FILE = resolve(ROOT, "data", "classifier-trie.json");

interface TrieNode {
  [key: string]: TrieNode | string | undefined;
  _?: string; // action type, present only on terminal nodes
}

async function main(): Promise<void> {
  const entries = await readdir(INPUT_DIR);
  const files = entries.filter((f) => f.endsWith(".json")).sort();

  const root: TrieNode = {};

  for (const file of files) {
    const actionType = basename(file, ".json");
    const raw = await Bun.file(resolve(INPUT_DIR, file)).json();

    if (
      !Array.isArray(raw) ||
      !raw.every(
        (arr: unknown) =>
          Array.isArray(arr) && arr.every((s: unknown) => typeof s === "string"),
      )
    ) {
      throw new Error(`${file}: expected JSON array of string arrays`);
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
  }

  await Bun.write(OUTPUT_FILE, JSON.stringify(root, null, 2) + "\n");

  const count = files.length;
  console.log(`Built ${OUTPUT_FILE} from ${count} source files.`);
}

await main();
