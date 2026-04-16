// build-write-emitters.ts
//
// Compiles data/classify_full/<command>.json into a map of command name ->
// list of write-flavoured action types (filesystem_write, filesystem_delete,
// disk_destructive). Output lands at data/write-emitters.json and is
// imported directly by src/predicates/composition.ts, so the bundled hook
// does not need filesystem access at runtime.
//
// Usage: bun run scripts/build-write-emitters.ts

import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dir, "..");
const INPUT_DIR = resolve(ROOT, "data", "classify_full");
const OUTPUT_FILE = resolve(ROOT, "data", "write-emitters.json");

const WRITE_ACTIONS = new Set([
  "filesystem_write",
  "filesystem_delete",
  "disk_destructive",
]);

function main(): void {
  const out: Record<string, string[]> = {};
  const files = readdirSync(INPUT_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort();

  for (const file of files) {
    const cmd = file.replace(/\.json$/, "");
    const contents = JSON.parse(
      readFileSync(resolve(INPUT_DIR, file), "utf-8"),
    ) as Record<string, unknown>;
    const actions: string[] = [];
    for (const key of Object.keys(contents)) {
      if (WRITE_ACTIONS.has(key)) actions.push(key);
    }
    if (actions.length > 0) out[cmd] = actions.sort();
  }

  writeFileSync(OUTPUT_FILE, JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${Object.keys(out).length} write emitters to ${OUTPUT_FILE}`);
}

main();
