// generate-classifiers.ts
//
// Assembles per-actionType JSON files from data/classify_full/ into the
// single TypeScript lookup table at data/classify-full.ts.
//
// Usage: bun run scripts/generate-classifiers.ts

import { readdir } from "node:fs/promises";
import { basename, resolve } from "node:path";

// ---------------------------------------------------------------------------
// Known actionTypes (defined inline to avoid circular imports from taxonomy)
// ---------------------------------------------------------------------------

const KNOWN_ACTION_TYPES = new Set([
  "container_destructive",
  "db_read",
  "db_write",
  "filesystem_delete",
  "filesystem_read",
  "filesystem_write",
  "git_discard",
  "git_history_rewrite",
  "git_safe",
  "git_write",
  "lang_exec",
  "network_diagnostic",
  "network_outbound",
  "network_write",
  "obfuscated",
  "package_install",
  "package_run",
  "package_uninstall",
  "process_signal",
]);

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const ROOT = resolve(import.meta.dir, "..");
const INPUT_DIR = resolve(ROOT, "data", "classify_full");
const OUTPUT_FILE = resolve(ROOT, "data", "classify-full.ts");

// ---------------------------------------------------------------------------
// PrefixEntry shape (mirrored in generated output)
// ---------------------------------------------------------------------------

interface PrefixEntry {
  prefix: string[];
  actionType: string;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // Ensure the input directory exists (may be empty before Task 2).
  let files: string[] = [];
  try {
    const entries = await readdir(INPUT_DIR);
    files = entries.filter((f) => f.endsWith(".json")).sort();
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      // No input directory yet; generate an empty table.
      files = [];
    } else {
      throw err;
    }
  }

  const allEntries: PrefixEntry[] = [];

  for (const file of files) {
    const actionType = basename(file, ".json");

    if (!KNOWN_ACTION_TYPES.has(actionType)) {
      throw new Error(
        `Unknown actionType "${actionType}" from file ${file}. ` +
          `Valid types: ${[...KNOWN_ACTION_TYPES].sort().join(", ")}`,
      );
    }

    const raw = await Bun.file(resolve(INPUT_DIR, file)).json();
    const prefixes = raw as string[][];

    for (const prefix of prefixes) {
      allEntries.push({ prefix, actionType });
    }
  }

  // Sort: longest prefix first, then alphabetically by joined prefix.
  allEntries.sort((a, b) => {
    const lenDiff = b.prefix.length - a.prefix.length;
    if (lenDiff !== 0) return lenDiff;
    const aKey = a.prefix.join(" ");
    const bKey = b.prefix.join(" ");
    return aKey < bKey ? -1 : aKey > bKey ? 1 : 0;
  });

  // Build the generated file content.
  const entryLines = allEntries.map(
    (e) =>
      `  { prefix: ${JSON.stringify(e.prefix).replace(/,/g, ", ")}, actionType: ${JSON.stringify(e.actionType)} },`,
  );

  const output = [
    "// =============================================================================",
    "// AUTO-GENERATED from data/classify_full/*.json",
    "// Do not edit manually. Run: bun run scripts/generate-classifiers.ts",
    "// =============================================================================",
    "",
    "export interface PrefixEntry {",
    "  prefix: string[];",
    "  actionType: string;",
    "}",
    "",
    "export const CLASSIFY_FULL_TABLE: PrefixEntry[] = [",
    ...entryLines,
    "];",
    "",
  ].join("\n");

  await Bun.write(OUTPUT_FILE, output);

  console.log(
    `Generated ${OUTPUT_FILE} with ${allEntries.length} entries from ${files.length} files.`,
  );
}

await main();
