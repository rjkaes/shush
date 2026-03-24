// build-flag-rules.ts
//
// Extracts flag_rules from data/classify_full/*.json and compiles them
// into data/flag-rules-compiled.json. Each command file may contain a
// "flag_rules" key with an array of flag rule objects.
//
// Validation:
//   - Each rule's `type` must exist in data/types.json
//   - `tokenMatches` regex patterns must be valid
//   - Only known match primitives are accepted
//
// The compiled output strips `_comment` fields and is keyed by command
// name: Record<string, FlagRuleJSON[]>.
//
// Usage: bun run scripts/build-flag-rules.ts

import { readdirSync } from "node:fs";
import { basename, resolve } from "node:path";

const ROOT = resolve(import.meta.dir, "..");
const INPUT_DIR = resolve(ROOT, "data", "classify_full");
const OUTPUT_FILE = resolve(ROOT, "data", "flag-rules-compiled.json");
const TYPES_FILE = resolve(ROOT, "data", "types.json");

// Known match primitive keys. Exactly one must be present in each
// rule's `match` object.
const MATCH_PRIMITIVES = new Set([
  "anyFlag",
  "anyFlagPrefix",
  "flag",
  "anyToken",
  "tokenMatches",
]);

interface RawRule {
  match: Record<string, unknown>;
  type: string;
  _comment?: string;
}

interface CleanRule {
  match: Record<string, unknown>;
  type: string;
}

function stripComment(rule: RawRule): CleanRule {
  const { _comment: _, ...rest } = rule;
  return rest;
}

// ==============================================================================
// Validation helpers
// ==============================================================================

function validateMatchPrimitive(
  match: Record<string, unknown>,
  file: string,
  index: number,
): void {
  const keys = Object.keys(match);
  if (keys.length !== 1) {
    throw new Error(
      `${file}[${index}]: match must have exactly one key, got: ${keys.join(", ")}`,
    );
  }
  const key = keys[0];
  if (!MATCH_PRIMITIVES.has(key)) {
    throw new Error(
      `${file}[${index}]: unknown match primitive "${key}". ` +
        `Expected one of: ${[...MATCH_PRIMITIVES].join(", ")}`,
    );
  }

  // Type-check the value for each primitive.
  const val = match[key];
  switch (key) {
    case "anyFlag":
    case "anyFlagPrefix":
      if (!Array.isArray(val) || !val.every((v) => typeof v === "string")) {
        throw new Error(`${file}[${index}]: ${key} must be a string array`);
      }
      break;
    case "flag":
      // `flag` primitive requires a sibling `nextIn` inside the same
      // match object... but we already validated exactly one key.
      // Actually, `flag` + `nextIn` is a compound: { flag, nextIn }.
      // Re-check: the spec says { flag: string; nextIn: string[] }.
      // That means match has TWO keys for this primitive.
      throw new Error(
        `${file}[${index}]: "flag" primitive requires both "flag" and "nextIn" keys`,
      );
    case "anyToken":
      if (typeof val !== "string") {
        throw new Error(`${file}[${index}]: anyToken must be a string`);
      }
      break;
    case "tokenMatches":
      if (typeof val !== "string") {
        throw new Error(`${file}[${index}]: tokenMatches must be a string`);
      }
      try {
        new RegExp(val as string);
      } catch (e) {
        throw new Error(
          `${file}[${index}]: invalid regex in tokenMatches: ${(e as Error).message}`,
        );
      }
      break;
  }
}

function validateFlagNextIn(
  match: Record<string, unknown>,
  file: string,
  index: number,
): void {
  // The { flag, nextIn } compound has exactly two keys.
  const keys = Object.keys(match);
  if (keys.length !== 2 || !keys.includes("flag") || !keys.includes("nextIn")) {
    return; // Not a flag+nextIn compound; handled by single-key path.
  }
  if (typeof match.flag !== "string") {
    throw new Error(`${file}[${index}]: flag must be a string`);
  }
  if (
    !Array.isArray(match.nextIn) ||
    !match.nextIn.every((v: unknown) => typeof v === "string")
  ) {
    throw new Error(`${file}[${index}]: nextIn must be a string array`);
  }
}

function validateMatch(
  match: Record<string, unknown>,
  file: string,
  index: number,
): void {
  const keys = Object.keys(match);

  // Special case: { flag, nextIn } compound has two keys.
  if (keys.length === 2 && keys.includes("flag") && keys.includes("nextIn")) {
    validateFlagNextIn(match, file, index);
    return;
  }

  validateMatchPrimitive(match, file, index);
}

// ==============================================================================
// Main
// ==============================================================================

async function main(): Promise<void> {
  const validTypes: Record<string, string> = await Bun.file(TYPES_FILE).json();
  const typeNames = new Set(Object.keys(validTypes));

  const files = readdirSync(INPUT_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort();

  const compiled: Record<string, CleanRule[]> = {};
  let totalRules = 0;

  for (const file of files) {
    const command = basename(file, ".json");
    const fullFile: unknown = await Bun.file(resolve(INPUT_DIR, file)).json();

    if (typeof fullFile !== "object" || fullFile === null || Array.isArray(fullFile)) {
      continue; // Not a valid command file
    }

    const raw = (fullFile as Record<string, unknown>).flag_rules;
    if (raw === undefined) continue; // No flag rules in this command file

    if (!Array.isArray(raw)) {
      throw new Error(`${file}: flag_rules must be a JSON array of rules`);
    }

    const rules: CleanRule[] = [];

    for (let i = 0; i < raw.length; i++) {
      const entry = raw[i] as RawRule;

      if (!entry.match || typeof entry.match !== "object") {
        throw new Error(`${file}[${i}]: missing or invalid "match" object`);
      }
      if (typeof entry.type !== "string") {
        throw new Error(`${file}[${i}]: missing or invalid "type" string`);
      }
      if (!typeNames.has(entry.type)) {
        throw new Error(
          `${file}[${i}]: unknown type "${entry.type}". ` +
            `Must be one of: ${[...typeNames].join(", ")}`,
        );
      }

      validateMatch(entry.match, file, i);
      rules.push(stripComment(entry));
    }

    compiled[command] = rules;
    totalRules += rules.length;
  }

  await Bun.write(OUTPUT_FILE, JSON.stringify(compiled, null, 2) + "\n");

  const ruleCount = Object.keys(compiled).length;
  console.log(
    `Built ${OUTPUT_FILE}: ${ruleCount} commands with flag rules (${totalRules} rules total).`,
  );
}

await main();
