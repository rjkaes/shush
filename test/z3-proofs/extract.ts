// test/z3-proofs/extract.ts
// Single source of truth for Z3 proofs and fast-check oracles.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  writeEmittersFromData,
  RESET_OPERATORS,
  PIPE_OPERATORS,
} from "../../src/predicates/composition.js";
import {
  SENSITIVE_DIRS,
  SENSITIVE_BASENAMES,
} from "../../src/predicates/path.js";

const DATA_DIR = fileURLToPath(new URL("../../data", import.meta.url));

export const WRITE_EMITTERS = writeEmittersFromData();

export { SENSITIVE_DIRS, SENSITIVE_BASENAMES, RESET_OPERATORS, PIPE_OPERATORS };

export const ACTION_TYPES: readonly string[] = (() => {
  const types = JSON.parse(readFileSync(path.join(DATA_DIR, "types.json"), "utf-8")) as Record<string, string>;
  return Object.freeze(Object.keys(types));
})();

/** Reference write-emitters that must be present. Build fails if missing. */
export const REFERENCE_WRITE_EMITTERS: readonly string[] = [
  "tee", "dd", "cp", "mv", "install", "ln",
];

export function assertExtraction(): void {
  if (WRITE_EMITTERS.size === 0) {
    throw new Error("extract.ts: WRITE_EMITTERS is empty; check data/classify_full/");
  }
  const missing = REFERENCE_WRITE_EMITTERS.filter((c) => !WRITE_EMITTERS.has(c));
  if (missing.length > 0) {
    throw new Error(`extract.ts: missing reference write-emitters: ${missing.join(", ")}`);
  }
  if (SENSITIVE_DIRS.length === 0) {
    throw new Error("extract.ts: SENSITIVE_DIRS is empty");
  }
  if (RESET_OPERATORS.size === 0) {
    throw new Error("extract.ts: RESET_OPERATORS is empty");
  }
  if (ACTION_TYPES.length === 0) {
    throw new Error("extract.ts: ACTION_TYPES is empty");
  }
}
