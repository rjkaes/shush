// scripts/verify-extract.ts
// Run in CI before tests to fail fast on extraction regressions.

import {
  assertExtraction,
  WRITE_EMITTERS,
  SENSITIVE_DIRS,
  ACTION_TYPES,
} from "../test/z3-proofs/extract.js";

try {
  assertExtraction();
  console.log(
    `extract OK: ${WRITE_EMITTERS.size} write-emitters, ${SENSITIVE_DIRS.length} sensitive dirs, ${ACTION_TYPES.length} action types`,
  );
} catch (err) {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
}
