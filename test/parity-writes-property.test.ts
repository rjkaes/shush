// test/parity-writes-property.test.ts
// Property-based test for G1: every write-emitter command applied to any
// sensitive path must produce a decision of at least "ask".
import { describe, test } from "bun:test";
import fc from "fast-check";
import { evaluate } from "../src/evaluate.js";
import { EMPTY_CONFIG } from "../src/types.js";
import { WRITE_EMITTERS, SENSITIVE_DIRS } from "./z3-proofs/extract.js";

const EMITTERS = [...WRITE_EMITTERS.keys()];
const SENSITIVE_PATHS = SENSITIVE_DIRS.map((e) => e.resolved);

function evalBash(cmd: string) {
  return evaluate({ toolName: "Bash", toolInput: { command: cmd }, cwd: null }, EMPTY_CONFIG);
}

describe("G1 bash/file write parity (property)", () => {
  test("every write-emitter × sensitive path → decision ≥ ask", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...EMITTERS),
        fc.constantFrom(...SENSITIVE_PATHS),
        fc.subarray(["-f", "-r", "-a", "-p", "--", ""], { maxLength: 2 }),
        (cmd, sensPath, flags) => {
          const tokens = [cmd, ...flags.filter(Boolean), `'${sensPath}'`].join(" ");
          const out = evalBash(tokens);
          if (!["ask", "block"].includes(out.decision)) {
            throw new Error(`parity break: ${tokens} -> ${out.decision} (${out.reason}); expected ask or block`);
          }
        },
      ),
      { numRuns: 500 },
    );
  });
});
