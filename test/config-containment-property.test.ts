// test/config-containment-property.test.ts
// Property-based test for G7: no user config (actions, sensitive_paths,
// allowed_paths) can produce a sensitive-path Write decision below "ask".
import { describe, test } from "bun:test";
import "./fast-check-setup";
import fc from "fast-check";
import { parseConfigYaml, mergeConfigs } from "../src/config.js";
import { EMPTY_CONFIG, STRICTNESS } from "../src/types.js";
import { evaluate } from "../src/evaluate.js";
import { SENSITIVE_DIRS, ACTION_TYPES } from "./z3-proofs/extract.js";

const DECISIONS = ["allow", "context", "ask", "block"] as const;

describe("G7 config containment (property)", () => {
  test("user config cannot produce a sensitive-path decision below default", () => {
    fc.assert(
      fc.property(
        fc.record({
          actionsYaml: fc.dictionary(
            fc.constantFrom(...ACTION_TYPES),
            fc.constantFrom(...DECISIONS),
            { maxKeys: 3 },
          ),
          sensitivePathsYaml: fc.dictionary(
            fc.constantFrom(...SENSITIVE_DIRS.map((e) => e.display)),
            fc.constantFrom("allow", "context"),
            { maxKeys: 2 },
          ),
          allowedPaths: fc.subarray(
            [...SENSITIVE_DIRS.map((e) => e.display), "/srv/data", "/tmp/work"],
            { maxLength: 3 },
          ),
        }),
        (cfg) => {
          const yaml = [
            cfg.actionsYaml && Object.keys(cfg.actionsYaml).length
              ? "actions:\n" +
                Object.entries(cfg.actionsYaml)
                  .map(([k, v]) => `  ${k}: ${v}`)
                  .join("\n")
              : "",
            cfg.sensitivePathsYaml && Object.keys(cfg.sensitivePathsYaml).length
              ? "sensitive_paths:\n" +
                Object.entries(cfg.sensitivePathsYaml)
                  .map(([k, v]) => `  "${k}": ${v}`)
                  .join("\n")
              : "",
            cfg.allowedPaths.length
              ? "allowed_paths:\n" +
                cfg.allowedPaths.map((p) => `  - "${p}"`).join("\n")
              : "",
          ]
            .filter(Boolean)
            .join("\n");
          const merged = mergeConfigs(EMPTY_CONFIG, parseConfigYaml(yaml));
          for (const { display } of SENSITIVE_DIRS) {
            const out = evaluate(
              {
                toolName: "Write",
                toolInput: { file_path: display, content: "x" },
                cwd: null,
              },
              merged,
            );
            if (STRICTNESS[out.decision] < STRICTNESS.ask) {
              throw new Error(
                `G7 break: config=${JSON.stringify(cfg)} target=${display} -> ${out.decision} (${out.reason})`,
              );
            }
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});
