import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join, basename } from "node:path";
import { classifyTokens } from "../src/taxonomy";

const dataDir = join(import.meta.dir, "..", "data");
const classifyDir = join(dataDir, "classify_full");

const policies: Record<string, string> = JSON.parse(
  readFileSync(join(dataDir, "policies.json"), "utf-8"),
);
const types: Record<string, string> = JSON.parse(
  readFileSync(join(dataDir, "types.json"), "utf-8"),
);

// Load all classify_full data files once.
const dataFiles = readdirSync(classifyDir)
  .filter((f) => f.endsWith(".json"))
  .map((f) => ({
    name: f,
    data: JSON.parse(readFileSync(join(classifyDir, f), "utf-8")) as Record<
      string,
      unknown
    >,
  }));

describe("data-consistency", () => {
  // ── 1. Every action type in classify_full data files exists in policies.json ──

  test("every action type in classify_full data files exists in policies.json", () => {
    const errors: string[] = [];

    for (const { name, data } of dataFiles) {
      for (const key of Object.keys(data)) {
        if (key === "flag_rules") {
          // flag_rules is an array of objects with a `type` field
          const rules = data[key] as Array<{ type: string }>;
          for (const rule of rules) {
            if (!(rule.type in policies)) {
              errors.push(`${name}: flag_rules type "${rule.type}"`);
            }
          }
        } else {
          if (!(key in policies)) {
            errors.push(`${name}: action type "${key}"`);
          }
        }
      }
    }

    expect(errors).toEqual([]);
  });

  // ── 2. Every action type in policies.json exists in types.json ──

  test("every action type in policies.json exists in types.json", () => {
    const missing = Object.keys(policies).filter((k) => !(k in types));
    expect(missing).toEqual([]);
  });

  // ── 3. Every action type in policies.json has at least one command mapping ──

  test("every action type in policies.json has at least one command mapping", () => {
    // Types assigned procedurally, not via data files.
    const exempt = new Set(["unknown", "obfuscated", "script_exec"]);

    // Collect all action types referenced across data files.
    const referenced = new Set<string>();
    for (const { data } of dataFiles) {
      for (const key of Object.keys(data)) {
        if (key === "flag_rules") {
          const rules = data[key] as Array<{ type: string }>;
          for (const rule of rules) {
            referenced.add(rule.type);
          }
        } else {
          referenced.add(key);
        }
      }
    }

    const orphaned = Object.keys(policies).filter(
      (k) => !referenced.has(k) && !exempt.has(k),
    );
    expect(orphaned).toEqual([]);
  });

  // ── 4. All policy values are valid decisions ──

  test("all policy values are valid decisions", () => {
    const validDecisions = new Set(["allow", "context", "ask", "block"]);
    const invalid = Object.entries(policies).filter(
      ([, v]) => !validDecisions.has(v),
    );
    expect(invalid).toEqual([]);
  });

  // ── 5. No duplicate prefixes across action types within a single data file ──

  test("no duplicate prefixes across action types within a single data file", () => {
    const errors: string[] = [];

    for (const { name, data } of dataFiles) {
      const seen = new Map<string, string>();

      for (const [actionType, prefixes] of Object.entries(data)) {
        if (actionType === "flag_rules") continue;
        if (!Array.isArray(prefixes)) continue;

        for (const prefix of prefixes) {
          const key = JSON.stringify(prefix);
          const existing = seen.get(key);
          if (existing) {
            errors.push(
              `${name}: prefix ${key} appears in both "${existing}" and "${actionType}"`,
            );
          } else {
            seen.set(key, actionType);
          }
        }
      }
    }

    expect(errors).toEqual([]);
  });

  // ── 6. Trie lookup matches raw data for every prefix ──

  test("trie lookup matches raw data for every prefix", () => {
    const errors: string[] = [];

    for (const { name, data } of dataFiles) {
      for (const [actionType, prefixes] of Object.entries(data)) {
        if (actionType === "flag_rules") continue;
        if (!Array.isArray(prefixes)) continue;

        for (const prefix of prefixes as string[][]) {
          const result = classifyTokens(prefix);
          if (result !== actionType) {
            errors.push(
              `${name}: classifyTokens(${JSON.stringify(prefix)}) = "${result}", expected "${actionType}"`,
            );
          }
        }
      }
    }

    expect(errors).toEqual([]);
  });

  // ── 7. Trie returns 'unknown' for unrecognized commands ──

  test.each([
    [["xyzzy123"]],
    [["notarealcommand", "subcommand"]],
    [["aaaa", "bbbb", "cccc"]],
  ] as [string[]][])("classifyTokens(%j) -> unknown", (tokens) => {
    expect(classifyTokens(tokens)).toBe("unknown");
  });

  // ── 8. Trie leaf nodes match expected types ──

  test.each([
    [["git", "status"], "git_safe"],
    [["ncat"], "network_write"],
    [["rm"], "filesystem_delete"],
    [["cat"], "filesystem_read"],
  ] as [string[], string][])(
    "classifyTokens(%j) -> %s",
    (tokens, expected) => {
      expect(classifyTokens(tokens)).toBe(expected);
    },
  );
});
