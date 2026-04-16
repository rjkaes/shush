import { describe, test, expect } from "bun:test";
import { loadConfigFromString } from "../src/config.js";

describe("G7.2 fail-closed", () => {
  test("rejects config when allowed_paths overlaps sensitive", () => {
    const yaml = `allowed_paths:\n  - ~/.ssh\n`;
    const r = loadConfigFromString(yaml);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/allowed_paths.*overlaps sensitive/i);
  });

  test("accepts overlap when allowOverlapWarn: true (deprecated soft mode)", () => {
    const yaml = `allowOverlapWarn: true\nallowed_paths:\n  - ~/.ssh\n`;
    const r = loadConfigFromString(yaml);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.config.allowedPaths).toEqual([]);
      expect(r.warnings.some((w: string) => /deprecated/i.test(w))).toBe(true);
    }
  });

  test("non-overlap loads cleanly", () => {
    const yaml = `allowed_paths:\n  - /tmp/scratch\n`;
    const r = loadConfigFromString(yaml);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.warnings).toEqual([]);
      expect(r.config.allowedPaths).toContain("/tmp/scratch");
    }
  });
});
