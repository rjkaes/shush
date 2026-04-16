// test/fast-check-seed.test.ts
// Regression: verifies that fast-check-setup.ts successfully pins the global
// seed so any CI counterexample can be replayed with a fixed seed.
import { describe, test, expect } from "bun:test";
import fc from "fast-check";
import { FAST_CHECK_SEED } from "./fast-check-setup";

describe("fast-check seed", () => {
  test("global seed is pinned to FAST_CHECK_SEED", () => {
    const cfg = fc.readConfigureGlobal();
    expect(cfg.seed).toBe(FAST_CHECK_SEED);
    expect(cfg.numRuns).toBe(200);
  });
});
