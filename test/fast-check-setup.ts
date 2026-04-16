// test/fast-check-setup.ts
// Centralised fast-check configuration. Import this module at the top of
// every test file that calls fc.assert or fc.property so all runs share the
// same seed and numRuns, making counterexamples reproducible across CI runs.
import fc from "fast-check";

const SEED = 0x5eed;
// 200 runs (2x default) catches more edge cases while keeping CI time in budget.
fc.configureGlobal({ seed: SEED, numRuns: 200 });

export const FAST_CHECK_SEED = SEED;
