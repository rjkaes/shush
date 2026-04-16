#!/usr/bin/env bun
import { readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";

// Observed baseline: max shard 858ms, total ~10s (13 shards).
// 30s per-shard gives ~35x headroom; 60s total gives ~6x — tight enough to
// catch a perf regression, loose enough to survive runner noise.
const SHARD_BUDGET_MS = 30_000;
const SUITE_BUDGET_MS = 60_000;

const shards = readdirSync("test")
  .filter(f => /^z3-.*\.test\.ts$/.test(f))
  .map(f => `test/${f}`);

let totalMs = 0;

if (shards.length === 0) {
  console.error("measure-z3: no z3 shards found in test/");
  process.exit(1);
}
let failed = false;

for (const shard of shards) {
  const start = Date.now();
  const r = spawnSync("bun", ["test", shard], { stdio: "inherit" });
  const elapsed = Date.now() - start;
  totalMs += elapsed;

  if (r.status !== 0) {
    console.error(`measure-z3: ${shard} FAILED`);
    failed = true;
  }
  if (elapsed > SHARD_BUDGET_MS) {
    console.error(`measure-z3: ${shard} took ${elapsed}ms (budget ${SHARD_BUDGET_MS}ms)`);
    failed = true;
  } else {
    console.log(`measure-z3: ${shard} ok (${elapsed}ms)`);
  }
}

console.log(`measure-z3: total ${totalMs}ms`);
if (totalMs > SUITE_BUDGET_MS) {
  console.error(`measure-z3: total ${totalMs}ms exceeds suite budget ${SUITE_BUDGET_MS}ms`);
  failed = true;
}

process.exit(failed ? 1 : 0);
