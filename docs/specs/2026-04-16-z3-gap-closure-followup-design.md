# Z3 Gap Closure: Follow-up — Design

Date: 2026-04-16

## Background

Review of `2026-04-16-z3-gap-closure-g1-g4-g7-design.md` surfaced
deferred items and missing details that need resolution before
implementation. This follow-up spec resolves them. It is a supplement,
not a replacement; the parent spec's architecture and goals stand.

Issues addressed:

- I1. G4 pipeline-flag persistence has an unbounded regression surface
  with only a post-break rollback plan.
- I2. G7.2 `allowedPaths` drop-with-warn silently softens protection
  if the operator ignores the warning.
- I3. G7.4 custom `classify` path-arg schema is assumed but undefined.
- I4. Coverage counter `< 100% fails` is flaky against fast-check's
  randomization.
- I5. G1 build guard hardcodes `{tee, dd, cp, mv, install, ln}`,
  contradicting the data-driven principle.
- I6. Migration order (Layer 1 refactor vs behavior changes) is
  unspecified and affects PR reviewability.
- I7. `COMMAND_WRAPPERS` referenced in Layer 2 but not defined in
  Layer 1.
- I8. G4 operator list has no parity check with `src/ast-walk.ts`.
- I9. Wall-time budget has no enforcement; nightly split drifts silently.

## Goals

1. Bound and verify G4's behavior-change surface pre-merge.
2. Make G7.2 fail-closed by default, with opt-in soft mode for legacy
   configs.
3. Define the custom-classify schema that G7.4 depends on.
4. Make coverage assertions deterministic.
5. Derive G1's build-guard reference set from data, not prose.
6. Sequence the PR split so each commit is independently reviewable
   and revertible.
7. Close the `COMMAND_WRAPPERS` and operator-parity gaps.
8. Enforce wall-time budget in CI.

## Non-goals

- Revisiting parent spec's Layer 1/2/3 architecture.
- Adding new gap coverage (G2/G3/G5/G6/G8-G12 remain deferred).
- String-theory-complete Z3 modeling.

## Resolutions

### I1 — G4 regression surface

`src/composition.ts` change: `seenNetworkSource` and `seenExecSink`
persist across reset operators (`&&`, `||`, `;`, etc.). This broadens
the net-to-exec rule and touches every multi-stage bash classification.

Pre-merge containment:

- **Golden corpus.** New file `test/fixtures/composition-golden.txt`.
  Each line: a real-world multi-stage command that must stay `allow`.
  Seed from: `cd /tmp && ls`, `git pull && npm test`, `make && make
  install`, `mkdir build && cd build`, `find . -name '*.ts' && echo
  done`, `[ -f x ] || touch x`, `test -d .git && git status`. Mined
  additionally from the last 12 months of shell history in
  `data/classify_full/` examples and CI logs.
- **Regression gate.** New test `test/composition-golden.test.ts`
  asserts each line classifies to `allow` or `context`, never `ask` or
  `block`. Fails PR if persistence over-fires.
- **Explicit reset conditions.** Persistence applies only when the
  downstream stage consumes stdin from an upstream source. Stages
  connected only by `&&`/`||`/`;` with no data flow reset flags at
  operator boundary UNLESS upstream stage emitted to a file
  subsequently read by downstream (flagged by shared path in
  redirections or `$(...)` substitution).
- **Rollback granularity.** Behavior change lands in a dedicated
  commit on top of the pure refactor commit (see I6). Revert = single
  `git revert`.

### I2 — G7.2 fail-closed

Parent spec: "overlapping entries are dropped with a stderr warning."
Change: reject the entire config load on overlap. Fall back to
defaults. Emit `ask` for the next decision with a pointer to the
offending config path.

Opt-in soft mode: config key `allowOverlapWarn: true` restores
drop-with-warn behavior for migration. Documented as a 1-release
deprecation; removed in the release following.

Rationale: a silent drop plus a warning the operator may never read
is the same failure mode this gap was filed to close.

### I3 — Custom classify schema

Extend `data/classify_full/*.json` entry format and `src/config.ts`
user-provided entries. Current entries are an array of token prefixes.
New optional field `pathArgs`:

```json
{
  "filesystem_write": [
    { "prefix": ["mycmd", "save"], "pathArgs": [2] },
    ["mycmd", "noop"]
  ]
}
```

- Bare array form remains valid; treated as `{prefix: [...], pathArgs:
  []}`.
- `pathArgs` is a list of zero-based token indices that `evaluate`
  passes through `checkPath`. Negative indices count from end.
- Schema validated at load time. Unknown fields rejected. Duplicate
  indices rejected.
- Parent spec's G7.4 proof references this field; extract.ts includes
  it in the WRITE_EMITTERS map.

Data migration: built-in entries that take path args (e.g. `cp`, `mv`)
gain `pathArgs` annotations in a prep commit before G1/G7 proofs run.
Tests in `test/classify.test.ts` cover the annotated cases.

### I4 — Deterministic coverage

Replace "coverage counter `< 100%` fails" with:

- **Enumerated coverage test.** `test/parity-writes.test.ts` iterates
  over extracted `WRITE_EMITTERS` (finite, deterministic) and asserts
  each one is exercised against at least one sensitive path. No
  fast-check randomness in the coverage gate itself.
- **fast-check randomized layer** runs separately over the same
  domain with a pinned seed (`fc.configureGlobal({seed: 0x5EED})`) for
  reproducibility. This layer finds shrinkable counterexamples; it
  does not gate coverage.

Result: coverage pass/fail is a pure function of `data/classify_full/`
contents. No flake.

### I5 — Data-driven build guard

Remove the hardcoded `{tee, dd, cp, mv, install, ln}` reference set.
Replace with:

- `scripts/verify-extract.ts` asserts `WRITE_EMITTERS.size >= N` where
  `N` is derived at script start from
  `Object.keys(data/types.json).filter(t => t.startsWith('filesystem_')
  || t === 'disk_destructive').length * 1` as a floor, then re-counted
  from the filtered classify_full files.
- Specific-command assertions move out of the build guard and into
  `test/parity-writes.test.ts` as regression cases, where they can
  evolve with the data.
- The build guard only asserts non-emptiness and type-correctness of
  extraction output.

### I6 — Migration order

PR split into three commits, each green independently:

1. **Refactor** (zero behavior change). New files
   `src/predicates/{path,composition,config}.ts`. Existing modules
   re-export from predicates. Full test suite passes unchanged.
2. **Proof scaffolding**. `test/z3-proofs/extract.ts`, new Z3 and
   fast-check test files. Proofs reference Layer 1 predicates.
   Behavior change proofs are skipped (`.skip`) with TODO markers.
3. **Behavior changes**. G1 path-check extension, G4 persistence, G7
   containment. Skipped proofs enabled. Golden-corpus test added.

Commit 1 is trivially revertible. Commit 3 is the load-bearing
change; revert leaves 1 and 2 in place as dead but harmless scaffolding
that a follow-up commit can activate again.

Commits land in a single PR with the above order preserved. Squash
merge is rejected; merge commit preserves history.

### I7 — COMMAND_WRAPPERS definition

Add to `src/predicates/composition.ts`:

```ts
export const COMMAND_WRAPPERS: ReadonlySet<string> = new Set([
  "bash", "sh", "zsh", "dash", "ash",
  "env", "nice", "nohup", "stdbuf", "time", "timeout",
  "sudo", "doas",
  "xargs",
]);
```

Source of truth: extracted from the recursive-unwrap logic currently
in `src/bash-guard.ts` and `src/ast-walk.ts`. Extraction commit
(part of I6 commit 1) moves the set into predicates and re-imports in
both call sites.

Test: `test/composition.test.ts` asserts the predicate set equals
the prior inline set byte-for-byte.

### I8 — Operator parity

`test/z3-proofs/extract.ts` imports `PIPE_OPERATORS` and
`RESET_OPERATORS` from `src/predicates/composition.ts`. The predicate
module in turn exports the exact set that `src/ast-walk.ts` recognizes
as an operator token.

New consistency test `test/ast-walk.test.ts` (or extend existing):

```ts
test("operator predicates cover every operator ast-walk produces", () => {
  const produced = collectAllOperatorsFromCorpus();
  const covered = new Set([...PIPE_OPERATORS, ...RESET_OPERATORS]);
  for (const op of produced) assert(covered.has(op));
});
```

`collectAllOperatorsFromCorpus` runs `ast-walk.ts` over a fixture
corpus and accumulates every `op` field it emits. Corpus seeded from
`test/fixtures/bash-samples.txt` (existing) and the G4 golden corpus.

If a new operator is added to `ast-walk.ts` without updating
predicates, the test fails.

### I9 — Wall-time enforcement

Parent spec allows a nightly split if Z3 runs exceed 60s. Change:

- CI runs full suite as required on every PR. No nightly split.
- If a proof exceeds 20s individually, it is split into finite-domain
  shards (e.g. per action-type group) at the test file level, each
  shard <= 20s.
- `scripts/measure-z3.ts` runs in CI and fails if any single shard
  exceeds 30s (50% headroom over 20s target).
- Budget measured on GitHub Actions `ubuntu-latest` as the reference
  environment. Local Darwin runs may vary.

## Source changes (delta to parent spec)

| File | Change |
|------|--------|
| `src/predicates/composition.ts` | Add `COMMAND_WRAPPERS` export. |
| `src/config.ts` | Reject on `allowedPaths` overlap (fail-closed); honor `allowOverlapWarn` opt-in. Validate `pathArgs` schema. |
| `src/classify.ts` | Honor `pathArgs` on custom entries when dispatching to `checkPath`. |
| `data/classify_full/*.json` | Annotate built-in entries with `pathArgs` where applicable (prep commit). |
| `test/fixtures/composition-golden.txt` | New. G4 regression corpus. |
| `test/composition-golden.test.ts` | New. G4 regression gate. |
| `test/ast-walk.test.ts` | New (or extended). Operator parity test. |
| `scripts/measure-z3.ts` | New. Per-shard wall-time enforcement. |
| `scripts/verify-extract.ts` | Remove hardcoded reference set; derive floor from data. |

## Error handling additions

- Config load with overlapping `allowedPaths` and no opt-in key →
  reject config, emit `ask`, write error to stderr with config path.
- `pathArgs` index out of range for a classified command → reject
  entry at load time.
- `ast-walk.ts` emits operator not in predicates → parity test fails
  in CI, not at runtime. Runtime behavior: operator treated as reset
  (safe default).
- Z3 shard exceeding 30s → CI fails with shard name and timing.

## Testing strategy additions

- I1 golden corpus test runs before any Z3 test in CI ordering; a
  G4 regression blocks the faster feedback loop first.
- I3 schema tests include malformed `pathArgs` variants (negative
  out-of-range, duplicates, non-integer, missing).
- I5 enumeration test is parameterized over extracted data; adding a
  new write emitter to `data/classify_full/` auto-covers it.
- I8 parity test runs on every `bun test`, not only Z3 runs.
- I9 measurement runs in CI only (skipped locally to avoid noisy
  timing on dev machines).

## Decisions

- `allowOverlapWarn` deprecation window: **one release**. Introduced
  as soft-mode escape hatch in release N; removed in release N+1.
  Release notes for N must flag the upcoming removal.
- Golden corpus seed size: **100 entries**. Seed from the I1 starter
  set plus mining of CI logs, `data/classify_full/` example strings,
  and common dev-workflow incantations (`git`, `npm`, `make`,
  `docker`, `kubectl`, `terraform` multi-stage commands). Grow
  further on regression reports.
- Parity test corpus: **merge** `test/fixtures/bash-samples.txt` with
  example strings extracted from `data/classify_full/`, deduplicated
  by exact string match. Merge happens at test-setup time; not
  committed as a derived file.
