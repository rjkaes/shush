# Z3 SMT Verification for shush

**Date:** 2026-04-13
**Status:** Draft
**Branch:** `feat/z3-verification`

## Summary

Replace TLA+ model checking with Z3 SMT proofs via the `z3-solver` npm
package. Z3 provides exhaustive verification over unbounded input domains,
runs in the same language (TypeScript) and test runner (bun test), and
eliminates the Java dependency.

## Goals (prioritized)

1. **Bypass proof**: prove no input combination yields Allow for
   sensitive/hook paths
2. **Policy completeness**: prove every reachable input maps to exactly
   one Decision with no gaps
3. **Bash/file equivalence**: prove structural equivalence between Bash
   tool decisions and file tool decisions for equivalent operations

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Relationship to TLA+ | Clean replacement | shush uses no temporal logic; Z3 covers all TLA+ invariants plus unbounded domains |
| Test location | `test/z3-*.test.ts` | Same runner, same CI, no separate toolchain |
| fast-check role | Smoke tests (always run) | Z3 = pre-commit gate; fast-check = fast regression on string-level parsing behavior |
| Encoding strategy | Hybrid | Auto-extract data (policies, classifications, paths) from JSON; hand-write structural invariants |
| Package | `z3-solver` npm (WASM) | Cross-platform, no native deps, full Z3 API |

## Architecture

### Data extraction layer (`test/z3-helpers.ts`)

Auto-imports real project data at test time:

```
data/policies.json       -> Z3 EnumSort(ActionType) + Function(ActionType -> Decision)
data/classify_full/*.json -> Z3 Array(CommandPrefix -> ActionType)
src/path-guard.ts         -> Z3 Set(String) for sensitive paths
```

This eliminates data drift: if policies.json changes, Z3 proofs
automatically run against the new data on next commit.

### Hand-written invariants

Structural properties of the decision pipeline, written as Z3
assertions independent of implementation. These are the specification:
they describe what _should_ be true, not what the code _does_.

### Decision pipeline encoding (PathGuard)

Modeled as nested if-then-else mirroring early-return semantics:

```
if isHookPath(path) AND isWriteTool(tool) -> Block
elif isHookPath(path) AND isReadTool(tool) -> Allow
elif isSensitive(path) -> sensitivePolicy(path)
elif isOutsideBoundary(path) AND NOT isReadTool(tool) -> Ask
elif hasContent AND isDangerous(content) -> Ask
else -> Allow
```

Each branch guards all subsequent branches, preserving early-return
precedence.

### Bash classification encoding

Z3 operates post-parse (after `unbash` produces `Stage[]`). This is
the clean boundary: Z3 proves algebraic properties of classified
stages; fast-check covers string-level parsing and trie lookup.

**What Z3 proves:**
- Composition rules (multi-stage patterns always produce correct result)
- Escalation monotonicity (escalation never lowers severity)
- Stricter-wins (pipeline result >= max of individual stages)
- Depth exhaustion safety (never produces Allow)
- Redirect-to-sensitive equivalence with Write-to-sensitive

**What fast-check keeps:**
- unbash parsing correctness
- Command string -> ActionType classification (trie lookup)
- Concrete Bash/file equivalence (needs actual parsing)

### Stricter composition

```
stricter(a, b) = If(a > b, a, b)
stricterAll(decisions[]) = fold(stricter, Allow)
```

## Invariant catalog

### Bypass proofs (`test/z3-bypass.test.ts`)

| ID | Invariant | Origin |
|----|-----------|--------|
| B1 | Sensitive-block path + any tool -> decision != Allow | PathGuard.tla |
| B2 | Sensitive-ask path + write tool -> decision >= Ask | PathGuard.tla |
| B3 | Hook path + write tool -> Block | PathGuard.tla |
| B4 | For all config overrides: sensitive path never drops below Ask | BypassCheck.tla |
| B5 | Depth exhaustion -> decision >= Ask | BypassCheckBash.tla |

### Completeness proofs (`test/z3-completeness.test.ts`)

| ID | Invariant | Origin |
|----|-----------|--------|
| C1 | Every ActionType in policies.json maps to valid Decision | ShushTypes.tla |
| C2 | No ActionType maps to two different Decisions | New |
| C3 | PathGuard pipeline: every branch terminates with a Decision | PathGuard.tla |
| C4 | Unknown command -> decision >= Ask | New |

### Equivalence proofs (`test/z3-equivalence.test.ts`)

| ID | Invariant | Origin |
|----|-----------|--------|
| E1 | redirect-to-sensitive >= Write-to-same-path | BypassCheckBash.tla |
| E2 | cat-sensitive >= Read-sensitive (structural) | BypassCheckBash.tla |
| E3 | stricter(a,b) = stricter(b,a) (commutativity) | ShushTypes.tla |
| E4 | stricter(a, stricter(b,c)) = stricter(stricter(a,b), c) | ShushTypes.tla |

### Composition proofs (`test/z3-composition.test.ts`)

| ID | Invariant | Origin |
|----|-----------|--------|
| X1 | network_outbound + lang_exec -> Block | BashGuard.tla |
| X2 | network_outbound + filesystem_write -> Block (exfil) | BashGuard.tla |
| X3 | obfuscated + any_exec -> Block | BashGuard.tla |
| X4 | Escalation monotonicity: final >= base | BashGuard.tla |
| X5 | Composition result >= max(stage results) | BashGuard.tla |
| X6 | No composition rule produces Allow | New |

**Total: 17 invariants** covering all TLA+ invariants plus 3 new ones.

## Test files

```
test/
  z3-bypass.test.ts        # Priority 1: no bypass exists
  z3-completeness.test.ts  # Priority 2: no decision gaps
  z3-equivalence.test.ts   # Priority 3: bash=file structural
  z3-composition.test.ts   # Bash composition/escalation
  z3-helpers.ts            # Data extraction, Z3 context builder
  tla-property.test.ts     # Retained: fast-check smoke tests
```

### Run behavior

- `bun test` runs everything including Z3 proofs
- `bun test --grep z3` runs only Z3 proofs
- `BUN_Z3=0 bun test` skips Z3 for fast iteration
- Lefthook pre-commit always runs full suite

## TLA+ retirement plan

Phased deletion, each phase atomic:

1. Write Z3 bypass proofs, verify same coverage as BypassCheck.tla
   and BypassCheckBash.tla, delete both TLA+ specs
2. Write Z3 composition/escalation proofs, verify against
   BashGuard.tla, delete it
3. Write Z3 path-guard proofs, verify against PathGuard.tla,
   delete it and ShushTypes.tla
4. Delete `tla/` directory and `tla/check.sh`
5. Trim fast-check tests to parsing/string smoke only, rename
   `tla-property.test.ts` to `property.test.ts`

Each phase: Z3 test passes, TLA+ spec deleted, single commit.

## CLAUDE.md updates

After TLA+ retirement:
- Replace TLA+ verification instructions with Z3 test references
- Remove `tla/check.sh` references
- Update "Security invariant" section to reference Z3 proofs
- Update "When changing decision logic" to say "ensure Z3 proofs pass"

## Dependencies

```json
{
  "devDependencies": {
    "z3-solver": "^4.x"
  }
}
```

WASM-based, ~30MB. No native dependencies, no Java requirement.
Cross-platform (macOS, Linux, Windows).

## Risks

- **WASM Z3 speed**: 2-5x slower than native. Mitigated by
  `BUN_Z3=0` skip for iteration, full run in pre-commit.
- **z3-solver API churn**: WASM bindings less stable than Python.
  Mitigated by pinning version, wrapping in helpers.
- **bun compatibility**: z3-solver targets Node. May need
  compatibility shims. Test early in Phase 1.
- **Encoding fidelity**: hand-written invariants could miss edge
  cases in the real pipeline. Mitigated by keeping fast-check as
  complementary smoke tests.
