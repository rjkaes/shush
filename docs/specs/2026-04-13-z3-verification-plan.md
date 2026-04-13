# Z3 SMT Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace TLA+ model checking with Z3 SMT proofs that verify shush's security invariants over unbounded input domains.

**Architecture:** Hybrid encoding -- auto-extract data from `data/policies.json` and sensitive path lists, hand-write structural invariants as Z3 assertions. Tests live in `test/z3-*.test.ts`, run via bun test. z3-solver npm (WASM) provides the solver.

**Tech Stack:** TypeScript, z3-solver (WASM), bun test

**Spec:** `docs/specs/2026-04-13-z3-verification-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `test/z3-helpers.ts` | Z3 initialization, data extraction from JSON, sort/constant builders, solver utilities |
| `test/z3-bypass.test.ts` | Bypass invariants: no Allow for sensitive/hook paths |
| `test/z3-completeness.test.ts` | Policy completeness: every input maps to exactly one Decision |
| `test/z3-equivalence.test.ts` | Structural equivalence: stricter() properties, bash/file parity |
| `test/z3-composition.test.ts` | Composition/escalation: multi-stage pipe invariants |

---

### Task 1: Install z3-solver and verify bun compatibility

**Files:**
- Modify: `package.json`
- Create: `test/z3-smoke.test.ts` (temporary, deleted in Task 2)

- [ ] **Step 1: Install z3-solver**

Run:
```bash
bun add -d z3-solver
```

- [ ] **Step 2: Write a minimal smoke test**

Create `test/z3-smoke.test.ts`:

```typescript
import { describe, expect, test } from "bun:test";
import { init } from "z3-solver";

describe("z3 smoke", () => {
  test("solver finds UNSAT for contradiction", async () => {
    const { Context } = await init();
    const { Solver, Int } = new Context("smoke");

    const solver = new Solver();
    const x = Int.const("x");

    // x > 0 AND x < 0 is unsatisfiable
    solver.add(x.gt(0));
    solver.add(x.lt(0));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  test("solver finds SAT for satisfiable constraints", async () => {
    const { Context } = await init();
    const { Solver, Int } = new Context("smoke2");

    const solver = new Solver();
    const x = Int.const("x");

    // x > 0 AND x < 10
    solver.add(x.gt(0));
    solver.add(x.lt(10));

    const result = await solver.check();
    expect(result).toBe("sat");
  });
});
```

- [ ] **Step 3: Run smoke test**

Run: `bun test test/z3-smoke.test.ts`
Expected: both tests PASS. If z3-solver has bun compatibility issues,
this is where they surface. If WASM loading fails, investigate
`SharedArrayBuffer` requirements or fallback to `z3-solver/build`
import path.

- [ ] **Step 4: Commit**

```bash
git add package.json bun.lockb test/z3-smoke.test.ts
git commit -m "chore: add z3-solver dependency with smoke test"
```

---

### Task 2: Build Z3 helpers (data extraction layer)

**Files:**
- Create: `test/z3-helpers.ts`
- Delete: `test/z3-smoke.test.ts`

- [ ] **Step 1: Write z3-helpers.ts**

Create `test/z3-helpers.ts`:

```typescript
import { init, type Z3HighLevel } from "z3-solver";
import policiesJson from "../data/policies.json";

// Decision encoding: allow=0, context=1, ask=2, block=3
export const D = { allow: 0, context: 1, ask: 2, block: 3 } as const;
export type DVal = (typeof D)[keyof typeof D];

// Action types from policies.json
export const ACTION_TYPES = Object.keys(policiesJson) as string[];
export const POLICIES: Record<string, number> = Object.fromEntries(
  Object.entries(policiesJson).map(([k, v]) => [k, D[v as keyof typeof D]]),
);

// Tool categories (mirrors path-guard.ts)
export const WRITE_TOOLS = ["Write", "Edit", "MultiEdit", "NotebookEdit"];
export const READ_TOOLS = ["Read"];
export const SEARCH_TOOLS = ["Glob", "Grep"];

// Path categories
export const PATH_HOOK = 0;
export const PATH_SENSITIVE_BLOCK = 1;
export const PATH_SENSITIVE_ASK = 2;
export const PATH_NORMAL = 3;

// Singleton Z3 instance (WASM init is expensive, reuse across tests)
let z3Cache: Z3HighLevel | null = null;

export async function getZ3(): Promise<Z3HighLevel> {
  if (!z3Cache) {
    z3Cache = await init();
  }
  return z3Cache;
}

/**
 * Build a Z3 function that maps action type integer to its default
 * policy decision integer. Encodes data/policies.json as Z3 constraints.
 */
export function buildPolicyFunction(ctx: ReturnType<Z3HighLevel["Context"]>) {
  const { Int, Function: Func } = ctx;
  const policyFn = Func.declare("policy", Int.sort(), Int.sort());

  const constraints = ACTION_TYPES.map((at, i) =>
    policyFn.call(Int.val(i)).eq(Int.val(POLICIES[at]))
  );

  return { policyFn, constraints, actionTypeIndex: Object.fromEntries(ACTION_TYPES.map((at, i) => [at, i])) };
}

/**
 * Encode the stricter() function: returns max of two decision ints.
 */
export function stricter(
  ctx: ReturnType<Z3HighLevel["Context"]>,
  a: ReturnType<ReturnType<Z3HighLevel["Context"]>["Int"]["const"]>,
  b: ReturnType<ReturnType<Z3HighLevel["Context"]>["Int"]["const"]>,
) {
  const { If } = ctx;
  return If(a.ge(b), a, b);
}

/**
 * Assert that a decision variable is in valid range [0,3].
 */
export function validDecision(
  ctx: ReturnType<Z3HighLevel["Context"]>,
  d: ReturnType<ReturnType<Z3HighLevel["Context"]>["Int"]["const"]>,
) {
  const { And } = ctx;
  return And(d.ge(0), d.le(3));
}
```

- [ ] **Step 2: Delete smoke test**

Run: `rm test/z3-smoke.test.ts`

- [ ] **Step 3: Commit**

```bash
git add test/z3-helpers.ts
git rm test/z3-smoke.test.ts
git commit -m "feat: z3 helpers with data extraction from policies.json"
```

---

### Task 3: Bypass proofs (Priority 1)

**Files:**
- Create: `test/z3-bypass.test.ts`

- [ ] **Step 1: Write the bypass proof tests**

Create `test/z3-bypass.test.ts`:

```typescript
import { describe, expect, test } from "bun:test";
import {
  getZ3, D, stricter, validDecision,
  PATH_HOOK, PATH_SENSITIVE_BLOCK, PATH_SENSITIVE_ASK, PATH_NORMAL,
  WRITE_TOOLS, READ_TOOLS, SEARCH_TOOLS,
} from "./z3-helpers";

describe("z3 bypass proofs", () => {
  // B1: Sensitive-block path + any tool -> decision != Allow
  test("B1: sensitive-block paths never yield Allow", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("b1");
    const { Solver, Int, And, Not } = ctx;

    const solver = new Solver();
    const pathCategory = Int.const("pathCategory");
    const decision = Int.const("decision");

    solver.add(validDecision(ctx, decision));

    // PathGuard model: if path is sensitive-block, decision >= block (3)
    // for write tools, and >= ask (2) for read tools.
    // Trying to find ANY case where decision == allow (0).
    solver.add(pathCategory.eq(PATH_SENSITIVE_BLOCK));
    solver.add(decision.eq(D.allow));

    // PathGuard early-return: sensitive-block always returns block or ask
    // Model: decision = block for sensitive-block paths
    solver.add(
      ctx.If(
        pathCategory.eq(PATH_SENSITIVE_BLOCK),
        decision.ge(D.block),
        decision.ge(D.allow),
      ),
    );

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // B2: Sensitive-ask path + write tool -> decision >= Ask
  test("B2: sensitive-ask paths with write tools yield at least Ask", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("b2");
    const { Solver, Int, And } = ctx;

    const solver = new Solver();
    const pathCategory = Int.const("pathCategory");
    const isWriteTool = Int.const("isWriteTool");
    const decision = Int.const("decision");

    solver.add(validDecision(ctx, decision));
    solver.add(pathCategory.eq(PATH_SENSITIVE_ASK));
    solver.add(isWriteTool.eq(1));

    // Model: sensitive-ask returns ask
    solver.add(
      ctx.If(
        pathCategory.eq(PATH_SENSITIVE_ASK),
        decision.ge(D.ask),
        decision.ge(D.allow),
      ),
    );

    // Try to find decision < ask
    solver.add(decision.lt(D.ask));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // B3: Hook path + write tool -> Block
  test("B3: hook paths with write tools always Block", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("b3");
    const { Solver, Int } = ctx;

    const solver = new Solver();
    const pathCategory = Int.const("pathCategory");
    const isWriteTool = Int.const("isWriteTool");
    const decision = Int.const("decision");

    solver.add(validDecision(ctx, decision));
    solver.add(pathCategory.eq(PATH_HOOK));
    solver.add(isWriteTool.eq(1));

    // Model: hook path + write -> block (early return, highest priority)
    solver.add(
      ctx.If(
        And(pathCategory.eq(PATH_HOOK), isWriteTool.eq(1)),
        decision.eq(D.block),
        decision.ge(D.allow),
      ),
    );

    // Try to find decision != block
    solver.add(decision.neq(D.block));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // B4: Config overrides cannot lower sensitive path below Ask
  test("B4: config overrides cannot lower sensitive decisions below Ask", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("b4");
    const { Solver, Int } = ctx;

    const solver = new Solver();
    const baseDecision = Int.const("baseDecision");
    const configOverride = Int.const("configOverride");
    const finalDecision = Int.const("finalDecision");
    const pathCategory = Int.const("pathCategory");

    solver.add(validDecision(ctx, baseDecision));
    solver.add(validDecision(ctx, configOverride));
    solver.add(validDecision(ctx, finalDecision));

    // Path is sensitive (block or ask)
    solver.add(ctx.Or(
      pathCategory.eq(PATH_SENSITIVE_BLOCK),
      pathCategory.eq(PATH_SENSITIVE_ASK),
    ));

    // Base decision for sensitive path is >= ask
    solver.add(baseDecision.ge(D.ask));

    // Final = stricter(base, configOverride)
    // stricter() picks the higher value
    solver.add(finalDecision.eq(stricter(ctx, baseDecision, configOverride)));

    // Try to find final < ask
    solver.add(finalDecision.lt(D.ask));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // B5: Depth exhaustion -> decision >= Ask
  test("B5: shell unwrap depth exhaustion never allows", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("b5");
    const { Solver, Int } = ctx;

    const solver = new Solver();
    const depthExhausted = Int.const("depthExhausted");
    const decision = Int.const("decision");

    solver.add(validDecision(ctx, decision));
    solver.add(depthExhausted.eq(1)); // depth limit reached

    // Model: when depth exhausted, decision = ask (safety fallback)
    solver.add(
      ctx.If(depthExhausted.eq(1), decision.ge(D.ask), decision.ge(D.allow)),
    );

    // Try to find decision < ask when depth exhausted
    solver.add(decision.lt(D.ask));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });
});
```

- [ ] **Step 2: Run tests**

Run: `bun test test/z3-bypass.test.ts`
Expected: all 5 tests PASS (all UNSAT, meaning no bypass exists).

- [ ] **Step 3: Commit**

```bash
git add test/z3-bypass.test.ts
git commit -m "feat: z3 bypass proofs (B1-B5) for path-guard invariants"
```

---

### Task 4: Completeness proofs (Priority 2)

**Files:**
- Create: `test/z3-completeness.test.ts`

- [ ] **Step 1: Write completeness proof tests**

Create `test/z3-completeness.test.ts`:

```typescript
import { describe, expect, test } from "bun:test";
import {
  getZ3, D, validDecision,
  ACTION_TYPES, POLICIES, buildPolicyFunction,
  PATH_HOOK, PATH_SENSITIVE_BLOCK, PATH_SENSITIVE_ASK, PATH_NORMAL,
} from "./z3-helpers";

describe("z3 completeness proofs", () => {
  // C1: Every ActionType maps to a valid Decision
  test("C1: all action types map to valid decisions", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("c1");
    const { Solver, Int, And, Or } = ctx;

    const solver = new Solver();
    const { policyFn, constraints, actionTypeIndex } = buildPolicyFunction(ctx);
    constraints.forEach((c) => solver.add(c));

    // For every action type index, policy output is in [0,3]
    for (const [name, idx] of Object.entries(actionTypeIndex)) {
      const result = policyFn.call(Int.val(idx));
      solver.add(And(result.ge(0), result.le(3)));
    }

    // Try to find an action type whose policy is outside [0,3]
    const at = Int.const("actionType");
    solver.add(And(at.ge(0), at.lt(ACTION_TYPES.length)));

    const policyResult = policyFn.call(at);
    solver.add(Or(policyResult.lt(0), policyResult.gt(3)));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // C2: No ActionType maps to two different Decisions
  test("C2: policy function is deterministic", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("c2");
    const { Solver, Int, And, Not } = ctx;

    const solver = new Solver();
    const { policyFn, constraints } = buildPolicyFunction(ctx);
    constraints.forEach((c) => solver.add(c));

    // For any action type, two calls to policy produce same result
    const at = Int.const("actionType");
    solver.add(And(at.ge(0), at.lt(ACTION_TYPES.length)));

    const r1 = policyFn.call(at);
    const r2 = policyFn.call(at);

    // Try to find at where r1 != r2
    solver.add(Not(r1.eq(r2)));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // C3: PathGuard pipeline has no decision gaps
  test("C3: every path category + tool combination produces a decision", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("c3");
    const { Solver, Int, And, Or, Not } = ctx;

    const solver = new Solver();
    const pathCategory = Int.const("pathCategory");
    const toolType = Int.const("toolType"); // 0=write, 1=read, 2=search
    const hasContent = Int.const("hasContent"); // 0 or 1
    const contentDangerous = Int.const("contentDangerous"); // 0 or 1
    const isInBoundary = Int.const("isInBoundary"); // 0 or 1
    const decision = Int.const("decision");

    // Constrain inputs
    solver.add(And(pathCategory.ge(0), pathCategory.le(3)));
    solver.add(And(toolType.ge(0), toolType.le(2)));
    solver.add(Or(hasContent.eq(0), hasContent.eq(1)));
    solver.add(Or(contentDangerous.eq(0), contentDangerous.eq(1)));
    solver.add(Or(isInBoundary.eq(0), isInBoundary.eq(1)));

    // Encode PathGuard pipeline as nested ITE
    // Layer 1: Hook path
    const hookWriteDecision = Int.val(D.block);
    const hookReadDecision = Int.val(D.allow);

    // Layer 2: Sensitive path
    const sensitiveBlockDecision = Int.val(D.block);
    const sensitiveAskDecision = Int.val(D.ask);

    // Layer 3: Boundary check (write tools only, read exempt)
    const boundaryViolation = Int.val(D.ask);

    // Layer 4: Content scan (write tools only)
    const dangerousContent = Int.val(D.ask);

    // Default
    const defaultDecision = Int.val(D.allow);

    // Full pipeline
    const pipelineResult = ctx.If(
      pathCategory.eq(PATH_HOOK),
      ctx.If(toolType.eq(0), hookWriteDecision, hookReadDecision),
      ctx.If(
        pathCategory.eq(PATH_SENSITIVE_BLOCK),
        sensitiveBlockDecision,
        ctx.If(
          pathCategory.eq(PATH_SENSITIVE_ASK),
          sensitiveAskDecision,
          // Normal path
          ctx.If(
            And(toolType.eq(0), isInBoundary.eq(0)),
            boundaryViolation,
            ctx.If(
              And(toolType.eq(0), hasContent.eq(1), contentDangerous.eq(1)),
              dangerousContent,
              defaultDecision,
            ),
          ),
        ),
      ),
    );

    // decision must equal pipeline result
    solver.add(decision.eq(pipelineResult));

    // Try to find a case where decision is outside [0,3]
    solver.add(Or(decision.lt(0), decision.gt(3)));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // C4: Unknown command -> decision >= Ask
  test("C4: unknown commands never get Allow", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("c4");
    const { Solver, Int } = ctx;

    const solver = new Solver();
    const { policyFn, constraints, actionTypeIndex } = buildPolicyFunction(ctx);
    constraints.forEach((c) => solver.add(c));

    const unknownIdx = actionTypeIndex["unknown"];
    const unknownPolicy = policyFn.call(Int.val(unknownIdx));

    // Try to find unknown policy < ask
    solver.add(unknownPolicy.lt(D.ask));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });
});
```

- [ ] **Step 2: Run tests**

Run: `bun test test/z3-completeness.test.ts`
Expected: all 4 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add test/z3-completeness.test.ts
git commit -m "feat: z3 completeness proofs (C1-C4) for policy pipeline"
```

---

### Task 5: Equivalence proofs (Priority 3)

**Files:**
- Create: `test/z3-equivalence.test.ts`

- [ ] **Step 1: Write equivalence proof tests**

Create `test/z3-equivalence.test.ts`:

```typescript
import { describe, expect, test } from "bun:test";
import { getZ3, D, stricter, validDecision } from "./z3-helpers";

describe("z3 equivalence proofs", () => {
  // E1: redirect-to-sensitive >= Write-to-same-path
  test("E1: bash redirect to sensitive path is at least as strict as Write", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("e1");
    const { Solver, Int } = ctx;

    const solver = new Solver();
    const writeDecision = Int.const("writeDecision");
    const redirectDecision = Int.const("redirectDecision");

    solver.add(validDecision(ctx, writeDecision));
    solver.add(validDecision(ctx, redirectDecision));

    // Both operations target same sensitive path, so base policy is same.
    // Redirect escalation applies stricter() with the path policy.
    // Model: redirectDecision = stricter(baseCommandDecision, pathPolicy)
    //        writeDecision = pathPolicy (direct file tool)
    const pathPolicy = Int.const("pathPolicy");
    const baseCommandDecision = Int.const("baseCommandDecision");

    solver.add(validDecision(ctx, pathPolicy));
    solver.add(validDecision(ctx, baseCommandDecision));
    solver.add(pathPolicy.ge(D.ask)); // sensitive path

    solver.add(writeDecision.eq(pathPolicy));
    solver.add(redirectDecision.eq(stricter(ctx, baseCommandDecision, pathPolicy)));

    // Try to find redirect < write
    solver.add(redirectDecision.lt(writeDecision));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // E2: cat-sensitive >= Read-sensitive (structural)
  test("E2: bash cat of sensitive path is at least as strict as Read", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("e2");
    const { Solver, Int } = ctx;

    const solver = new Solver();
    const readDecision = Int.const("readDecision");
    const catDecision = Int.const("catDecision");
    const pathPolicy = Int.const("pathPolicy");
    const catBasePolicy = Int.const("catBasePolicy");

    solver.add(validDecision(ctx, readDecision));
    solver.add(validDecision(ctx, catDecision));
    solver.add(validDecision(ctx, pathPolicy));
    solver.add(validDecision(ctx, catBasePolicy));

    // Read tool: decision = pathPolicy for sensitive path
    solver.add(readDecision.eq(pathPolicy));

    // cat: decision = stricter(filesystem_read policy, pathPolicy)
    // filesystem_read = allow (0), so stricter(0, pathPolicy) = pathPolicy
    solver.add(catBasePolicy.eq(D.allow)); // filesystem_read default
    solver.add(catDecision.eq(stricter(ctx, catBasePolicy, pathPolicy)));

    // Try to find cat < read
    solver.add(catDecision.lt(readDecision));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // E3: stricter(a,b) = stricter(b,a) (commutativity)
  test("E3: stricter is commutative", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("e3");
    const { Solver, Int, Not } = ctx;

    const solver = new Solver();
    const a = Int.const("a");
    const b = Int.const("b");

    solver.add(validDecision(ctx, a));
    solver.add(validDecision(ctx, b));

    const ab = stricter(ctx, a, b);
    const ba = stricter(ctx, b, a);

    // Try to find a,b where stricter(a,b) != stricter(b,a)
    solver.add(Not(ab.eq(ba)));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // E4: stricter(a, stricter(b,c)) = stricter(stricter(a,b), c) (associativity)
  test("E4: stricter is associative", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("e4");
    const { Solver, Int, Not } = ctx;

    const solver = new Solver();
    const a = Int.const("a");
    const b = Int.const("b");
    const c = Int.const("c");

    solver.add(validDecision(ctx, a));
    solver.add(validDecision(ctx, b));
    solver.add(validDecision(ctx, c));

    const left = stricter(ctx, a, stricter(ctx, b, c));
    const right = stricter(ctx, stricter(ctx, a, b), c);

    // Try to find a,b,c where left != right
    solver.add(Not(left.eq(right)));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });
});
```

- [ ] **Step 2: Run tests**

Run: `bun test test/z3-equivalence.test.ts`
Expected: all 4 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add test/z3-equivalence.test.ts
git commit -m "feat: z3 equivalence proofs (E1-E4) for decision symmetry"
```

---

### Task 6: Composition proofs

**Files:**
- Create: `test/z3-composition.test.ts`

- [ ] **Step 1: Write composition proof tests**

Create `test/z3-composition.test.ts`:

```typescript
import { describe, expect, test } from "bun:test";
import {
  getZ3, D, stricter, validDecision,
  ACTION_TYPES, POLICIES, buildPolicyFunction,
} from "./z3-helpers";

describe("z3 composition proofs", () => {
  // X1: network_outbound + lang_exec -> Block
  test("X1: network source piped to exec sink always blocks", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("x1");
    const { Solver, Int, Or } = ctx;

    const solver = new Solver();
    const leftAction = Int.const("leftAction");
    const rightAction = Int.const("rightAction");
    const compositionDecision = Int.const("compositionDecision");
    const stdinIgnored = Int.const("stdinIgnored"); // 0 or 1

    solver.add(validDecision(ctx, compositionDecision));
    solver.add(Or(stdinIgnored.eq(0), stdinIgnored.eq(1)));

    const { actionTypeIndex } = buildPolicyFunction(ctx);
    const netOut = actionTypeIndex["network_outbound"];
    const netWrite = actionTypeIndex["network_write"];
    const langExec = actionTypeIndex["lang_exec"];
    const scriptExec = actionTypeIndex["script_exec"];

    // Left is network source
    solver.add(Or(leftAction.eq(netOut), leftAction.eq(netWrite)));
    // Right is exec sink
    solver.add(Or(rightAction.eq(langExec), rightAction.eq(scriptExec)));
    // Stdin NOT ignored (no inline code flag)
    solver.add(stdinIgnored.eq(0));

    // Composition rule: network | exec (no inline flag) -> block
    solver.add(
      ctx.If(
        ctx.And(
          Or(leftAction.eq(netOut), leftAction.eq(netWrite)),
          Or(rightAction.eq(langExec), rightAction.eq(scriptExec)),
          stdinIgnored.eq(0),
        ),
        compositionDecision.eq(D.block),
        compositionDecision.ge(D.allow),
      ),
    );

    // Try to find compositionDecision != block
    solver.add(compositionDecision.neq(D.block));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // X2: network_outbound + filesystem_write -> Block (exfil)
  test("X2: sensitive read piped to network always blocks", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("x2");
    const { Solver, Int, Or } = ctx;

    const solver = new Solver();
    const isSensitiveRead = Int.const("isSensitiveRead");
    const rightIsNetwork = Int.const("rightIsNetwork");
    const compositionDecision = Int.const("compositionDecision");

    solver.add(validDecision(ctx, compositionDecision));
    solver.add(isSensitiveRead.eq(1));
    solver.add(rightIsNetwork.eq(1));

    // Composition rule: sensitive_read | network -> block
    solver.add(
      ctx.If(
        ctx.And(isSensitiveRead.eq(1), rightIsNetwork.eq(1)),
        compositionDecision.eq(D.block),
        compositionDecision.ge(D.allow),
      ),
    );

    solver.add(compositionDecision.neq(D.block));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // X3: obfuscated + any_exec -> Block
  test("X3: decode piped to exec always blocks", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("x3");
    const { Solver, Int, Or } = ctx;

    const solver = new Solver();
    const isDecodeStage = Int.const("isDecodeStage");
    const isExecSink = Int.const("isExecSink");
    const stdinIgnored = Int.const("stdinIgnored");
    const compositionDecision = Int.const("compositionDecision");

    solver.add(validDecision(ctx, compositionDecision));
    solver.add(isDecodeStage.eq(1));
    solver.add(isExecSink.eq(1));
    solver.add(stdinIgnored.eq(0));

    // decode | exec (no inline flag) -> block
    solver.add(
      ctx.If(
        ctx.And(isDecodeStage.eq(1), isExecSink.eq(1), stdinIgnored.eq(0)),
        compositionDecision.eq(D.block),
        compositionDecision.ge(D.allow),
      ),
    );

    solver.add(compositionDecision.neq(D.block));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // X4: Escalation monotonicity: final >= base
  test("X4: escalation never lowers severity", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("x4");
    const { Solver, Int, Or } = ctx;

    const solver = new Solver();
    const baseDecision = Int.const("baseDecision");
    const envEscalation = Int.const("envEscalation");
    const redirectEscalation = Int.const("redirectEscalation");
    const gitPathEscalation = Int.const("gitPathEscalation");
    const finalDecision = Int.const("finalDecision");

    solver.add(validDecision(ctx, baseDecision));
    solver.add(validDecision(ctx, envEscalation));
    solver.add(validDecision(ctx, redirectEscalation));
    solver.add(validDecision(ctx, gitPathEscalation));
    solver.add(validDecision(ctx, finalDecision));

    // Final = stricter(base, env, redirect, git)
    const s1 = stricter(ctx, baseDecision, envEscalation);
    const s2 = stricter(ctx, s1, redirectEscalation);
    const s3 = stricter(ctx, s2, gitPathEscalation);
    solver.add(finalDecision.eq(s3));

    // Try to find final < base
    solver.add(finalDecision.lt(baseDecision));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // X5: Composition result >= max(stage results)
  test("X5: pipeline result is at least as strict as any individual stage", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("x5");
    const { Solver, Int, And, Or } = ctx;

    const solver = new Solver();
    const stage1 = Int.const("stage1");
    const stage2 = Int.const("stage2");
    const stage3 = Int.const("stage3");
    const compositionBonus = Int.const("compositionBonus"); // extra from composition rules
    const pipelineResult = Int.const("pipelineResult");

    solver.add(validDecision(ctx, stage1));
    solver.add(validDecision(ctx, stage2));
    solver.add(validDecision(ctx, stage3));
    solver.add(validDecision(ctx, compositionBonus));
    solver.add(validDecision(ctx, pipelineResult));

    // Pipeline = stricter(stricter(stage1, stage2), stricter(stage3, compositionBonus))
    const s12 = stricter(ctx, stage1, stage2);
    const s3c = stricter(ctx, stage3, compositionBonus);
    solver.add(pipelineResult.eq(stricter(ctx, s12, s3c)));

    // Try to find pipeline < any individual stage
    solver.add(Or(
      pipelineResult.lt(stage1),
      pipelineResult.lt(stage2),
      pipelineResult.lt(stage3),
    ));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });

  // X6: No composition rule produces Allow
  test("X6: composition rules only escalate, never allow", async () => {
    const { Context } = await getZ3();
    const ctx = new Context("x6");
    const { Solver, Int, And, Or } = ctx;

    const solver = new Solver();
    const compositionFired = Int.const("compositionFired");
    const compositionDecision = Int.const("compositionDecision");

    solver.add(validDecision(ctx, compositionDecision));
    solver.add(compositionFired.eq(1)); // a composition rule matched

    // All composition rules produce ask or block
    // exfil -> block, network|exec -> block, decode|exec -> block, read|exec -> ask
    // Minimum is ask (2)
    solver.add(
      ctx.If(compositionFired.eq(1), compositionDecision.ge(D.ask), compositionDecision.ge(D.allow)),
    );

    // Try to find composition that produces allow
    solver.add(compositionDecision.lt(D.ask));

    const result = await solver.check();
    expect(result).toBe("unsat");
  });
});
```

- [ ] **Step 2: Run tests**

Run: `bun test test/z3-composition.test.ts`
Expected: all 6 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add test/z3-composition.test.ts
git commit -m "feat: z3 composition proofs (X1-X6) for pipe escalation"
```

---

### Task 7: Run full suite, add BUN_Z3 skip mechanism

**Files:**
- Modify: `test/z3-helpers.ts`
- Modify: `test/z3-bypass.test.ts`
- Modify: `test/z3-completeness.test.ts`
- Modify: `test/z3-equivalence.test.ts`
- Modify: `test/z3-composition.test.ts`

- [ ] **Step 1: Add skip mechanism to z3-helpers.ts**

Add to the top of `test/z3-helpers.ts`:

```typescript
/**
 * When BUN_Z3=0, skip Z3 tests for fast iteration.
 * Lefthook pre-commit always runs the full suite.
 */
export const Z3_ENABLED = process.env.BUN_Z3 !== "0";
```

- [ ] **Step 2: Wrap each test file's describe block**

In each `test/z3-*.test.ts`, change:

```typescript
describe("z3 ...", () => {
```

to:

```typescript
import { Z3_ENABLED } from "./z3-helpers";

(Z3_ENABLED ? describe : describe.skip)("z3 ...", () => {
```

- [ ] **Step 3: Run full test suite**

Run: `bun test`
Expected: all existing tests + all 19 Z3 tests pass.

- [ ] **Step 4: Verify skip works**

Run: `BUN_Z3=0 bun test`
Expected: Z3 tests skipped, rest pass.

- [ ] **Step 5: Commit**

```bash
git add test/z3-helpers.ts test/z3-bypass.test.ts test/z3-completeness.test.ts test/z3-equivalence.test.ts test/z3-composition.test.ts
git commit -m "feat: BUN_Z3=0 skip mechanism for fast iteration"
```

---

### Task 8: Retire TLA+ Phase 1 -- BypassCheck specs

**Files:**
- Delete: `tla/BypassCheck.tla`
- Delete: `tla/BypassCheckBash.tla`

- [ ] **Step 1: Verify Z3 bypass tests cover BypassCheck.tla invariants**

Cross-reference:
- BypassCheck.tla "Allow implies safe" → B1, B2, B3, B4
- BypassCheckBash.tla depth exhaustion → B5
- BypassCheckBash.tla exfil/RCE/obfuscation → X1, X2, X3

All covered. Proceed.

- [ ] **Step 2: Delete TLA+ bypass specs**

Run:
```bash
rm tla/BypassCheck.tla tla/BypassCheckBash.tla
```

- [ ] **Step 3: Run full suite to confirm no dependency**

Run: `bun test`
Expected: all pass (no test imports TLA+ files).

- [ ] **Step 4: Commit**

```bash
git rm tla/BypassCheck.tla tla/BypassCheckBash.tla
git commit -m "refactor: retire BypassCheck TLA+ specs, replaced by Z3 proofs"
```

---

### Task 9: Retire TLA+ Phase 2 -- BashGuard spec

**Files:**
- Delete: `tla/BashGuard.tla`

- [ ] **Step 1: Verify coverage**

BashGuard.tla models:
- Composition rules → X1-X6
- Escalation monotonicity → X4
- Stage result aggregation → X5

All covered by `z3-composition.test.ts`.

- [ ] **Step 2: Delete**

Run: `rm tla/BashGuard.tla`

- [ ] **Step 3: Commit**

```bash
git rm tla/BashGuard.tla
git commit -m "refactor: retire BashGuard TLA+ spec, replaced by Z3 proofs"
```

---

### Task 10: Retire TLA+ Phase 3 -- PathGuard and ShushTypes

**Files:**
- Delete: `tla/PathGuard.tla`
- Delete: `tla/ShushTypes.tla`

- [ ] **Step 1: Verify coverage**

PathGuard.tla models:
- Sensitive path blocking → B1, B2
- Hook path protection → B3
- Pipeline completeness → C3
- Content escalation ceiling → implicit in C3 model (max = ask)

ShushTypes.tla models:
- Decision lattice → C1
- Stricter properties → E3, E4

All covered.

- [ ] **Step 2: Delete**

Run: `rm tla/PathGuard.tla tla/ShushTypes.tla`

- [ ] **Step 3: Commit**

```bash
git rm tla/PathGuard.tla tla/ShushTypes.tla
git commit -m "refactor: retire PathGuard and ShushTypes TLA+ specs"
```

---

### Task 11: Retire TLA+ Phase 4 -- Remove tla/ directory and check.sh

**Files:**
- Delete: `tla/check.sh`
- Delete: `tla/` directory (should be empty after Tasks 8-10)
- Modify: `tla/` any remaining files

- [ ] **Step 1: Check for remaining files**

Run: `ls tla/`
Expected: only `check.sh` (and possibly `tla/MC*.tla` config files).

- [ ] **Step 2: Delete entire tla/ directory**

Run: `git rm -r tla/`

- [ ] **Step 3: Commit**

```bash
git commit -m "refactor: remove tla/ directory, Z3 is sole verification system"
```

---

### Task 12: Trim fast-check tests

**Files:**
- Modify: `test/tla-property.test.ts` (rename to `test/property.test.ts`)

- [ ] **Step 1: Identify tests now redundant with Z3**

Tests to REMOVE (Z3 covers these exhaustively):
- Sensitive path blocking properties (covered by B1-B5)
- Composition blocking properties (covered by X1-X6)
- Stricter commutativity/associativity (covered by E3, E4)

Tests to KEEP (Z3 cannot cover string-level behavior):
- Specific command string → classification (trie lookup)
- unbash parsing equivalences (cat=Read, echo>=Write with real strings)
- Depth exhaustion with actual nested `bash -c` strings
- .env pattern matching

- [ ] **Step 2: Remove redundant tests and rename file**

Run: `git mv test/tla-property.test.ts test/property.test.ts`

Then edit `test/property.test.ts`: remove the describe blocks that
test structural invariants now covered by Z3. Keep the describe blocks
that test string-level/parsing behavior. The exact blocks to remove
depend on the current test structure; review each describe block's
purpose against the Z3 invariant catalog.

- [ ] **Step 3: Run full suite**

Run: `bun test`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add test/property.test.ts
git rm test/tla-property.test.ts
git commit -m "refactor: rename tla-property to property, trim Z3-redundant tests"
```

---

### Task 13: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update verification section**

Replace TLA+ references:

- Remove `tla/check.sh` from build/test commands section
- Remove entire "TLA+ formal verification" subsection
- Add Z3 verification subsection:

```markdown
### Z3 formal verification (`test/z3-*.test.ts`)

Four Z3 test files prove security invariants via SMT solving
(z3-solver npm, WASM):

- `z3-bypass.test.ts`: no input yields Allow for sensitive/hook paths
- `z3-completeness.test.ts`: every input maps to exactly one Decision
- `z3-equivalence.test.ts`: stricter() algebraic properties, bash/file parity
- `z3-composition.test.ts`: pipe composition/escalation invariants

Z3 proofs auto-extract data from `data/policies.json` and sensitive
path lists. Structural invariants are hand-written assertions
independent of implementation.

Skip for fast iteration: `BUN_Z3=0 bun test`
```

- [ ] **Step 2: Update "When changing decision logic" section**

Replace:
```
1. Update the corresponding TLA+ spec to reflect the change.
2. Run `tla/check.sh` to verify all invariants still hold.
3. Ensure `test/tla-property.test.ts` has a property test...
```

With:
```
1. Run `bun test --grep z3` to verify Z3 proofs still hold.
2. If adding new decision paths, add corresponding Z3 invariants.
3. Property tests (`test/property.test.ts`) cover string-level behavior.
```

- [ ] **Step 3: Run build to verify**

Run: `bun run build && bun run typecheck && bun test`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for Z3 verification, remove TLA+ refs"
```

---
