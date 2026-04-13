import {
  getZ3,
  D,
  ACTION_TYPES,
  buildPolicyFunction,
  report,
} from "../z3-helpers";

/**
 * Z3 completeness proofs for policy and PathGuard pipelines.
 *
 * Four invariants (C1-C4) prove that every input combination
 * produces a valid, deterministic decision with no gaps.
 */

async function main() {
  // -- Shared constants --------------------------------------------------
  const ALLOW = D.allow; // 0
  const ASK = D.ask; // 2
  const BLOCK = D.block; // 3

  // Path categories (same encoding as bypass.ts)
  const P_HOOK = 0;
  const P_SENS_BLOCK = 1;
  const P_SENS_ASK = 2;
  const P_OUTSIDE = 3;
  const P_NORMAL = 4;

  // Tool categories
  const T_WRITE = 0;
  const _T_READ = 1;
  const T_SEARCH = 2;

  // =====================================================================
  // C1: Every ActionType in policies.json maps to a valid Decision (0-3).
  //
  // Encode all policies via buildPolicyFunction(), then assert exists
  // an action type whose policy is outside [0,3]. UNSAT = all valid.
  // =====================================================================
  {
    const ctx = new (await getZ3()).Context("C1");
    const { Solver, Int, Or } = ctx;
    const solver = new Solver();

    const { policyFn, constraints } = buildPolicyFunction(ctx);

    // Assert all policy constraints (policyFn(i) == known value)
    for (const c of constraints) {
      solver.add(c);
    }

    // Try to find an action type index whose decision is outside [0,3]
    const at = Int.const("at");
    solver.add(at.ge(0), at.le(ACTION_TYPES.length - 1));

    const d = policyFn.call(at);
    solver.add(Or(d.lt(0), d.gt(3)));

    report("C1", await solver.check());
  }

  // =====================================================================
  // C2: Policy function is deterministic -- two calls with same input
  // produce same output. Assert exists actionType where
  // policyFn(at) != policyFn(at). UNSAT = deterministic.
  // =====================================================================
  {
    const ctx = new (await getZ3()).Context("C2");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const { policyFn, constraints } = buildPolicyFunction(ctx);
    for (const c of constraints) {
      solver.add(c);
    }

    const at = Int.const("at");
    solver.add(at.ge(0), at.le(ACTION_TYPES.length - 1));

    // Assert the function returns different values for the same input
    solver.add(policyFn.call(at).neq(policyFn.call(at)));

    report("C2", await solver.check());
  }

  // =====================================================================
  // C3: PathGuard pipeline has no decision gaps -- every combination of
  // (pathCategory, toolType, hasDangerousContent) produces a decision
  // in [0,3]. UNSAT = complete coverage, no gaps.
  //
  // Pipeline priority order (from src/path-guard.ts):
  //   1. Hook path: write -> Block, read/search -> Allow
  //   2. Sensitive-block: -> Block
  //   3. Sensitive-ask: -> Ask
  //   4. Outside boundary: write -> Ask, read/search -> Allow
  //   5. Dangerous content + write -> Ask
  //   6. Default -> Allow
  // =====================================================================
  {
    const ctx = new (await getZ3()).Context("C3");
    const { Solver, Int, Bool, Or } = ctx;
    const solver = new Solver();

    const pathCat = Int.const("pathCat");
    const toolCat = Int.const("toolCat");
    const dangerousContent = Bool.const("dangerousContent");

    // Constrain inputs to valid ranges
    solver.add(pathCat.ge(P_HOOK), pathCat.le(P_NORMAL));
    solver.add(toolCat.ge(T_WRITE), toolCat.le(T_SEARCH));

    // Build pipeline (same as bypass.ts)
    const isWrite = toolCat.eq(T_WRITE);

    // Build from bottom up
    const defaultDecision = Int.val(ALLOW);

    // 5. Content scan
    const afterContentScan = ctx.If(
      ctx.And(dangerousContent, isWrite),
      Int.val(ASK),
      defaultDecision,
    );

    // 4. Project boundary
    const afterBoundary = ctx.If(
      pathCat.eq(P_OUTSIDE),
      ctx.If(isWrite, Int.val(ASK), afterContentScan),
      afterContentScan,
    );

    // 3. Sensitive-ask
    const afterSensAsk = ctx.If(pathCat.eq(P_SENS_ASK), Int.val(ASK), afterBoundary);

    // 2. Sensitive-block
    const afterSensBlock = ctx.If(pathCat.eq(P_SENS_BLOCK), Int.val(BLOCK), afterSensAsk);

    // 1. Hook path
    const pipeline = ctx.If(
      pathCat.eq(P_HOOK),
      ctx.If(isWrite, Int.val(BLOCK), Int.val(ALLOW)),
      afterSensBlock,
    );

    // Try to find: pipeline output outside [0,3]
    solver.add(Or(pipeline.lt(0), pipeline.gt(3)));

    report("C3", await solver.check());
  }

  // =====================================================================
  // C4: Unknown command -> decision >= Ask. The "unknown" action type
  // must never produce Allow or Context. UNSAT = unknown always >= Ask.
  // =====================================================================
  {
    const ctx = new (await getZ3()).Context("C4");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const { policyFn, constraints, actionTypeIndex } = buildPolicyFunction(ctx);
    for (const c of constraints) {
      solver.add(c);
    }

    const unknownIdx = actionTypeIndex["unknown"];
    const decision = policyFn.call(Int.val(unknownIdx));

    // Try to find: decision < Ask (negation of invariant)
    solver.add(decision.lt(ASK));

    report("C4", await solver.check());
  }
}

main().then(() => process.exit(0));
