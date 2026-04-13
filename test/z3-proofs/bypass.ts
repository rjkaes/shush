import { getZ3, D, stricter, validDecision, report } from "../z3-helpers";

/**
 * Z3 bypass proofs for PathGuard invariants.
 *
 * Models the PathGuard decision pipeline as nested if-then-else over
 * symbolic path categories and tool types, then proves five invariants
 * by showing their negations are unsatisfiable.
 */

async function main() {
  const { Context } = await getZ3();

  // -- Shared constants --------------------------------------------------
  // Path categories (symbolic enum)
  const P_HOOK = 0;
  const P_SENS_BLOCK = 1;
  const P_SENS_ASK = 2;
  const P_OUTSIDE = 3; // outside project boundary
  const P_NORMAL = 4;

  // Tool categories
  const T_WRITE = 0; // Write, Edit, MultiEdit, NotebookEdit
  const T_READ = 1;
  const T_SEARCH = 2; // Glob, Grep

  // Decision values from D
  const ALLOW = D.allow; // 0
  const CONTEXT = D.context;
  const ASK = D.ask; // 2
  const BLOCK = D.block; // 3

  // =====================================================================
  // Helper: build the PathGuard pipeline as a Z3 expression.
  //
  // Pipeline priority order (from src/path-guard.ts):
  //   1. Hook path: write -> Block, read/search -> Allow
  //   2. Sensitive-block: -> Block
  //   3. Sensitive-ask: -> Ask
  //   4. Outside project boundary: write -> Ask, read/search -> Allow
  //   5. Content scan: dangerous content + write -> Ask
  //   6. Default: Allow
  // =====================================================================
  function buildPipeline(ctx: any, pathCat: any, toolCat: any, hasDangerousContent: any) {
    const { Int, If, And } = ctx;
    const isWrite = toolCat.eq(T_WRITE);

    // Build from bottom up (default first, then wrap in if-then-else)
    const defaultDecision = Int.val(ALLOW);

    // 5. Content scan
    const afterContentScan = If(
      And(hasDangerousContent, isWrite),
      Int.val(ASK),
      defaultDecision,
    );

    // 4. Project boundary
    const afterBoundary = If(
      pathCat.eq(P_OUTSIDE),
      If(isWrite, Int.val(ASK), afterContentScan),
      afterContentScan,
    );

    // 3. Sensitive-ask
    const afterSensAsk = If(pathCat.eq(P_SENS_ASK), Int.val(ASK), afterBoundary);

    // 2. Sensitive-block
    const afterSensBlock = If(pathCat.eq(P_SENS_BLOCK), Int.val(BLOCK), afterSensAsk);

    // 1. Hook path
    const pipeline = If(
      pathCat.eq(P_HOOK),
      If(isWrite, Int.val(BLOCK), Int.val(ALLOW)),
      afterSensBlock,
    );

    return pipeline;
  }

  // =====================================================================
  // B1: sensitive-block path + any tool -> decision != Allow
  // =====================================================================
  {
    const ctx = new Context("B1");
    const { Solver, Int, Bool } = ctx;
    const solver = new Solver();

    const pathCat = Int.const("pathCat");
    const toolCat = Int.const("toolCat");
    const dangerousContent = Bool.const("dangerousContent");

    // Constrain inputs to valid ranges
    solver.add(pathCat.ge(P_HOOK), pathCat.le(P_NORMAL));
    solver.add(toolCat.ge(T_WRITE), toolCat.le(T_SEARCH));

    // Fix path to sensitive-block
    solver.add(pathCat.eq(P_SENS_BLOCK));

    const decision = buildPipeline(ctx, pathCat, toolCat, dangerousContent);

    // Try to find: decision == Allow (negation of invariant)
    solver.add(decision.eq(ALLOW));

    report("B1", await solver.check());
  }

  // =====================================================================
  // B2: sensitive-ask path + write tool -> decision >= Ask
  // =====================================================================
  {
    const ctx = new Context("B2");
    const { Solver, Int, Bool } = ctx;
    const solver = new Solver();

    const pathCat = Int.const("pathCat");
    const toolCat = Int.const("toolCat");
    const dangerousContent = Bool.const("dangerousContent");

    solver.add(pathCat.ge(P_HOOK), pathCat.le(P_NORMAL));
    solver.add(toolCat.ge(T_WRITE), toolCat.le(T_SEARCH));

    // Fix path to sensitive-ask, tool to write
    solver.add(pathCat.eq(P_SENS_ASK));
    solver.add(toolCat.eq(T_WRITE));

    const decision = buildPipeline(ctx, pathCat, toolCat, dangerousContent);

    // Try to find: decision < Ask (negation of invariant)
    solver.add(decision.lt(ASK));

    report("B2", await solver.check());
  }

  // =====================================================================
  // B3: hook path + write tool -> decision == Block
  // =====================================================================
  {
    const ctx = new Context("B3");
    const { Solver, Int, Bool } = ctx;
    const solver = new Solver();

    const pathCat = Int.const("pathCat");
    const toolCat = Int.const("toolCat");
    const dangerousContent = Bool.const("dangerousContent");

    solver.add(pathCat.ge(P_HOOK), pathCat.le(P_NORMAL));
    solver.add(toolCat.ge(T_WRITE), toolCat.le(T_SEARCH));

    // Fix path to hook, tool to write
    solver.add(pathCat.eq(P_HOOK));
    solver.add(toolCat.eq(T_WRITE));

    const decision = buildPipeline(ctx, pathCat, toolCat, dangerousContent);

    // Try to find: decision != Block (negation of invariant)
    solver.add(decision.neq(BLOCK));

    report("B3", await solver.check());
  }

  // =====================================================================
  // B4: config override via stricter() cannot lower sensitive decision
  //     below Ask. stricter(base, override) = max(base, override).
  //     If base >= Ask, then max(base, override) >= Ask for any override.
  // =====================================================================
  {
    const ctx = new Context("B4");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const base = Int.const("base");
    const override = Int.const("override");

    // Both are valid decisions
    solver.add(validDecision(ctx, base));
    solver.add(validDecision(ctx, override));

    // Base is at least Ask (sensitive path produced it)
    solver.add(base.ge(ASK));

    // stricter() = max(base, override)
    const result = stricter(ctx, base, override);

    // Try to find: result < Ask (negation of invariant)
    solver.add(result.lt(ASK));

    report("B4", await solver.check());
  }

  // =====================================================================
  // B5: depth exhaustion (shell unwrap limit hit) -> decision >= Ask
  //
  // When recursive shell unwrapping hits the depth limit, bash-guard
  // returns Ask to prevent bypass via deep nesting. Model: if
  // depthExhausted is true, decision = max(Ask, innerDecision).
  // Prove this is always >= Ask.
  // =====================================================================
  {
    const ctx = new Context("B5");
    const { Solver, Int, Bool } = ctx;
    const solver = new Solver();

    const innerDecision = Int.const("innerDecision");
    const depthExhausted = Bool.const("depthExhausted");

    solver.add(validDecision(ctx, innerDecision));

    // When depth is exhausted, the guard forces at least Ask
    const decision = ctx.If(
      depthExhausted,
      stricter(ctx, Int.val(ASK), innerDecision),
      innerDecision,
    );

    // Constrain to the exhausted case
    solver.add(depthExhausted);

    // Try to find: decision < Ask (negation of invariant)
    solver.add(decision.lt(ASK));

    report("B5", await solver.check());
  }
}

main().then(() => process.exit(0));
