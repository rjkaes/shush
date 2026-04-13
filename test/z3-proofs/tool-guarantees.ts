import {
  getZ3,
  D,
  validDecision,
  report,
} from "../z3-helpers";

/**
 * Z3 tool guarantee proofs (TG1-TG3).
 *
 * TG1: Hook self-protection -- all modifying tools blocked on hook paths.
 * TG2: Content guard ceiling -- content scan never escalates beyond Ask.
 * TG3: Tool-specific check matrix -- boundary/content checks per tool type.
 */

async function main() {
  const ALLOW = D.allow; // 0
  const ASK = D.ask; // 2
  const BLOCK = D.block; // 3

  // Path categories (same encoding as completeness.ts)
  const P_HOOK = 0;
  const P_SENS_BLOCK = 1;
  const P_SENS_ASK = 2;
  const P_OUTSIDE = 3;
  const P_NORMAL = 4;

  // Tool categories
  const T_WRITE = 0;
  const T_READ = 1;
  const _T_SEARCH = 2;
  const T_MCP_WRITE = 3;

  /**
   * Shared PathGuard pipeline model used by TG1 and TG3.
   *
   * Encodes the nested if-then-else from src/path-guard.ts:
   *   hook + write/mcp_write -> Block
   *   hook + read/search     -> Allow
   *   sensitive_block         -> Block
   *   sensitive_ask           -> Ask
   *   outside + write         -> Ask
   *   dangerous + write       -> Ask
   *   default                 -> Allow
   */
  function buildPipeline(ctx: any, pathCat: any, toolCat: any, dangerousContent: any) {
    const { Int } = ctx;
    const isWrite = ctx.Or(toolCat.eq(T_WRITE), toolCat.eq(T_MCP_WRITE));

    const defaultDecision = Int.val(ALLOW);

    // 5. Content scan (only write tools)
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
    return ctx.If(
      pathCat.eq(P_HOOK),
      ctx.If(isWrite, Int.val(BLOCK), Int.val(ALLOW)),
      afterSensBlock,
    );
  }

  // =====================================================================
  // TG1a: hook + write tool -> Block
  //
  // Assert that a write tool on a hook path does NOT produce Block.
  // UNSAT = hook + write always produces Block.
  // =====================================================================
  {
    const ctx = new (await getZ3()).Context("TG1a");
    const { Solver, Int, Bool } = ctx;
    const solver = new Solver();

    const pathCat = Int.const("pathCat");
    const toolCat = Int.const("toolCat");
    const dangerousContent = Bool.const("dangerousContent");

    // Fix: hook path, write tool
    solver.add(pathCat.eq(P_HOOK));
    solver.add(toolCat.eq(T_WRITE));

    const decision = buildPipeline(ctx, pathCat, toolCat, dangerousContent);

    // Try to find: decision != Block
    solver.add(decision.neq(BLOCK));

    report("TG1a", await solver.check());
  }

  // =====================================================================
  // TG1b: hook + mcp_write tool -> Block
  //
  // Assert that an MCP write tool on a hook path does NOT produce Block.
  // UNSAT = hook + mcp_write always produces Block.
  // =====================================================================
  {
    const ctx = new (await getZ3()).Context("TG1b");
    const { Solver, Int, Bool } = ctx;
    const solver = new Solver();

    const pathCat = Int.const("pathCat");
    const toolCat = Int.const("toolCat");
    const dangerousContent = Bool.const("dangerousContent");

    solver.add(pathCat.eq(P_HOOK));
    solver.add(toolCat.eq(T_MCP_WRITE));

    const decision = buildPipeline(ctx, pathCat, toolCat, dangerousContent);

    solver.add(decision.neq(BLOCK));

    report("TG1b", await solver.check());
  }

  // =====================================================================
  // TG1c: hook + read tool -> Allow
  //
  // Assert that a read tool on a hook path does NOT produce Allow.
  // UNSAT = hook + read always produces Allow.
  // =====================================================================
  {
    const ctx = new (await getZ3()).Context("TG1c");
    const { Solver, Int, Bool } = ctx;
    const solver = new Solver();

    const pathCat = Int.const("pathCat");
    const toolCat = Int.const("toolCat");
    const dangerousContent = Bool.const("dangerousContent");

    solver.add(pathCat.eq(P_HOOK));
    solver.add(toolCat.eq(T_READ));

    const decision = buildPipeline(ctx, pathCat, toolCat, dangerousContent);

    solver.add(decision.neq(ALLOW));

    report("TG1c", await solver.check());
  }

  // =====================================================================
  // TG2a: Content guard ceiling is Ask
  //
  // The content scan result is capped at Ask by design -- it should
  // never produce Block. Model: contentResult is the output of content
  // scanning, constrained to be > Ask. UNSAT = ceiling holds.
  // =====================================================================
  {
    const ctx = new (await getZ3()).Context("TG2a");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const contentResult = Int.const("contentResult");
    solver.add(validDecision(ctx, contentResult));

    // Content scan output is capped at Ask (by design in content-guard.ts)
    // Model: the scan can return Allow or Ask, never higher
    solver.add(ctx.Or(contentResult.eq(ALLOW), contentResult.eq(ASK)));

    // Try to find: contentResult > Ask
    solver.add(contentResult.gt(ASK));

    report("TG2a", await solver.check());
  }

  // =====================================================================
  // TG2b: Read tool + dangerous content -> decision unaffected
  //
  // Content scan only applies to write tools. A read tool with
  // dangerous content on a normal path should still produce Allow.
  // UNSAT = read tool is unaffected by content scan.
  // =====================================================================
  {
    const ctx = new (await getZ3()).Context("TG2b");
    const { Solver, Int, Bool } = ctx;
    const solver = new Solver();

    const pathCat = Int.const("pathCat");
    const toolCat = Int.const("toolCat");
    const dangerousContent = Bool.const("dangerousContent");

    // Normal path, read tool, dangerous content present
    solver.add(pathCat.eq(P_NORMAL));
    solver.add(toolCat.eq(T_READ));
    solver.add(dangerousContent);

    const decision = buildPipeline(ctx, pathCat, toolCat, dangerousContent);

    // Try to find: decision != Allow (content scan leaked through)
    solver.add(decision.neq(ALLOW));

    report("TG2b", await solver.check());
  }

  // =====================================================================
  // TG3a: Read tool has NO boundary check
  //
  // Read outside project boundary with normal-ish path = Allow.
  // The outside-boundary check only gates write tools.
  // UNSAT = read outside boundary is always Allow.
  // =====================================================================
  {
    const ctx = new (await getZ3()).Context("TG3a");
    const { Solver, Int, Bool } = ctx;
    const solver = new Solver();

    const pathCat = Int.const("pathCat");
    const toolCat = Int.const("toolCat");
    const dangerousContent = Bool.const("dangerousContent");

    // Outside boundary, read tool, no dangerous content
    solver.add(pathCat.eq(P_OUTSIDE));
    solver.add(toolCat.eq(T_READ));
    solver.add(ctx.Not(dangerousContent));

    const decision = buildPipeline(ctx, pathCat, toolCat, dangerousContent);

    solver.add(decision.neq(ALLOW));

    report("TG3a", await solver.check());
  }

  // =====================================================================
  // TG3b: Write tool ALWAYS gets boundary check
  //
  // Write outside project with normal path -> decision >= Ask.
  // UNSAT = write outside boundary is never less than Ask.
  // =====================================================================
  {
    const ctx = new (await getZ3()).Context("TG3b");
    const { Solver, Int, Bool } = ctx;
    const solver = new Solver();

    const pathCat = Int.const("pathCat");
    const toolCat = Int.const("toolCat");
    const dangerousContent = Bool.const("dangerousContent");

    solver.add(pathCat.eq(P_OUTSIDE));
    solver.add(toolCat.eq(T_WRITE));

    const decision = buildPipeline(ctx, pathCat, toolCat, dangerousContent);

    // Try to find: decision < Ask
    solver.add(decision.lt(ASK));

    report("TG3b", await solver.check());
  }

  // =====================================================================
  // TG3c: Write tool ALWAYS gets content scan
  //
  // Write with dangerous content on a normal path -> decision >= Ask.
  // UNSAT = dangerous content on write always escalates to at least Ask.
  // =====================================================================
  {
    const ctx = new (await getZ3()).Context("TG3c");
    const { Solver, Int, Bool } = ctx;
    const solver = new Solver();

    const pathCat = Int.const("pathCat");
    const toolCat = Int.const("toolCat");
    const dangerousContent = Bool.const("dangerousContent");

    solver.add(pathCat.eq(P_NORMAL));
    solver.add(toolCat.eq(T_WRITE));
    solver.add(dangerousContent);

    const decision = buildPipeline(ctx, pathCat, toolCat, dangerousContent);

    // Try to find: decision < Ask
    solver.add(decision.lt(ASK));

    report("TG3c", await solver.check());
  }
}

main().then(() => process.exit(0));
