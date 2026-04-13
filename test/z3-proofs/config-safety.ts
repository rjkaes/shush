import { getZ3, D, stricter, validDecision, report } from "../z3-helpers";

async function main() {
  const { Context } = await getZ3();

  // CS1: Config can tighten policies, never loosen
  // The stricter-wins merge means mergedPolicy = stricter(default, override).
  // Assert: mergedPolicy < defaultPolicy. UNSAT proves config never loosens.
  {
    const ctx = new Context("CS1");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const defaultPolicy = Int.const("defaultPolicy");
    const configOverride = Int.const("configOverride");
    solver.add(validDecision(ctx, defaultPolicy));
    solver.add(validDecision(ctx, configOverride));

    const mergedPolicy = stricter(ctx, defaultPolicy, configOverride);

    // Try to find a case where merged is less strict than default
    solver.add(mergedPolicy.lt(defaultPolicy));
    report("CS1", await solver.check());
  }

  // CS2a: allowedPaths does not weaken sensitive_block decisions
  // PathGuard pipeline checks sensitive paths BEFORE boundary checks.
  // allowedPaths only exempts the boundary check. A sensitive_block path
  // still returns Block regardless of isAllowedPath.
  //
  // Pipeline as nested ITE:
  //   If(isHook ^ isWrite, Block,
  //   If(isHook ^ !isWrite, Allow,
  //   If(isSensitiveBlock, Block,
  //   If(isSensitiveAsk, Ask,
  //   If(isOutsideBoundary ^ !isAllowedPath ^ isWrite, Ask,
  //   If(hasDangerousContent ^ isWrite, Ask,
  //   Allow))))))
  {
    const ctx = new Context("CS2a");
    const { Solver, Bool, Int } = ctx;
    const solver = new Solver();

    const isHook = Bool.const("isHook");
    const isWrite = Bool.const("isWrite");
    const isSensitiveBlock = Bool.const("isSensitiveBlock");
    const isSensitiveAsk = Bool.const("isSensitiveAsk");
    const isOutsideBoundary = Bool.const("isOutsideBoundary");
    const isAllowedPath = Bool.const("isAllowedPath");
    const hasDangerousContent = Bool.const("hasDangerousContent");

    const allow = Int.val(D.allow);
    const ask = Int.val(D.ask);
    const block = Int.val(D.block);

    // Encode the PathGuard pipeline
    const decision = ctx.If(
      ctx.And(isHook, isWrite),
      block,
      ctx.If(
        ctx.And(isHook, ctx.Not(isWrite)),
        allow,
        ctx.If(
          isSensitiveBlock,
          block,
          ctx.If(
            isSensitiveAsk,
            ask,
            ctx.If(
              ctx.And(isOutsideBoundary, ctx.Not(isAllowedPath), isWrite),
              ask,
              ctx.If(
                ctx.And(hasDangerousContent, isWrite),
                ask,
                allow,
              ),
            ),
          ),
        ),
      ),
    );

    // Constrain: path is sensitive_block AND in allowedPaths
    solver.add(isSensitiveBlock.eq(ctx.Bool.val(true)));
    solver.add(isAllowedPath.eq(ctx.Bool.val(true)));
    solver.add(isHook.eq(ctx.Bool.val(false)));

    // Assert decision < Block — should be UNSAT
    solver.add(decision.lt(block));
    report("CS2a", await solver.check());
  }

  // CS2b: allowedPaths does not weaken sensitive_ask decisions
  // Same pipeline, but path is sensitive_ask. Decision should still be >= Ask.
  {
    const ctx = new Context("CS2b");
    const { Solver, Bool, Int } = ctx;
    const solver = new Solver();

    const isHook = Bool.const("isHook");
    const isWrite = Bool.const("isWrite");
    const isSensitiveBlock = Bool.const("isSensitiveBlock");
    const isSensitiveAsk = Bool.const("isSensitiveAsk");
    const isOutsideBoundary = Bool.const("isOutsideBoundary");
    const isAllowedPath = Bool.const("isAllowedPath");
    const hasDangerousContent = Bool.const("hasDangerousContent");

    const allow = Int.val(D.allow);
    const ask = Int.val(D.ask);
    const block = Int.val(D.block);

    const decision = ctx.If(
      ctx.And(isHook, isWrite),
      block,
      ctx.If(
        ctx.And(isHook, ctx.Not(isWrite)),
        allow,
        ctx.If(
          isSensitiveBlock,
          block,
          ctx.If(
            isSensitiveAsk,
            ask,
            ctx.If(
              ctx.And(isOutsideBoundary, ctx.Not(isAllowedPath), isWrite),
              ask,
              ctx.If(
                ctx.And(hasDangerousContent, isWrite),
                ask,
                allow,
              ),
            ),
          ),
        ),
      ),
    );

    // Constrain: path is sensitive_ask (not sensitive_block) AND in allowedPaths
    solver.add(isSensitiveBlock.eq(ctx.Bool.val(false)));
    solver.add(isSensitiveAsk.eq(ctx.Bool.val(true)));
    solver.add(isAllowedPath.eq(ctx.Bool.val(true)));
    solver.add(isHook.eq(ctx.Bool.val(false)));

    // Assert decision < Ask — should be UNSAT
    solver.add(decision.lt(ask));
    report("CS2b", await solver.check());
  }
}

main().then(() => process.exit(0));
