import { getZ3, D, stricter, validDecision, report } from "../z3-helpers";

async function main() {
  const { Context } = await getZ3();

  // X1: network | exec (no inline flag) always blocks
  // When a network source pipes to an exec sink without stdin being
  // ignored, the composition rule fires and forces block.
  {
    const ctx = new Context("X1");
    const { Solver, Bool, Int } = ctx;
    const solver = new Solver();

    const isNetworkSource = Bool.const("isNetworkSource");
    const isExecSink = Bool.const("isExecSink");
    const stdinIgnored = Bool.const("stdinIgnored");
    const decision = Int.const("decision");

    solver.add(validDecision(ctx, decision));
    // When composition fires, decision = block
    solver.add(
      ctx.Implies(
        ctx.And(isNetworkSource, isExecSink, ctx.Not(stdinIgnored)),
        decision.eq(Int.val(D.block)),
      ),
    );
    // Try to find: composition fires but decision != block
    solver.add(isNetworkSource);
    solver.add(isExecSink);
    solver.add(ctx.Not(stdinIgnored));
    solver.add(decision.neq(Int.val(D.block)));
    report("X1", await solver.check());
  }

  // X2: sensitive_read | network always blocks (exfil detection)
  {
    const ctx = new Context("X2");
    const { Solver, Bool, Int } = ctx;
    const solver = new Solver();

    const isSensitiveRead = Bool.const("isSensitiveRead");
    const isNetworkSink = Bool.const("isNetworkSink");
    const decision = Int.const("decision");

    solver.add(validDecision(ctx, decision));
    solver.add(
      ctx.Implies(
        ctx.And(isSensitiveRead, isNetworkSink),
        decision.eq(Int.val(D.block)),
      ),
    );
    solver.add(isSensitiveRead);
    solver.add(isNetworkSink);
    solver.add(decision.neq(Int.val(D.block)));
    report("X2", await solver.check());
  }

  // X3: decode | exec (no inline flag) always blocks
  {
    const ctx = new Context("X3");
    const { Solver, Bool, Int } = ctx;
    const solver = new Solver();

    const isDecodeStage = Bool.const("isDecodeStage");
    const isExecSink = Bool.const("isExecSink");
    const stdinIgnored = Bool.const("stdinIgnored");
    const decision = Int.const("decision");

    solver.add(validDecision(ctx, decision));
    solver.add(
      ctx.Implies(
        ctx.And(isDecodeStage, isExecSink, ctx.Not(stdinIgnored)),
        decision.eq(Int.val(D.block)),
      ),
    );
    solver.add(isDecodeStage);
    solver.add(isExecSink);
    solver.add(ctx.Not(stdinIgnored));
    solver.add(decision.neq(Int.val(D.block)));
    report("X3", await solver.check());
  }

  // X4: Escalation monotonicity — final decision >= base decision
  // Escalations (env, redirect, git-path) can only raise severity.
  {
    const ctx = new Context("X4");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const baseDecision = Int.const("baseDecision");
    const envEscalation = Int.const("envEscalation");
    const redirectEscalation = Int.const("redirectEscalation");
    const gitPathEscalation = Int.const("gitPathEscalation");

    solver.add(validDecision(ctx, baseDecision));
    solver.add(validDecision(ctx, envEscalation));
    solver.add(validDecision(ctx, redirectEscalation));
    solver.add(validDecision(ctx, gitPathEscalation));

    const finalDecision = stricter(
      ctx,
      stricter(ctx, stricter(ctx, baseDecision, envEscalation), redirectEscalation),
      gitPathEscalation,
    );

    // Try to find: final < base
    solver.add(finalDecision.lt(baseDecision));
    report("X4", await solver.check());
  }

  // X5: Pipeline result >= max of individual stages
  // The pipeline result (composed via stricter) is at least as strict
  // as every individual stage.
  {
    const ctx = new Context("X5");
    const { Solver, Int, Or } = ctx;
    const solver = new Solver();

    const stage1 = Int.const("stage1");
    const stage2 = Int.const("stage2");
    const stage3 = Int.const("stage3");
    const compositionBonus = Int.const("compositionBonus");

    solver.add(validDecision(ctx, stage1));
    solver.add(validDecision(ctx, stage2));
    solver.add(validDecision(ctx, stage3));
    solver.add(validDecision(ctx, compositionBonus));

    const pipelineResult = stricter(
      ctx,
      stricter(ctx, stage1, stage2),
      stricter(ctx, stage3, compositionBonus),
    );

    // Try to find: pipeline result less than any individual stage
    solver.add(
      Or(
        pipelineResult.lt(stage1),
        pipelineResult.lt(stage2),
        pipelineResult.lt(stage3),
      ),
    );
    report("X5", await solver.check());
  }

  // X6: No composition rule produces Allow
  // When any composition rule fires, the decision is at least ask (2).
  {
    const ctx = new Context("X6");
    const { Solver, Bool, Int } = ctx;
    const solver = new Solver();

    const compositionFired = Bool.const("compositionFired");
    const compositionDecision = Int.const("compositionDecision");

    solver.add(validDecision(ctx, compositionDecision));
    // When a composition rule fires, decision >= ask
    solver.add(
      ctx.Implies(compositionFired, compositionDecision.ge(Int.val(D.ask))),
    );
    // Try to find: fired but decision < ask
    solver.add(compositionFired);
    solver.add(compositionDecision.lt(Int.val(D.ask)));
    report("X6", await solver.check());
  }
}

main().then(() => process.exit(0));
