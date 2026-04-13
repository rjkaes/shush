import {
  getZ3,
  D,
  stricter,
  validDecision,
  report,
  ACTION_TYPES,
  POLICIES,
  buildPolicyFunction,
} from "../z3-helpers";

async function main() {
  const { Context } = await getZ3();

  // L1: Idempotency — stricter(a, a) = a
  {
    const ctx = new Context("L1");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const a = Int.const("a");
    solver.add(validDecision(ctx, a));

    // Try to find a where stricter(a, a) != a
    solver.add(stricter(ctx, a, a).neq(a));
    report("L1", await solver.check());
  }

  // L2: Identity — stricter(allow, x) = x (allow=0 is the identity element)
  {
    const ctx = new Context("L2");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const x = Int.const("x");
    solver.add(validDecision(ctx, x));

    // Try to find x where stricter(0, x) != x
    solver.add(stricter(ctx, Int.val(D.allow), x).neq(x));
    report("L2", await solver.check());
  }

  // L3: Total order — for any a, b in [0,3]: a <= b OR b <= a
  {
    const ctx = new Context("L3");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const a = Int.const("a");
    const b = Int.const("b");
    solver.add(validDecision(ctx, a));
    solver.add(validDecision(ctx, b));

    // Try to find a, b where neither a <= b nor b <= a
    solver.add(ctx.Not(ctx.Or(a.le(b), b.le(a))));
    report("L3", await solver.check());
  }

  // L4: No gaps — decisions are exactly {0, 1, 2, 3}
  {
    const ctx = new Context("L4");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const d = Int.const("d");
    solver.add(validDecision(ctx, d));

    // Try to find d in [0,3] that is none of {0, 1, 2, 3}
    solver.add(d.neq(D.allow));
    solver.add(d.neq(D.context));
    solver.add(d.neq(D.ask));
    solver.add(d.neq(D.block));
    report("L4", await solver.check());
  }

  // L5: Policy partition — the 22 action types partition into exactly
  // 7 allow, 4 context, 10 ask, 1 block
  {
    const ctx = new Context("L5");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const { policyFn, constraints } = buildPolicyFunction(ctx);
    for (const c of constraints) solver.add(c);

    // Count policies per level from real data
    const counts = { allow: 0, context: 0, ask: 0, block: 0 };
    for (const at of ACTION_TYPES) {
      const p = POLICIES[at];
      if (p === D.allow) counts.allow++;
      else if (p === D.context) counts.context++;
      else if (p === D.ask) counts.ask++;
      else if (p === D.block) counts.block++;
    }

    const expected = { allow: 7, context: 4, ask: 10, block: 1 };
    const totalOk = ACTION_TYPES.length === 22;
    const partitionOk =
      counts.allow === expected.allow &&
      counts.context === expected.context &&
      counts.ask === expected.ask &&
      counts.block === expected.block;

    if (!totalOk || !partitionOk) {
      report("L5", "sat");
    } else {
      // Use Z3 to verify: assert there exists an index where policyFn
      // disagrees with the expected mapping. UNSAT = all match.
      const idx = Int.const("idx");
      solver.add(idx.ge(0));
      solver.add(idx.lt(ACTION_TYPES.length));

      // For each valid index, policyFn must equal the expected value
      const mismatches = ACTION_TYPES.map((at, i) =>
        ctx.And(idx.eq(i), policyFn.call(idx).neq(Int.val(POLICIES[at]))),
      );
      solver.add(ctx.Or(...mismatches));
      report("L5", await solver.check());
    }
  }
}

main().then(() => process.exit(0));
