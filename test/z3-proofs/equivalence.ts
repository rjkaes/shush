import { getZ3, D, stricter, validDecision, report } from "../z3-helpers";

async function main() {
  const { Context } = await getZ3();

  // E1: Bash redirect to sensitive path >= Write to same path
  // Write tool gets pathPolicy directly. Bash redirect gets
  // stricter(baseCommandDecision, pathPolicy), which is max(base, pathPolicy)
  // >= pathPolicy. Assert the opposite and expect UNSAT.
  {
    const ctx = new Context("E1");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const pathPolicy = Int.const("pathPolicy");
    const baseCmd = Int.const("baseCmd");
    solver.add(validDecision(ctx, pathPolicy));
    solver.add(validDecision(ctx, baseCmd));

    const writeDecision = pathPolicy;
    const redirectDecision = stricter(ctx, baseCmd, pathPolicy);

    // Try to find a case where redirect is less strict than write
    solver.add(redirectDecision.lt(writeDecision));
    report("E1", await solver.check());
  }

  // E2: Bash cat of sensitive path >= Read of same path
  // Read tool gets pathPolicy directly. cat gets
  // stricter(filesystem_read_policy, pathPolicy). filesystem_read is
  // allow (0), so stricter(0, pathPolicy) = pathPolicy = readDecision.
  // Assert catDecision < readDecision and expect UNSAT.
  {
    const ctx = new Context("E2");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const pathPolicy = Int.const("pathPolicy");
    solver.add(validDecision(ctx, pathPolicy));

    const readDecision = pathPolicy;
    const fsReadPolicy = Int.val(D.allow);
    const catDecision = stricter(ctx, fsReadPolicy, pathPolicy);

    solver.add(catDecision.lt(readDecision));
    report("E2", await solver.check());
  }

  // E3: stricter is commutative — stricter(a,b) == stricter(b,a)
  {
    const ctx = new Context("E3");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const a = Int.const("a");
    const b = Int.const("b");
    solver.add(validDecision(ctx, a));
    solver.add(validDecision(ctx, b));

    solver.add(stricter(ctx, a, b).neq(stricter(ctx, b, a)));
    report("E3", await solver.check());
  }

  // E4: stricter is associative — stricter(a, stricter(b,c)) == stricter(stricter(a,b), c)
  {
    const ctx = new Context("E4");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const a = Int.const("a");
    const b = Int.const("b");
    const c = Int.const("c");
    solver.add(validDecision(ctx, a));
    solver.add(validDecision(ctx, b));
    solver.add(validDecision(ctx, c));

    const left = stricter(ctx, a, stricter(ctx, b, c));
    const right = stricter(ctx, stricter(ctx, a, b), c);

    solver.add(left.neq(right));
    report("E4", await solver.check());
  }
}

main().then(() => process.exit(0));
