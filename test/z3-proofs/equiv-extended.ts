import { getZ3, D, stricter, validDecision, report } from "../z3-helpers";

async function main() {
  const { Context } = await getZ3();

  // EX1: tee to sensitive path >= Write to same path
  // tee writes to a file, classified as filesystem_write (context=1).
  // For a sensitive path, teeDecision = stricter(filesystem_write, pathPolicy).
  // Write tool gets pathPolicy directly.
  // Assert teeDecision < writeDecision and expect UNSAT.
  {
    const ctx = new Context("EX1");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const pathPolicy = Int.const("pathPolicy");
    solver.add(validDecision(ctx, pathPolicy));
    // Sensitive paths have pathPolicy >= ask
    solver.add(pathPolicy.ge(D.ask));

    const writeDecision = pathPolicy;
    const teeBasePolicy = Int.val(D.context); // filesystem_write
    const teeDecision = stricter(ctx, teeBasePolicy, pathPolicy);

    solver.add(teeDecision.lt(writeDecision));
    report("EX1", await solver.check());
  }

  // EX2: cp to sensitive path >= Write to same path
  // cp writes to destination, classified as filesystem_write (context=1).
  // Same structure as EX1 with cp instead of tee.
  {
    const ctx = new Context("EX2");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const pathPolicy = Int.const("pathPolicy");
    solver.add(validDecision(ctx, pathPolicy));
    solver.add(pathPolicy.ge(D.ask));

    const writeDecision = pathPolicy;
    const cpBasePolicy = Int.val(D.context); // filesystem_write
    const cpDecision = stricter(ctx, cpBasePolicy, pathPolicy);

    solver.add(cpDecision.lt(writeDecision));
    report("EX2", await solver.check());
  }

  // EX3: mv to sensitive path >= Write to same path
  // mv writes to destination, classified as filesystem_write (context=1).
  {
    const ctx = new Context("EX3");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const pathPolicy = Int.const("pathPolicy");
    solver.add(validDecision(ctx, pathPolicy));
    solver.add(pathPolicy.ge(D.ask));

    const writeDecision = pathPolicy;
    const mvBasePolicy = Int.val(D.context); // filesystem_write
    const mvDecision = stricter(ctx, mvBasePolicy, pathPolicy);

    solver.add(mvDecision.lt(writeDecision));
    report("EX3", await solver.check());
  }

  // EX4: chmod on sensitive path >= Write to same path
  // chmod modifies file metadata, classified as filesystem_write (context=1).
  {
    const ctx = new Context("EX4");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const pathPolicy = Int.const("pathPolicy");
    solver.add(validDecision(ctx, pathPolicy));
    solver.add(pathPolicy.ge(D.ask));

    const writeDecision = pathPolicy;
    const chmodBasePolicy = Int.val(D.context); // filesystem_write
    const chmodDecision = stricter(ctx, chmodBasePolicy, pathPolicy);

    solver.add(chmodDecision.lt(writeDecision));
    report("EX4", await solver.check());
  }
}

main().then(() => process.exit(0));
