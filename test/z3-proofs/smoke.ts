import { getZ3, report } from "../z3-helpers";

async function main() {
  const { Context } = await getZ3();
  const { Solver, Int } = new Context("smoke");

  const solver = new Solver();
  const x = Int.const("x");
  solver.add(x.gt(0));
  solver.add(x.lt(0));
  report("contradiction", await solver.check());

  const solver2 = new Solver();
  const y = Int.const("y");
  solver2.add(y.gt(0));
  solver2.add(y.lt(10));
  report("satisfiable", await solver2.check());
}

main().then(() => process.exit(0));
