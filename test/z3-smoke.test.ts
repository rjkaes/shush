import { describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { join } from "node:path";

// z3-solver uses Emscripten pthreads (SharedArrayBuffer + Worker threads)
// which are incompatible with bun's Worker implementation. All Z3 operations
// must run in a node subprocess.

function z3Run(script: string): string {
  return execFileSync("node", ["-e", script], {
    cwd: join(import.meta.dir, ".."),
    timeout: 30_000,
    encoding: "utf-8",
  }).trim();
}

describe("z3 smoke", () => {
  test("solver finds UNSAT for contradiction", () => {
    const result = z3Run(`
      const { init } = require('z3-solver');
      (async () => {
        const { Context } = await init();
        const { Solver, Int } = new Context('smoke');
        const solver = new Solver();
        const x = Int.const('x');
        solver.add(x.gt(0));
        solver.add(x.lt(0));
        const result = await solver.check();
        console.log(result);
        process.exit(0);
      })();
    `);
    expect(result).toBe("unsat");
  });

  test("solver finds SAT for satisfiable constraints", () => {
    const result = z3Run(`
      const { init } = require('z3-solver');
      (async () => {
        const { Context } = await init();
        const { Solver, Int } = new Context('smoke2');
        const solver = new Solver();
        const x = Int.const('x');
        solver.add(x.gt(0));
        solver.add(x.lt(10));
        const result = await solver.check();
        console.log(result);
        process.exit(0);
      })();
    `);
    expect(result).toBe("sat");
  });
});
