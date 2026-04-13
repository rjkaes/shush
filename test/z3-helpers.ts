import { init } from "z3-solver";

import policiesJson from "../data/policies.json";

// Decision encoding: allow=0, context=1, ask=2, block=3
export const D = { allow: 0, context: 1, ask: 2, block: 3 } as const;
export type DVal = (typeof D)[keyof typeof D];

// Action types from policies.json
export const ACTION_TYPES = Object.keys(policiesJson) as string[];
export const POLICIES: Record<string, number> = Object.fromEntries(
  Object.entries(policiesJson).map(([k, v]) => [k, D[v as keyof typeof D]]),
);

// Tool categories (mirrors path-guard.ts)
export const WRITE_TOOLS = ["Write", "Edit", "MultiEdit", "NotebookEdit"];
export const READ_TOOLS = ["Read"];
export const SEARCH_TOOLS = ["Glob", "Grep"];

// Path categories
export const PATH_HOOK = 0;
export const PATH_SENSITIVE_BLOCK = 1;
export const PATH_SENSITIVE_ASK = 2;
export const PATH_NORMAL = 3;

// Singleton Z3 instance (WASM init is expensive)
let z3Cache: Awaited<ReturnType<typeof init>> | null = null;

export async function getZ3() {
  if (!z3Cache) {
    z3Cache = await init();
  }
  return z3Cache;
}

// Build Z3 function mapping action type index -> default policy decision
export function buildPolicyFunction(ctx: any) {
  const { Int, Function: Func } = ctx;
  const policyFn = Func.declare("policy", Int.sort(), Int.sort());
  const constraints = ACTION_TYPES.map((at, i) =>
    policyFn.call(Int.val(i)).eq(Int.val(POLICIES[at])),
  );
  return {
    policyFn,
    constraints,
    actionTypeIndex: Object.fromEntries(ACTION_TYPES.map((at, i) => [at, i])),
  };
}

// stricter(a, b) = max(a, b) in decision severity
export function stricter(ctx: any, a: any, b: any) {
  return ctx.If(a.ge(b), a, b);
}

// Constrain decision variable to [0,3]
export function validDecision(ctx: any, d: any) {
  return ctx.And(d.ge(0), d.le(3));
}

// Standard result reporter for proof files
export function report(name: string, result: string) {
  console.log(JSON.stringify({ name, result }));
}
