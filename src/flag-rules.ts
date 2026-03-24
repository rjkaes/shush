// flag-rules.ts
//
// Data-driven flag rule engine. Loaded from compiled JSON at build
// time; anyFlag arrays hydrated to Sets at module load for O(1)
// membership checks.

export interface FlagRuleJSON {
  match:
    | { anyFlag: string[] }
    | { anyFlagPrefix: string[] }
    | { flag: string; nextIn: string[] }
    | { anyToken: string }
    | { tokenMatches: string };
  type: string;
}

type HydratedMatch =
  | { kind: "anyFlag"; flags: Set<string> }
  | { kind: "anyFlagPrefix"; prefixes: string[] }
  | { kind: "flag"; flag: string; nextIn: Set<string> }
  | { kind: "anyToken"; substring: string }
  | { kind: "tokenMatches"; regex: RegExp };

export interface HydratedRule {
  match: HydratedMatch;
  type: string;
}

export type CompiledFlagRulesJSON = Record<string, FlagRuleJSON[]>;
