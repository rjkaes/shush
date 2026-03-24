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

// ==============================================================================
// Hydration — convert compiled JSON into runtime-friendly structures
// ==============================================================================

export function hydrateMatch(m: FlagRuleJSON["match"]): HydratedMatch {
  if ("anyFlag" in m) {
    return { kind: "anyFlag", flags: new Set(m.anyFlag) };
  }
  if ("anyFlagPrefix" in m) {
    return { kind: "anyFlagPrefix", prefixes: m.anyFlagPrefix };
  }
  if ("flag" in m && "nextIn" in m) {
    return { kind: "flag", flag: m.flag, nextIn: new Set(m.nextIn) };
  }
  if ("anyToken" in m) {
    return { kind: "anyToken", substring: m.anyToken };
  }
  if ("tokenMatches" in m) {
    return { kind: "tokenMatches", regex: new RegExp(m.tokenMatches) };
  }
  throw new Error(`Unknown match shape: ${JSON.stringify(m)}`);
}

export function hydrate(
  raw: CompiledFlagRulesJSON,
): Map<string, HydratedRule[]> {
  const map = new Map<string, HydratedRule[]>();
  for (const [command, rules] of Object.entries(raw)) {
    map.set(
      command,
      rules.map((r) => ({ match: hydrateMatch(r.match), type: r.type })),
    );
  }
  return map;
}

// ==============================================================================
// Condition evaluation
// ==============================================================================

export function matchesCondition(
  match: HydratedMatch,
  tokens: string[],
): boolean {
  switch (match.kind) {
    case "anyFlag":
      return tokens.some((t) => match.flags.has(t));

    case "anyFlagPrefix":
      return tokens.some((t) =>
        match.prefixes.some((p) => t === p || t.startsWith(p)),
      );

    case "flag": {
      const idx = tokens.indexOf(match.flag);
      if (idx === -1 || idx + 1 >= tokens.length) return false;
      return match.nextIn.has(tokens[idx + 1]);
    }

    case "anyToken":
      return tokens.some((t) => t.includes(match.substring));

    case "tokenMatches":
      return tokens.some((t) => match.regex.test(t));
  }
}

// ==============================================================================
// Rule evaluation — first match wins
// ==============================================================================

export function checkFlagRules(
  command: string,
  tokens: string[],
  rules: Map<string, HydratedRule[]> = FLAG_RULES,
): string | null {
  const commandRules = rules.get(command);
  if (!commandRules) return null;

  for (const rule of commandRules) {
    if (matchesCondition(rule.match, tokens)) {
      return rule.type;
    }
  }
  return null;
}

// ==============================================================================
// Default rules — loaded from compiled JSON at module init
// ==============================================================================

import compiledJSON from "../data/flag-rules-compiled.json";

const FLAG_RULES: Map<string, HydratedRule[]> = hydrate(
  compiledJSON as CompiledFlagRulesJSON,
);
