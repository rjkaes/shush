import { checkFlagRules } from "../flag-rules.js";
import {
  classifyTokens,
  FILESYSTEM_READ,
  FILESYSTEM_DELETE,
  DEFAULT_POLICIES,
} from "../taxonomy.js";
import { STRICTNESS, type Decision } from "../types.js";

function classifyExecTokens(tokens: string[]): string {
  const flagResult = checkFlagRules(tokens[0], tokens);
  if (flagResult) return flagResult;
  return classifyTokens(tokens);
}

function stricterType(a: string, b: string): string {
  const policies = DEFAULT_POLICIES as Record<string, Decision>;
  const aRank = STRICTNESS[policies[a] ?? "ask"] ?? 2;
  const bRank = STRICTNESS[policies[b] ?? "ask"] ?? 2;
  return bRank > aRank ? b : a;
}

export function classifyFind(tokens: string[]): string | null {
  if (!tokens.length || tokens[0] !== "find") return null;

  let worst: string = FILESYSTEM_READ;
  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i];

    if (tok === "-delete") return FILESYSTEM_DELETE;

    // -exec/-execdir/-ok: classify the command that follows
    if (tok === "-exec" || tok === "-execdir" || tok === "-ok") {
      // Collect tokens until the terminating ; or +
      const execTokens: string[] = [];
      for (let j = i + 1; j < tokens.length; j++) {
        if (tokens[j] === ";" || tokens[j] === "+") break;
        // Skip {} placeholder
        if (tokens[j] === "{}") continue;
        execTokens.push(tokens[j]);
      }
      if (execTokens.length) {
        // Classify the inner command via prefix table + flag classifiers
        const innerType = classifyExecTokens(execTokens);
        worst = stricterType(worst, innerType);
      } else {
        // No tokens after -exec: conservative default
        return FILESYSTEM_DELETE;
      }
    }
  }
  return worst;
}
