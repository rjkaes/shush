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

// Predicate flags that signal end of search root paths.
// Everything before the first predicate is a search root directory.
const FIND_PREDICATES = new Set([
  "-name", "-iname", "-path", "-ipath", "-regex", "-iregex",
  "-type", "-size", "-mtime", "-atime", "-ctime", "-mmin", "-amin", "-cmin",
  "-perm", "-user", "-group", "-uid", "-gid", "-newer", "-newermt",
  "-maxdepth", "-mindepth", "-depth",
  "-delete", "-exec", "-execdir", "-ok", "-okdir",
  "-print", "-print0", "-printf", "-ls", "-fls",
  "-prune", "-quit", "-empty", "-readable", "-writable", "-executable",
  "-not", "!", "(", ")", "-a", "-o", "-and", "-or",
  "-true", "-false", "-noleaf", "-mount", "-xdev",
  "-samefile", "-inum", "-links", "-used",
]);

/**
 * Extract search root paths from find tokens.
 * In `find /a /b -name "*.log" -delete`, roots are ["/a", "/b"].
 * Everything before the first predicate flag is a search root.
 */
export function extractFindRoots(tokens: string[]): string[] {
  const roots: string[] = [];
  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i];
    if (FIND_PREDICATES.has(tok)) break;
    roots.push(tok);
  }
  return roots;
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
