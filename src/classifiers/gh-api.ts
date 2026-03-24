import {
  GIT_SAFE,
  GIT_WRITE,
  GIT_HISTORY_REWRITE,
} from "../taxonomy.js";

// gh api uses --method/-X for HTTP method (default GET).
// Body flags (-f, --field, -F, --raw-field, --input) flip the default to POST.
const GH_API_METHOD_FLAGS = new Set(["--method", "-X"]);
const GH_API_BODY_FLAGS = new Set(["-f", "--field", "-F", "--raw-field", "--input"]);
// Known flags that consume a value argument (skip to avoid misclassification)
const GH_API_VALUE_FLAGS = new Set(["-H", "--header", "--jq", "-t", "--template", "--cache"]);

export function classifyGhApi(tokens: string[]): string | null {
  if (tokens.length < 2 || tokens[0] !== "gh" || tokens[1] !== "api") return null;

  let explicitMethod: string | null = null;
  let hasBody = false;

  let i = 2;
  while (i < tokens.length) {
    const tok = tokens[i];

    if (GH_API_METHOD_FLAGS.has(tok) && i + 1 < tokens.length) {
      explicitMethod = tokens[i + 1].toUpperCase();
      i += 2;
      continue;
    }
    if (tok.startsWith("--method=")) {
      explicitMethod = tok.split("=", 2)[1].toUpperCase();
      i += 1;
      continue;
    }

    const eqIdx = tok.indexOf("=");
    const flagPart = eqIdx >= 0 ? tok.slice(0, eqIdx) : tok;
    if (GH_API_BODY_FLAGS.has(flagPart)) {
      hasBody = true;
      i += eqIdx >= 0 ? 1 : 2; // =joined: skip flag only; separate: skip flag + value
      continue;
    }

    // Skip known flags that consume a value argument
    if (GH_API_VALUE_FLAGS.has(flagPart)) {
      i += eqIdx >= 0 ? 1 : 2;
      continue;
    }

    i += 1;
  }

  const method = explicitMethod ?? (hasBody ? "POST" : "GET");

  // Classification: DELETE → git_history_rewrite (destructive, irreversible),
  // GET/HEAD → git_safe (read-only), POST/PUT/PATCH → git_write (mutating).
  if (method === "DELETE") return GIT_HISTORY_REWRITE;
  if (method === "GET" || method === "HEAD") return GIT_SAFE;
  return GIT_WRITE;
}
