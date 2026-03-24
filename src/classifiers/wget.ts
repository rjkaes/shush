import {
  NETWORK_WRITE,
  NETWORK_OUTBOUND,
} from "../taxonomy.js";
import { WRITE_METHODS } from "./curl.js";

export function classifyWget(tokens: string[]): string | null {
  if (!tokens.length || tokens[0] !== "wget") return null;

  let hasData = false;
  let hasWriteMethod = false;

  let i = 1;
  while (i < tokens.length) {
    const tok = tokens[i];

    // --post-data, --post-file (standalone or =joined)
    if (tok === "--post-data" || tok === "--post-file") {
      hasData = true;
      i += 2; // skip value
      continue;
    }
    if (tok.startsWith("--post-data=") || tok.startsWith("--post-file=")) {
      hasData = true;
      i += 1;
      continue;
    }

    // --method METHOD or --method=METHOD
    if (tok === "--method") {
      if (i + 1 < tokens.length) {
        const method = tokens[i + 1].toUpperCase();
        if (WRITE_METHODS.has(method)) {
          hasWriteMethod = true;
        }
      }
      i += 2;
      continue;
    }
    if (tok.startsWith("--method=")) {
      const method = tok.split("=", 2)[1].toUpperCase();
      if (WRITE_METHODS.has(method)) {
        hasWriteMethod = true;
      }
      i += 1;
      continue;
    }

    i += 1;
  }

  if (hasData) return NETWORK_WRITE;
  if (hasWriteMethod) return NETWORK_WRITE;
  return NETWORK_OUTBOUND;
}
