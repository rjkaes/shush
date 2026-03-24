import {
  NETWORK_WRITE,
  NETWORK_OUTBOUND,
} from "../taxonomy.js";
import { WRITE_METHODS } from "./curl.js";

const HTTPIE_CMDS = new Set(["http", "https", "xh", "xhs"]);
const HTTPIE_METHODS = new Set(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]);

export function classifyHttpie(tokens: string[]): string | null {
  if (!tokens.length || !HTTPIE_CMDS.has(tokens[0])) return null;

  const args = tokens.slice(1);
  let hasForm = false;
  let hasWriteMethod = false;
  let hasDataItem = false;
  let foundUrl = false;

  for (const arg of args) {
    // Check for --form / -f
    if (arg === "--form" || arg === "-f") {
      hasForm = true;
      continue;
    }

    // Skip other flags
    if (arg.startsWith("-")) continue;

    // First non-flag arg: check if it's an uppercase method
    if (!foundUrl && HTTPIE_METHODS.has(arg.toUpperCase())) {
      if (WRITE_METHODS.has(arg.toUpperCase())) {
        hasWriteMethod = true;
      }
      continue;
    }

    if (!foundUrl) {
      foundUrl = true;
      continue;
    }

    // After URL: check for data item patterns (key=value, key:=value, key@file)
    if (arg.includes("=") || arg.includes(":=") || arg.includes("@")) {
      hasDataItem = true;
    }
  }

  if (hasWriteMethod) return NETWORK_WRITE;
  if (hasForm) return NETWORK_WRITE;
  if (hasDataItem) return NETWORK_WRITE;
  return NETWORK_OUTBOUND;
}
