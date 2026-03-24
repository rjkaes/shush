import {
  NETWORK_WRITE,
  NETWORK_OUTBOUND,
  FILESYSTEM_WRITE,
} from "../taxonomy.js";

const CURL_DATA_FLAGS = new Set([
  "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
  "-F", "--form", "--form-string", "-T", "--upload-file", "--json",
]);
const CURL_DATA_LONG_PREFIXES = [
  "--data=", "--data-raw=", "--data-binary=", "--data-urlencode=",
  "--form=", "--form-string=", "--upload-file=", "--json=",
];
const CURL_METHOD_FLAGS = new Set(["-X", "--request"]);
export const WRITE_METHODS = new Set(["POST", "PUT", "DELETE", "PATCH"]);

export function classifyCurl(tokens: string[]): string | null {
  if (!tokens.length || tokens[0] !== "curl") return null;

  let hasData = false;
  let hasWriteMethod = false;

  let i = 1;
  while (i < tokens.length) {
    const tok = tokens[i];

    // Standalone data flags (consume the value argument too)
    if (CURL_DATA_FLAGS.has(tok)) {
      hasData = true;
      i += 2;
      continue;
    }

    // =joined long data flags
    if (CURL_DATA_LONG_PREFIXES.some((p) => tok.startsWith(p))) {
      hasData = true;
      i += 1;
      continue;
    }

    // Method flags: -X METHOD, --request METHOD, --request=METHOD
    if (CURL_METHOD_FLAGS.has(tok)) {
      if (i + 1 < tokens.length) {
        const method = tokens[i + 1].toUpperCase();
        if (WRITE_METHODS.has(method)) {
          hasWriteMethod = true;
        }
      }
      i += 2;
      continue;
    }
    if (tok.startsWith("--request=")) {
      const method = tok.split("=", 2)[1].toUpperCase();
      if (WRITE_METHODS.has(method)) {
        hasWriteMethod = true;
      }
      i += 1;
      continue;
    }

    // Combined short flags: -sXPOST, -XPOST, etc.
    if (tok.startsWith("-") && !tok.startsWith("--") && tok.length > 1) {
      const letters = tok.slice(1);
      if (letters.includes("X")) {
        const xIdx = letters.indexOf("X");
        const rest = letters.slice(xIdx + 1);
        // Extract method: chars after X until non-alpha
        const methodChars: string[] = [];
        for (const c of rest) {
          if (/[a-zA-Z]/.test(c)) {
            methodChars.push(c);
          } else {
            break;
          }
        }
        if (methodChars.length) {
          const method = methodChars.join("").toUpperCase();
          if (WRITE_METHODS.has(method)) {
            hasWriteMethod = true;
          }
        } else if (i + 1 < tokens.length) {
          // X is last char in combined flags, method is next token
          const method = tokens[i + 1].toUpperCase();
          if (WRITE_METHODS.has(method)) {
            hasWriteMethod = true;
          }
          i += 2;
          continue;
        }
      }
    }

    i += 1;
  }

  if (hasData) return NETWORK_WRITE;
  if (hasWriteMethod) return NETWORK_WRITE;
  return NETWORK_OUTBOUND;
}
