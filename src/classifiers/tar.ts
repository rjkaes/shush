import {
  FILESYSTEM_READ,
  FILESYSTEM_WRITE,
  FILESYSTEM_DELETE,
} from "../taxonomy.js";

export function classifyTar(tokens: string[]): string | null {
  if (!tokens.length || tokens[0] !== "tar") return null;

  let foundRead = false;
  let foundWrite = false;
  const args = tokens.slice(1);

  if (!args.length) return FILESYSTEM_WRITE; // Conservative default

  // Check if first arg is a bare mode string (no leading dash): tf, czf, xf
  const first = args[0];
  if (first && !first.startsWith("-")) {
    if ([..."cxru"].some((c) => first.includes(c))) {
      foundWrite = true;
    } else if (first.includes("t")) {
      foundRead = true;
    }
  }

  // Check all flag arguments
  for (const tok of args) {
    if (tok.startsWith("-") && tok.length > 1 && tok[1] !== "-") {
      // Short flags: -tf, -czf, -xf, etc.
      const letters = tok.slice(1);
      if (letters.includes("t")) foundRead = true;
      if ([..."cxru"].some((c) => letters.includes(c))) foundWrite = true;
    } else if (tok.startsWith("--")) {
      if (tok === "--list") foundRead = true;
      if (["--create", "--extract", "--append", "--update", "--get", "--delete"].includes(tok)) {
        foundWrite = true;
      }
    }
  }

  if (foundWrite) return FILESYSTEM_WRITE;
  if (foundRead) return FILESYSTEM_READ;
  return FILESYSTEM_WRITE; // Conservative default
}
