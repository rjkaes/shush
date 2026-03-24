import { PROCSUB_PLACEHOLDER } from "../ast-walk.js";
import { FILESYSTEM_READ } from "../taxonomy.js";

/**
 * If `tee` only writes to process substitutions (no real file paths),
 * classify as filesystem_read instead of letting the trie return
 * filesystem_write.
 */
export function classifyTee(tokens: string[]): string | null {
  if (tokens[0] !== "tee") return null;
  // Check non-flag arguments: are they all process-sub placeholders?
  let hasRealTarget = false;
  for (let i = 1; i < tokens.length; i++) {
    if (tokens[i].startsWith("-")) continue; // skip flags
    if (tokens[i] === PROCSUB_PLACEHOLDER) continue;
    hasRealTarget = true;
    break;
  }
  // If every target is a process substitution (or there are none), this
  // tee invocation just reads stdin without writing to any real file.
  if (!hasRealTarget) return FILESYSTEM_READ;
  return null;
}
