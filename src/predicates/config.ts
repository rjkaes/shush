// src/predicates/config.ts

import { type Decision, stricter } from "../types.js";
import { resolvePath } from "./path.js";
import path from "node:path";

export function mergeStricter(
  base: Record<string, Decision>,
  overlay: Record<string, Decision>,
): Record<string, Decision> {
  const result = { ...base };
  for (const [key, overlayVal] of Object.entries(overlay)) {
    result[key] = result[key] ? stricter(result[key], overlayVal) : overlayVal;
  }
  return result;
}

/** Returns true if resolved path `a` contains or equals resolved path `b`. */
export function pathContainsOrEquals(a: string, b: string): boolean {
  if (a === b) return true;
  return b.startsWith(a + path.sep);
}

/** Returns overlap path string or null. Sensitive overlap = either direction. */
export function allowedPathOverlapsSensitive(
  allowedPathRaw: string,
  sensitiveResolved: string[],
): string | null {
  const resolved = resolvePath(allowedPathRaw);
  for (const s of sensitiveResolved) {
    if (pathContainsOrEquals(resolved, s) || pathContainsOrEquals(s, resolved)) return s;
  }
  return null;
}

/** Returns filtered allowedPaths list with overlapping entries silently removed. */
export function filterAllowedPaths(
  allowedPaths: string[],
  sensitiveResolved: string[],
): string[] {
  return allowedPaths.filter(
    (raw) => allowedPathOverlapsSensitive(raw, sensitiveResolved) === null,
  );
}
