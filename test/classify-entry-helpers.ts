/**
 * Extract the prefix token array from a classify entry.
 * Accepts both the bare array form ["cmd", "sub"] and the object form
 * { prefix: ["cmd", "sub"], pathArgs: [...] }.
 */
export function entryPrefix(e: unknown): string[] {
  if (Array.isArray(e)) return e as string[];
  if (e !== null && typeof e === "object") {
    const obj = e as { prefix?: unknown };
    if (Array.isArray(obj.prefix)) return obj.prefix as string[];
  }
  return [];
}
