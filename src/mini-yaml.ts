// src/mini-yaml.ts
//
// Minimal YAML parser for shush config files. Handles only the subset
// we need: top-level map keys, nested key:value pairs, and nested
// arrays with `- item` syntax. Supports comments and quoted values.
//
// Replaces the full `yaml` package (108KB minified) with ~40 lines.

/** Strip matching single or double quotes. */
function unquote(s: string): string {
  if (s.length >= 2 &&
      ((s[0] === '"' && s[s.length - 1] === '"') ||
       (s[0] === "'" && s[s.length - 1] === "'"))) {
    return s.slice(1, -1);
  }
  return s;
}

/**
 * Strip a trailing comment from a raw YAML line, respecting quotes.
 * A `#` only starts a comment when preceded by whitespace and not
 * inside single or double quotes.
 */
function stripComment(raw: string): string {
  let inSQ = false;
  let inDQ = false;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === "'" && !inDQ) { inSQ = !inSQ; continue; }
    if (ch === '"' && !inSQ) { inDQ = !inDQ; continue; }
    if (ch === "#" && !inSQ && !inDQ && (i === 0 || raw[i - 1] === " " || raw[i - 1] === "\t")) {
      return raw.slice(0, i);
    }
  }
  return raw;
}

/**
 * Parse a simple YAML document into a plain object.
 *
 * Supported structure (two indent levels max):
 *   top_key:
 *     sub_key: value        -> { top_key: { sub_key: "value" } }
 *     sub_key:
 *       - item              -> { top_key: { sub_key: ["item"] } }
 *
 * Returns undefined for empty/comment-only documents. Throws on
 * unrecoverable syntax errors.
 */
export function parseSimpleYaml(text: string): Record<string, Record<string, string | string[]>> | undefined {
  const result: Record<string, Record<string, string | string[]>> = {};
  let section: Record<string, string | string[]> | null = null;
  let sectionKey: string | null = null;
  let arrayKey: string | null = null;
  let array: string[] | null = null;

  for (const raw of text.split("\n")) {
    const line = stripComment(raw).trimEnd();
    if (line === "" || line === "---") continue;

    const indent = line.length - line.trimStart().length;
    const content = line.trimStart();

    if (indent === 0) {
      // Flush pending array
      if (arrayKey && array && section) section[arrayKey] = array;
      arrayKey = null;
      array = null;
      // New top-level section
      if (!content.endsWith(":")) {
        throw new Error(`expected top-level key, got: ${content}`);
      }
      sectionKey = content.slice(0, -1).trim();
      section = {};
      result[sectionKey] = section;
    } else if (content.startsWith("- ")) {
      // Array item
      if (!array) array = [];
      array.push(unquote(content.slice(2).trim()));
    } else {
    let colonIdx: number;
    if (content.startsWith('"') || content.startsWith("'")) {
      const quote = content[0];
      const closeIdx = content.indexOf(quote, 1);
      colonIdx = closeIdx >= 0 ? content.indexOf(":", closeIdx + 1) : content.indexOf(":");
    } else {
      colonIdx = content.indexOf(":");
    }
    if (colonIdx < 0) continue;
    const key = unquote(content.slice(0, colonIdx).trim());
    const val = content.slice(colonIdx + 1).trim();
      // Flush any pending array from a previous sub-key
      if (arrayKey && array && section) section[arrayKey] = array;
      if (val === "") {
        // Sub-key with no value: next lines will be array items
        arrayKey = key;
        array = [];
      } else {
        arrayKey = null;
        array = null;
        if (section) section[key] = unquote(val);
      }
    }
  }

  // Flush final pending state
  if (arrayKey && array && section) section[arrayKey] = array;

  return Object.keys(result).length > 0 ? result : undefined;
}
