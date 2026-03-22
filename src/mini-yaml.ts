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
    const line = raw.replace(/#.*$/, "").trimEnd();
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
      const colonIdx = content.indexOf(":");
      if (colonIdx < 0) continue;
      const key = content.slice(0, colonIdx).trim();
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
