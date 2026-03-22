// src/config.ts
//
// YAML config loading, validation, and merging.
// Global: ~/.config/shush/config.yaml
// Per-project: .shush.yaml (can only tighten)

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { parseSimpleYaml } from "./mini-yaml.js";
import { type Decision, type ShushConfig, EMPTY_CONFIG, STRICTNESS, stricter } from "./types.js";
import ACTION_TYPES from "../data/types.json";
import { DEFAULT_POLICIES, prefixMatch } from "./taxonomy.js";

const VALID_DECISIONS = new Set<string>(Object.keys(STRICTNESS));

/** Parse a YAML string into a validated ShushConfig. */
export function parseConfigYaml(text: string): ShushConfig {
  if (!text) return EMPTY_CONFIG;

  let doc: Record<string, Record<string, string | string[]>> | undefined;
  try {
    doc = parseSimpleYaml(text);
  } catch (err) {
    process.stderr.write(`shush: malformed config YAML, ignoring: ${err}\n`);
    return EMPTY_CONFIG;
  }

  if (!doc) return EMPTY_CONFIG;

  // Parse actions
  const actions: Record<string, Decision> = {};
  if (doc.actions) {
    for (const [key, val] of Object.entries(doc.actions)) {
      if (!(key in ACTION_TYPES)) {
        process.stderr.write(`shush: config: unknown action type "${key}", skipping\n`);
        continue;
      }
      if (typeof val === "string" && VALID_DECISIONS.has(val)) {
        actions[key] = val as Decision;
      } else {
        process.stderr.write(`shush: config: invalid decision "${val}" for action "${key}", skipping\n`);
      }
    }
  }

  // Parse sensitive_paths
  const sensitivePaths: Record<string, Decision> = {};
  if (doc.sensitive_paths) {
    for (const [key, val] of Object.entries(doc.sensitive_paths)) {
      if (typeof val === "string" && VALID_DECISIONS.has(val)) {
        sensitivePaths[key] = val as Decision;
      } else {
        process.stderr.write(`shush: config: invalid decision "${val}" for path "${key}", skipping\n`);
      }
    }
  }

  // Parse classify
  const classify: Record<string, string[]> = {};
  if (doc.classify) {
    for (const [key, val] of Object.entries(doc.classify)) {
      if (Array.isArray(val) && val.every((v) => typeof v === "string")) {
        classify[key] = val as string[];
      } else {
        process.stderr.write(`shush: config: classify "${key}" must be a string array, skipping\n`);
      }
    }
  }

  return { actions, sensitivePaths, classify };
}

/**
 * Merge an overlay config onto a base config with tightening semantics.
 * For actions and sensitive_paths: overlay can only make policies stricter
 * (so project config cannot relax global config). Note: this controls
 * inter-layer merge only. The merged result can still override hardcoded
 * defaults in either direction via getPolicy() — see loadConfig() for how
 * project configs are prevented from exploiting this.
 * For classify: overlay entries are additive (union of patterns).
 * Callers are responsible for pre-filtering untrusted classify entries
 * via filterClassifyTightenOnly() before passing them here.
 */
function mergeStricter(
  base: Record<string, Decision>,
  overlay: Record<string, Decision>,
): Record<string, Decision> {
  const result = { ...base };
  for (const [key, overlayVal] of Object.entries(overlay)) {
    result[key] = result[key] ? stricter(result[key], overlayVal) : overlayVal;
  }
  return result;
}

export function mergeConfigs(base: ShushConfig, overlay: ShushConfig): ShushConfig {
  const actions = mergeStricter(base.actions, overlay.actions);
  const sensitivePaths = mergeStricter(base.sensitivePaths, overlay.sensitivePaths);

  // Merge classify: additive union of patterns per action type
  const classify: Record<string, string[]> = {};
  const allKeys = new Set([...Object.keys(base.classify), ...Object.keys(overlay.classify)]);
  for (const key of allKeys) {
    const basePatterns = base.classify[key] ?? [];
    const overlayPatterns = overlay.classify[key] ?? [];
    // Deduplicate while preserving order
    const seen = new Set(basePatterns);
    const merged = [...basePatterns];
    for (const p of overlayPatterns) {
      if (!seen.has(p)) {
        merged.push(p);
        seen.add(p);
      }
    }
    classify[key] = merged;
  }

  return { actions, sensitivePaths, classify };
}

/** Load and parse a single config file. Returns null if file doesn't exist. */
export function loadConfigFile(filePath: string): ShushConfig | null {
  try {
    const text = readFileSync(filePath, "utf-8");
    return parseConfigYaml(text);
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    process.stderr.write(`shush: error reading config ${filePath}: ${err}\n`);
    return EMPTY_CONFIG;
  }
}


/**
 * Filter project classify entries to only allow tightening.
 *
 * For each pattern in the project config's classify section, look up
 * what the base (trie + global config) would classify those tokens as,
 * then compare policies. Only keep entries where the project's target
 * action type has a policy that is stricter-or-equal to the base
 * classification's policy.
 */
export function filterClassifyTightenOnly(
  projectClassify: Record<string, string[]>,
  baseClassify: Record<string, string[]>,
  effectiveActions: Record<string, Decision>,
): Record<string, string[]> {
  const filtered: Record<string, string[]> = {};
  for (const [targetActionType, patterns] of Object.entries(projectClassify)) {
    const targetPolicy = effectiveActions[targetActionType]
      ?? DEFAULT_POLICIES[targetActionType]
      ?? "ask";
    const kept: string[] = [];
    for (const pattern of patterns) {
      // If this pattern already exists in the base classify, allow it
      // (it came from the global config or built-in data).
      if (baseClassify[targetActionType]?.includes(pattern)) {
        kept.push(pattern);
        continue;
      }
      const tokens = pattern.split(/\s+/);
      // Look up the base classification via the trie
      const baseActionType = prefixMatch(tokens);
      const basePolicy = effectiveActions[baseActionType]
        ?? DEFAULT_POLICIES[baseActionType]
        ?? "ask";
      // Only keep if the target policy is at least as strict
      if (STRICTNESS[targetPolicy as Decision] >= STRICTNESS[basePolicy as Decision]) {
        kept.push(pattern);
      } else {
        process.stderr.write(
          `shush: project config classify: dropping "${pattern}" -> ${targetActionType} `
          + `(would loosen from ${baseActionType}/${basePolicy} to ${targetPolicy})\n`,
        );
      }
    }
    if (kept.length > 0) {
      filtered[targetActionType] = kept;
    }
  }
  return filtered;
}

const DEFAULT_GLOBAL_PATH = path.join(homedir(), ".config", "shush", "config.yaml");

/**
 * Load the effective config by merging global and per-project files.
 * @param projectRoot - project directory (for .shush.yaml lookup), or null
 * @param globalPath - override for global config path (for testing)
 */
export function loadConfig(
  projectRoot: string | null,
  globalPath: string = DEFAULT_GLOBAL_PATH,
): ShushConfig {
  const globalConfig = loadConfigFile(globalPath) ?? EMPTY_CONFIG;

  if (!projectRoot) return globalConfig;

  const projectPath = path.join(projectRoot, ".shush.yaml");
  const projectConfig = loadConfigFile(projectPath) ?? EMPTY_CONFIG;

  // Build effective base: for action types the project tries to override,
  // ensure the base includes the effective policy (global override or
  // hardcoded default). This prevents a malicious .shush.yaml from
  // loosening policies below the effective default.
  const baseActions: Record<string, Decision> = { ...globalConfig.actions };
  for (const key of Object.keys(projectConfig.actions)) {
    if (!(key in baseActions)) {
      const hardcoded = DEFAULT_POLICIES[key];
      if (hardcoded) baseActions[key] = hardcoded;
    }
  }
  const effectiveBase: ShushConfig = {
    actions: baseActions,
    sensitivePaths: globalConfig.sensitivePaths,
    classify: globalConfig.classify,
  };

  // Filter project classify entries: only allow tightening.
  const filteredClassify = filterClassifyTightenOnly(
    projectConfig.classify,
    globalConfig.classify,
    baseActions,
  );
  const filteredProject: ShushConfig = {
    ...projectConfig,
    classify: filteredClassify,
  };

  return mergeConfigs(effectiveBase, filteredProject);
}
