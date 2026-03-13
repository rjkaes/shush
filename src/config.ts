// src/config.ts
//
// YAML config loading, validation, and merging.
// Global: ~/.config/shush/config.yaml
// Per-project: .shush.yaml (can only tighten)

import { readFileSync } from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { type Decision, type ShushConfig, EMPTY_CONFIG, STRICTNESS, stricter } from "./types.js";

const VALID_DECISIONS = new Set<string>(Object.keys(STRICTNESS));

/** Parse a YAML string into a validated ShushConfig. */
export function parseConfigYaml(text: string): ShushConfig {
  if (!text) return EMPTY_CONFIG;

  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch {
    process.stderr.write("shush: malformed config YAML, ignoring\n");
    return EMPTY_CONFIG;
  }

  if (raw === null || raw === undefined || typeof raw !== "object") {
    return EMPTY_CONFIG;
  }

  const doc = raw as Record<string, unknown>;

  // Parse actions
  const actions: Record<string, Decision> = {};
  if (doc.actions && typeof doc.actions === "object") {
    for (const [key, val] of Object.entries(doc.actions as Record<string, unknown>)) {
      if (typeof val === "string" && VALID_DECISIONS.has(val)) {
        actions[key] = val as Decision;
      } else {
        process.stderr.write(`shush: config: invalid decision "${val}" for action "${key}", skipping\n`);
      }
    }
  }

  // Parse sensitive_paths
  const sensitivePaths: Record<string, Decision> = {};
  if (doc.sensitive_paths && typeof doc.sensitive_paths === "object") {
    for (const [key, val] of Object.entries(doc.sensitive_paths as Record<string, unknown>)) {
      if (typeof val === "string" && VALID_DECISIONS.has(val)) {
        sensitivePaths[key] = val as Decision;
      } else {
        process.stderr.write(`shush: config: invalid decision "${val}" for path "${key}", skipping\n`);
      }
    }
  }

  // Parse classify
  const classify: Record<string, string[]> = {};
  if (doc.classify && typeof doc.classify === "object") {
    for (const [key, val] of Object.entries(doc.classify as Record<string, unknown>)) {
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
 * For actions and sensitive_paths: overlay can only make policies stricter.
 * For classify: overlay entries are additive (union of patterns).
 */
export function mergeConfigs(base: ShushConfig, overlay: ShushConfig): ShushConfig {
  // Merge actions: stricter wins
  const actions: Record<string, Decision> = { ...base.actions };
  for (const [key, overlayVal] of Object.entries(overlay.actions)) {
    const baseVal = actions[key];
    actions[key] = baseVal ? stricter(baseVal, overlayVal) : overlayVal;
  }

  // Merge sensitive_paths: stricter wins
  const sensitivePaths: Record<string, Decision> = { ...base.sensitivePaths };
  for (const [key, overlayVal] of Object.entries(overlay.sensitivePaths)) {
    const baseVal = sensitivePaths[key];
    sensitivePaths[key] = baseVal ? stricter(baseVal, overlayVal) : overlayVal;
  }

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

const DEFAULT_GLOBAL_PATH = (() => {
  const { homedir } = require("node:os");
  return path.join(homedir(), ".config", "shush", "config.yaml");
})();

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

  return mergeConfigs(globalConfig, projectConfig);
}
