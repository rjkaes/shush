import { describe, test, expect } from "bun:test";
import { parseConfigYaml, mergeConfigs, loadConfigFile, loadConfig } from "../src/config.js";
import { EMPTY_CONFIG } from "../src/types.js";
import type { ShushConfig } from "../src/types.js";

describe("parseConfigYaml", () => {
  test("parses valid config with all sections", () => {
    const yaml = `
actions:
  filesystem_delete: ask
  git_history_rewrite: block
sensitive_paths:
  ~/.kube: ask
  ~/Documents/taxes: block
classify:
  database_destructive:
    - "psql -c DROP"
    - "mysql -e DROP"
`;
    const config = parseConfigYaml(yaml);
    expect(config.actions).toEqual({
      filesystem_delete: "ask",
      git_history_rewrite: "block",
    });
    expect(config.sensitivePaths).toEqual({
      "~/.kube": "ask",
      "~/Documents/taxes": "block",
    });
    expect(config.classify).toEqual({
      database_destructive: ["psql -c DROP", "mysql -e DROP"],
    });
  });

  test("returns EMPTY_CONFIG for empty string", () => {
    expect(parseConfigYaml("")).toEqual(EMPTY_CONFIG);
  });

  test("returns EMPTY_CONFIG for null/undefined YAML parse", () => {
    expect(parseConfigYaml("---")).toEqual(EMPTY_CONFIG);
  });

  test("skips invalid decision values in actions", () => {
    const yaml = `
actions:
  filesystem_delete: ask
  git_safe: invalid_value
`;
    const config = parseConfigYaml(yaml);
    expect(config.actions).toEqual({ filesystem_delete: "ask" });
  });

  test("skips invalid decision values in sensitive_paths", () => {
    const yaml = `
sensitive_paths:
  ~/.kube: ask
  ~/bad: nope
`;
    const config = parseConfigYaml(yaml);
    expect(config.sensitivePaths).toEqual({ "~/.kube": "ask" });
  });

  test("skips classify entries that are not string arrays", () => {
    const yaml = `
classify:
  good_type:
    - "psql -c DROP"
  bad_type: "not an array"
`;
    const config = parseConfigYaml(yaml);
    expect(config.classify).toEqual({ good_type: ["psql -c DROP"] });
  });

  test("handles config with only actions section", () => {
    const yaml = `
actions:
  lang_exec: allow
`;
    const config = parseConfigYaml(yaml);
    expect(config.actions).toEqual({ lang_exec: "allow" });
    expect(config.sensitivePaths).toEqual({});
    expect(config.classify).toEqual({});
  });
});

describe("mergeConfigs", () => {
  test("overlay tightens actions", () => {
    const base: ShushConfig = {
      actions: { lang_exec: "allow" },
      sensitivePaths: {},
      classify: {},
    };
    const overlay: ShushConfig = {
      actions: { lang_exec: "ask" },
      sensitivePaths: {},
      classify: {},
    };
    const merged = mergeConfigs(base, overlay);
    expect(merged.actions.lang_exec).toBe("ask");
  });

  test("overlay cannot relax actions", () => {
    const base: ShushConfig = {
      actions: { filesystem_delete: "block" },
      sensitivePaths: {},
      classify: {},
    };
    const overlay: ShushConfig = {
      actions: { filesystem_delete: "allow" },
      sensitivePaths: {},
      classify: {},
    };
    const merged = mergeConfigs(base, overlay);
    expect(merged.actions.filesystem_delete).toBe("block");
  });

  test("overlay tightens sensitive_paths", () => {
    const base: ShushConfig = {
      actions: {},
      sensitivePaths: { "~/.kube": "ask" },
      classify: {},
    };
    const overlay: ShushConfig = {
      actions: {},
      sensitivePaths: { "~/.kube": "block" },
      classify: {},
    };
    const merged = mergeConfigs(base, overlay);
    expect(merged.sensitivePaths["~/.kube"]).toBe("block");
  });

  test("overlay cannot relax sensitive_paths", () => {
    const base: ShushConfig = {
      actions: {},
      sensitivePaths: { "~/.kube": "block" },
      classify: {},
    };
    const overlay: ShushConfig = {
      actions: {},
      sensitivePaths: { "~/.kube": "allow" },
      classify: {},
    };
    const merged = mergeConfigs(base, overlay);
    expect(merged.sensitivePaths["~/.kube"]).toBe("block");
  });

  test("overlay adds new sensitive_paths", () => {
    const base: ShushConfig = {
      actions: {},
      sensitivePaths: { "~/.kube": "ask" },
      classify: {},
    };
    const overlay: ShushConfig = {
      actions: {},
      sensitivePaths: { "~/taxes": "block" },
      classify: {},
    };
    const merged = mergeConfigs(base, overlay);
    expect(merged.sensitivePaths["~/.kube"]).toBe("ask");
    expect(merged.sensitivePaths["~/taxes"]).toBe("block");
  });

  test("classify entries are additive (union)", () => {
    const base: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: { db_destructive: ["psql -c DROP"] },
    };
    const overlay: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: { db_destructive: ["mysql -e DROP"], other: ["foo bar"] },
    };
    const merged = mergeConfigs(base, overlay);
    expect(merged.classify.db_destructive).toEqual(["psql -c DROP", "mysql -e DROP"]);
    expect(merged.classify.other).toEqual(["foo bar"]);
  });

  test("merging two empty configs returns empty", () => {
    const merged = mergeConfigs(EMPTY_CONFIG, EMPTY_CONFIG);
    expect(merged).toEqual(EMPTY_CONFIG);
  });
});

import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("loadConfigFile", () => {
  test("returns null for missing file", () => {
    const result = loadConfigFile("/nonexistent/path/config.yaml");
    expect(result).toBeNull();
  });

  test("parses existing YAML file", () => {
    const dir = mkdtempSync(join(tmpdir(), "shush-test-"));
    const filePath = join(dir, "config.yaml");
    writeFileSync(filePath, "actions:\n  lang_exec: block\n");
    try {
      const result = loadConfigFile(filePath);
      expect(result).not.toBeNull();
      expect(result!.actions.lang_exec).toBe("block");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("returns EMPTY_CONFIG for malformed YAML file", () => {
    const dir = mkdtempSync(join(tmpdir(), "shush-test-"));
    const filePath = join(dir, "config.yaml");
    writeFileSync(filePath, "{{{{not yaml");
    try {
      const result = loadConfigFile(filePath);
      expect(result).not.toBeNull();
      expect(result).toEqual(EMPTY_CONFIG);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("loadConfig", () => {
  test("returns EMPTY_CONFIG when no config files exist", () => {
    const dir = mkdtempSync(join(tmpdir(), "shush-test-"));
    try {
      const result = loadConfig(dir, join(dir, "no-such-global.yaml"));
      expect(result).toEqual(EMPTY_CONFIG);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("loads project config from .shush.yaml", () => {
    const dir = mkdtempSync(join(tmpdir(), "shush-test-"));
    writeFileSync(join(dir, ".shush.yaml"), "actions:\n  lang_exec: block\n");
    try {
      const result = loadConfig(dir, join(dir, "no-such-global.yaml"));
      expect(result.actions.lang_exec).toBe("block");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("merges global and project with tightening", () => {
    const dir = mkdtempSync(join(tmpdir(), "shush-test-"));
    const globalPath = join(dir, "global.yaml");
    writeFileSync(globalPath, "actions:\n  lang_exec: ask\n");
    writeFileSync(join(dir, ".shush.yaml"), "actions:\n  lang_exec: allow\n");
    try {
      // Project tries to relax -> should stay at "ask"
      const result = loadConfig(dir, globalPath);
      expect(result.actions.lang_exec).toBe("ask");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("project config cannot relax hardcoded defaults", () => {
    const dir = mkdtempSync(join(tmpdir(), "shush-test-"));
    // No global config; project tries to set obfuscated (hardcoded: "block") to "allow"
    writeFileSync(join(dir, ".shush.yaml"), "actions:\n  obfuscated: allow\n");
    try {
      const result = loadConfig(dir, join(dir, "no-such-global.yaml"));
      expect(result.actions.obfuscated).toBe("block");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

import { getPolicy, classifyTokens } from "../src/taxonomy.js";

describe("getPolicy with config", () => {
  test("config overrides default policy", () => {
    const config: ShushConfig = {
      actions: { lang_exec: "block" },
      sensitivePaths: {},
      classify: {},
    };
    expect(getPolicy("lang_exec", config)).toBe("block");
  });

  test("config can relax hardcoded default", () => {
    const config: ShushConfig = {
      actions: { lang_exec: "allow" },
      sensitivePaths: {},
      classify: {},
    };
    // Global config overrides the hardcoded default for lang_exec ("ask")
    expect(getPolicy("lang_exec", config)).toBe("allow");
  });

  test("no config returns hardcoded default", () => {
    expect(getPolicy("lang_exec")).toBe("ask");
  });
});

describe("classifyTokens with config", () => {
  test("config classify entries match before built-in table", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: { database_destructive: ["psql -c DROP"] },
    };
    expect(classifyTokens(["psql", "-c", "DROP", "TABLE"], config)).toBe("database_destructive");
  });

  test("without config, psql is classified normally", () => {
    // psql without config should hit built-in table (likely "unknown")
    const result = classifyTokens(["psql", "-c", "DROP", "TABLE"]);
    expect(result).not.toBe("database_destructive");
  });
});

import { isSensitive, resolvePath } from "../src/path-guard.js";

describe("isSensitive with config", () => {
  test("config adds new sensitive path", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: { "~/.kube": "ask" },
      classify: {},
    };
    const resolved = resolvePath("~/.kube/config");
    const result = isSensitive(resolved, config);
    expect(result.matched).toBe(true);
    expect(result.policy).toBe("ask");
    expect(result.pattern).toBe("~/.kube");
  });

  test("built-in sensitive paths still work with config", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: { "~/.kube": "ask" },
      classify: {},
    };
    const resolved = resolvePath("~/.ssh/id_rsa");
    const result = isSensitive(resolved, config);
    expect(result.matched).toBe(true);
    expect(result.policy).toBe("block");
  });

  test("no config returns built-in result only", () => {
    const resolved = resolvePath("~/.kube/config");
    const result = isSensitive(resolved);
    expect(result.matched).toBe(false);
  });
});

describe("cross-platform config path", () => {
  test("loadConfig uses a valid absolute path for global config", () => {
    const { homedir } = require("node:os");
    const path = require("node:path");
    const home = homedir();
    // loadConfig with null projectRoot returns global config (file may not exist, that's OK)
    const config = loadConfig(null);
    // Verify homedir is non-empty and absolute (guards against process.env.HOME being undefined)
    expect(home.length).toBeGreaterThan(0);
    expect(path.isAbsolute(home)).toBe(true);
    // Config should parse without error (returns EMPTY_CONFIG if file missing)
    expect(config).toHaveProperty("actions");
    expect(config).toHaveProperty("sensitivePaths");
    expect(config).toHaveProperty("classify");
  });
});
import { classifyCommand } from "../src/bash-guard.js";
import { checkPath } from "../src/path-guard.js";

describe("end-to-end: config affects classifyCommand", () => {
  test("custom classify pattern changes action type", () => {
    const config: ShushConfig = {
      actions: { database_destructive: "block" },
      sensitivePaths: {},
      classify: { database_destructive: ["psql -c DROP"] },
    };
    const result = classifyCommand("psql -c DROP TABLE users", 0, config);
    expect(result.finalDecision).toBe("block");
    expect(result.stages[0].actionType).toBe("database_destructive");
  });

  test("action override tightens policy for built-in command", () => {
    const config: ShushConfig = {
      actions: { filesystem_delete: "block" },
      sensitivePaths: {},
      classify: {},
    };
    const result = classifyCommand("rm -rf /tmp/test", 0, config);
    expect(result.finalDecision).toBe("block");
  });

  test("no config gives default behavior", () => {
    const result = classifyCommand("ls -la", 0);
    expect(result.finalDecision).toBe("allow");
  });
});

describe("end-to-end: config affects path checks", () => {
  test("config sensitive path triggers ask on checkPath", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: { "~/.kube": "ask" },
      classify: {},
    };
    const result = checkPath("Read", "~/.kube/config", config);
    expect(result).not.toBeNull();
    expect(result!.decision).toBe("ask");
  });
});
