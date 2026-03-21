// plugins/opencode.ts
//
// OpenCode plugin entry point. Wraps shush's classification engine
// in an OpenCode tool.execute.before hook.

import type { Plugin } from "@opencode-ai/plugin";
import { evaluate } from "../src/evaluate.js";
import { loadConfig } from "../src/config.js";

const TOOL_NAME_MAP: Record<string, string> = {
  bash: "Bash",
  read: "Read",
  write: "Write",
  edit: "Edit",
  glob: "Glob",
  grep: "Grep",
};

const plugin: Plugin = async (ctx) => {
  return {
    "tool.execute.before": async (input, output) => {
      const config = loadConfig(ctx.directory);
      const toolName = TOOL_NAME_MAP[input.tool] ?? input.tool;
      const result = evaluate(
        { toolName, toolInput: output.args as Record<string, unknown>, cwd: ctx.directory },
        config,
      );

      if (result.decision === "block") {
        throw new Error(`shush(block) ${toolName}: ${result.reason}`);
      }
      if (result.decision === "ask") {
        throw new Error(`shush(ask) ${toolName}: ${result.reason}`);
      }
      // "allow" and "context": no-op, let execution proceed.
      // OpenCode has no equivalent of Claude Code's "context" level.
    },
  };
};

export default plugin;
