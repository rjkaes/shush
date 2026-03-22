import { evaluate } from "../src/evaluate.js";
import { loadConfig } from "../src/config.js";
import type { HookInput, HookOutput } from "../src/types.js";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf-8");
}

async function main() {
  const input: HookInput = JSON.parse(await readStdin());
  const { tool_name, tool_input } = input;
  const projectRoot = input.cwd ?? null;
  const config = loadConfig(projectRoot);

  const { decision, reason } = evaluate(
    { toolName: tool_name, toolInput: tool_input, cwd: projectRoot },
    config,
  );

  // Silent pass-through: both "allow" and "context" exit with no output.
  if (decision === "allow" || decision === "context") {
    process.exit(0);
  }

  if (process.env.SHUSH_DEBUG) {
    const timestamp = new Date().toISOString();
    process.stderr.write(
      `[${timestamp}] shush ${decision} ${tool_name}: ${reason}\n`,
    );
  }

  const permissionDecision = decision === "block" ? "deny" : "ask";

  const output: HookOutput = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision,
      permissionDecisionReason: `shush(${decision}) ${tool_name}: ${reason}`,
    },
  };

  process.stdout.write(JSON.stringify(output));
  process.exit(0);
}

main().catch((err) => {
  process.stderr.write(`shush: ${err}\n`);
  // Write a deny decision so Claude Code does not treat a crash as "allow".
  const failsafe: HookOutput = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: `shush: internal error: ${err}`,
    },
  };
  process.stdout.write(JSON.stringify(failsafe));
  process.exit(0);
});
