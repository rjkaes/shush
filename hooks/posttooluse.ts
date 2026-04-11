import { loadConfig } from "../src/config.js";
import { matchAfterMessage } from "../src/after-messages.js";
import type { HookInput } from "../src/types.js";

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

  // Only process Bash commands for after_messages
  if (tool_name !== "Bash") {
    process.exit(0);
  }

  const command = (tool_input.command as string) ?? "";
  const message = matchAfterMessage(command, config);

  if (message) {
    // Output the message as a hook response so the AI sees it
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        permissionDecisionReason: `shush: ${message}`,
      },
    }));
  }

  process.exit(0);
}

main().catch((err) => {
  process.stderr.write(`shush(posttooluse): ${err}\n`);
  process.exit(0);
});
