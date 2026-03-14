import { classifyCommand } from "../src/bash-guard.js";
import { checkPath, checkProjectBoundary } from "../src/path-guard.js";
import { scanContent, isCredentialSearch, formatContentMessage } from "../src/content-guard.js";
import { loadConfig } from "../src/config.js";
import type { HookInput, HookOutput, Decision, ShushConfig } from "../src/types.js";

/** Shared path + boundary + content check for file-writing tools. */
function checkFileWrite(
  toolName: string,
  filePath: string,
  content: string,
  projectRoot: string | null,
  config: ShushConfig,
): { decision: Decision; reason: string } {
  let decision: Decision = "allow";
  let reason = "";

  const pathResult = checkPath(toolName, filePath, config);
  if (pathResult) {
    decision = pathResult.decision;
    reason = pathResult.reason;
  }
  if (decision === "allow") {
    const boundaryResult = checkProjectBoundary(toolName, filePath, projectRoot);
    if (boundaryResult) {
      decision = boundaryResult.decision;
      reason = boundaryResult.reason;
    }
  }
  if (decision === "allow" || decision === "context") {
    const matches = scanContent(content);
    if (matches.length > 0) {
      decision = "ask";
      reason = formatContentMessage(toolName, matches);
    }
  }
  return { decision, reason };
}

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

  let decision: Decision = "allow";
  let reason = "";

  switch (tool_name) {
    case "Bash": {
      const command = tool_input.command as string ?? "";
      const result = classifyCommand(command, 0, config);
      decision = result.finalDecision;
      reason = result.reason;
      break;
    }
    case "Read": {
      const filePath = tool_input.file_path as string ?? "";
      const pathResult = checkPath("Read", filePath, config);
      if (pathResult) {
        decision = pathResult.decision;
        reason = pathResult.reason;
      }
      break;
    }
    case "Write": {
      const result = checkFileWrite("Write", tool_input.file_path as string ?? "", tool_input.content as string ?? "", projectRoot, config);
      decision = result.decision;
      reason = result.reason;
      break;
    }
    case "Edit": {
      const result = checkFileWrite("Edit", tool_input.file_path as string ?? "", tool_input.new_string as string ?? "", projectRoot, config);
      decision = result.decision;
      reason = result.reason;
      break;
    }
    case "Glob": {
      const path = tool_input.path as string ?? "";
      if (path) {
        const pathResult = checkPath("Glob", path, config);
        if (pathResult) {
          decision = pathResult.decision;
          reason = pathResult.reason;
        }
      }
      break;
    }
    case "Grep": {
      const path = tool_input.path as string ?? "";
      const pattern = tool_input.pattern as string ?? "";
      if (path) {
        const pathResult = checkPath("Grep", path, config);
        if (pathResult) {
          decision = pathResult.decision;
          reason = pathResult.reason;
        }
      }
      // Credential search detection outside project
      if (decision === "allow" && isCredentialSearch(pattern)) {
        // TODO: check if path is outside project root
        // For now, always ask for credential searches
        decision = "ask";
        reason = "Grep pattern looks like credential search";
      }
      break;
    }
  }

  // Silent allow — write nothing to stdout
  if (decision === "allow" || decision === "context") {
    process.exit(0);
  }

  // Optional debug logging (stderr is shown as "hook error" in Claude Code)
  if (process.env.SHUSH_DEBUG) {
    const timestamp = new Date().toISOString();
    process.stderr.write(
      `[${timestamp}] shush ${decision} ${tool_name}: ${reason}\n`
    );
  }

  // Map our decision to Claude Code's permission model
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
  process.exit(2);
});
