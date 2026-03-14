// src/bash-guard.ts
//
// Orchestrates the full bash command classification pipeline:
// extractStages -> classify each stage -> check composition -> aggregate.

import { extractStages } from "./ast-walk.js";
import { classifyTokens, SHELL_WRAPPERS, getPolicy, FILESYSTEM_WRITE } from "./taxonomy.js";
import { classifyWithFlags, stripGitGlobalFlags } from "./classify.js";
import { checkComposition } from "./composition.js";
import { checkPath } from "./path-guard.js";
import type { ClassifyResult, StageResult, Decision, ShushConfig } from "./types.js";
import { stricter } from "./types.js";

const MAX_UNWRAP_DEPTH = 3;

/**
 * Classify a single stage's tokens, returning an action type and decision.
 * Tries flag-aware classifiers first, falls back to prefix table.
 */
function classifyStage(tokens: string[], config?: ShushConfig): { actionType: string; decision: Decision } {
  // Flag-aware classifiers (git, curl, wget, etc.)
  const flagResult = classifyWithFlags(tokens);
  if (flagResult) {
    const policy = getPolicy(flagResult, config);
    return { actionType: flagResult, decision: policy };
  }
  // Prefix table fallback — use flag-stripped tokens so that e.g.
  // `git -C /path commit` matches the `["git", "commit"]` trie entry.
  const normalized = tokens[0] === "git" ? stripGitGlobalFlags(tokens) : tokens;
  const actionType = classifyTokens(normalized, config);
  const decision = getPolicy(actionType, config);
  return { actionType, decision };
}

/**
 * Classify a full bash command string. Parses into stages, classifies each,
 * checks composition rules, and returns the most restrictive decision.
 * Handles shell unwrapping (bash -c, sh -c) with depth limit.
 */
export function classifyCommand(command: string, depth = 0, config?: ShushConfig): ClassifyResult {
  if (!command.trim()) {
    return {
      command,
      stages: [],
      finalDecision: "allow",
      reason: "",
    };
  }

  const stages = extractStages(command);

  // Shell unwrapping: if the entire command is `bash -c '...'`, classify the inner command.
  if (
    depth < MAX_UNWRAP_DEPTH &&
    stages.length === 1 &&
    stages[0].tokens.length >= 3 &&
    SHELL_WRAPPERS.has(stages[0].tokens[0]) &&
    stages[0].tokens[1] === "-c"
  ) {
    const innerCommand = stages[0].tokens.slice(2).join(" ");
    return classifyCommand(innerCommand, depth + 1, config);
  }

  // Classify each stage. xargs is unwrapped to expose the inner command
  // without mutating the original stage tokens.
  const stageResults: StageResult[] = stages.map((stage) => {
    const tokens = (stage.tokens[0] === "xargs" && stage.tokens.length >= 2)
      ? unwrapXargs(stage.tokens)
      : stage.tokens;
    let { actionType, decision } = classifyStage(tokens, config);
    let reason = decision !== "allow" ? `${tokens[0]}: ${actionType}` : "";

    // A redirect means this stage writes to a file, regardless of what
    // the command itself would normally be classified as.
    if (stage.redirectTarget) {
      const writePolicy = getPolicy(FILESYSTEM_WRITE, config);
      const combined = stricter(decision, writePolicy);
      if (combined !== decision) {
        actionType = FILESYSTEM_WRITE;
        decision = combined;
        reason = `${tokens[0]} redirects to ${stage.redirectTarget}: ${FILESYSTEM_WRITE}`;
      }

      // Check redirect target against sensitive/hook paths
      const pathResult = checkPath("Bash", stage.redirectTarget, config);
      if (pathResult) {
        decision = stricter(decision, pathResult.decision);
        reason = pathResult.reason;
      }
    }

    return {
      tokens: stage.tokens,
      actionType,
      defaultPolicy: decision,
      decision,
      reason,
    };
  });

  // Check composition rules (pipe chains, etc.)
  const [compDecision, compReason, compRule] = checkComposition(stageResults, stages, config);

  // Aggregate: most restrictive stage decision
  let finalDecision: Decision = "allow";
  let reason = "";
  for (const sr of stageResults) {
    if (sr.decision !== "allow") {
      finalDecision = stricter(finalDecision, sr.decision);
      reason = sr.reason;
    }
  }

  // Composition rules may override
  if (compDecision) {
    finalDecision = stricter(finalDecision, compDecision);
    reason = compReason;
  }

  return {
    command,
    stages: stageResults,
    finalDecision,
    reason,
    compositionRule: compRule || undefined,
  };
}

// xargs flags that consume a following argument
const XARGS_VALUE_FLAGS = new Set(["-I", "-L", "-n", "-P", "-s", "-R", "-S"]);

/**
 * Strip xargs and its flags, returning the inner command tokens.
 * e.g. ["xargs", "-0", "grep", "-l", "pattern"] -> ["grep", "-l", "pattern"]
 */
function unwrapXargs(tokens: string[]): string[] {
  let i = 1; // skip "xargs"
  while (i < tokens.length) {
    const tok = tokens[i];
    // Value flags: -I {}, -n 10, etc.
    if (XARGS_VALUE_FLAGS.has(tok)) {
      i += 2;
      continue;
    }
    // Joined value flags: -I{}, -P4, etc.
    if (tok.length > 2 && tok.startsWith("-") && !tok.startsWith("--") && XARGS_VALUE_FLAGS.has(tok.slice(0, 2))) {
      i += 1;
      continue;
    }
    // Boolean flags: -0, -t, -p, -r, --no-run-if-empty, -d, etc.
    if (tok.startsWith("-")) {
      i += 1;
      continue;
    }
    // First non-flag token is the start of the inner command
    break;
  }
  // If we consumed everything, xargs with no command defaults to /bin/echo
  if (i >= tokens.length) return ["echo"];
  return tokens.slice(i);
}
