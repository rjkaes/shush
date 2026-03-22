// src/bash-guard.ts
//
// Orchestrates the full bash command classification pipeline:
// extractStages -> classify each stage -> check composition -> aggregate.

import { extractProcessSubs, extractStages } from "./ast-walk.js";
import { classifyTokens, SHELL_WRAPPERS, getPolicy, FILESYSTEM_WRITE, LANG_EXEC } from "./taxonomy.js";
import { classifyWithFlags, stripGitGlobalFlags, extractGitDirPaths, classifyScriptExec } from "./classify.js";
import { checkComposition } from "./composition.js";
import { checkPath } from "./path-guard.js";
import type { ClassifyResult, StageResult, Decision, ShushConfig } from "./types.js";
import { stricter } from "./types.js";

const MAX_UNWRAP_DEPTH = 3;

// ==============================================================================
// Command Wrapper Unwrapping
// ==============================================================================

// Commands that wrap another command. We strip them and their flags to classify
// the inner command. Each entry maps the wrapper name to a set of flags that
// consume a following argument (value flags).
interface WrapperSpec {
  valueFlags: Set<string>;
  /** Skip tokens matching VAR=value (used by `env`). */
  skipAssignments?: boolean;
  /** Skip the first non-flag positional (used by `timeout` for the duration arg). */
  skipFirstPositional?: RegExp;
  /** Fallback tokens when the wrapper has no inner command (used by `xargs` → echo). */
  defaultInner?: string[];
}

// PowerShell value flags: flags that take a separate argument.
// -Command/-c, -File/-f, and -EncodedCommand/-e/-ec are intentionally excluded
// so the next positional token (the script, command string, or opaque payload)
// becomes the classified inner command.
const PWSH_VALUE_FLAGS = new Set([
  "-ExecutionPolicy", "-ep",
  "-ConfigurationName",
  "-CustomPipeName",
  "-InputFormat", "-if",
  "-OutputFormat", "-of",
  "-SettingsFile",
  "-WorkingDirectory", "-wd",
]);

const COMMAND_WRAPPERS: Record<string, WrapperSpec> = {
  xargs:   { valueFlags: new Set(["-I", "-L", "-n", "-P", "-s", "-R", "-S", "-E"]), defaultInner: ["echo"] },
  nice:    { valueFlags: new Set(["-n", "--adjustment"]) },
  nohup:   { valueFlags: new Set([]) },
  timeout: { valueFlags: new Set(["-k", "--kill-after", "-s", "--signal"]), skipFirstPositional: /^[\d.]+[smhd]?$/ },
  stdbuf:  { valueFlags: new Set(["-i", "--input", "-o", "--output", "-e", "--error"]) },
  ionice:  { valueFlags: new Set(["-c", "--class", "-n", "--classdata", "-t"]) },
  env:     { valueFlags: new Set(["-u", "--unset", "-C", "--chdir", "-S", "--split-string"]), skipAssignments: true },
  pwsh:       { valueFlags: PWSH_VALUE_FLAGS },
  powershell: { valueFlags: PWSH_VALUE_FLAGS },
};

/**
 * Strip a command wrapper and its flags, returning the inner command tokens.
 * Returns null if the command is not a known wrapper (or has no inner command
 * and no defaultInner fallback).
 */
function unwrapCommandWrapper(tokens: string[]): string[] | null {
  const wrapper = COMMAND_WRAPPERS[tokens[0]];
  if (!wrapper) return null;

  let i = 1; // skip the wrapper itself
  let sawFirstPositional = false;
  while (i < tokens.length) {
    const tok = tokens[i];

    // Skip inline assignments (VAR=value) when the wrapper supports it
    if (wrapper.skipAssignments && tok.includes("=") && !tok.startsWith("-")) {
      i += 1;
      continue;
    }

    // Value flags: consume the next argument too
    if (wrapper.valueFlags.has(tok)) {
      i += 2;
      continue;
    }

    // Joined value flags: -n5, -c2, -I{}, -P4, etc.
    if (tok.length > 2 && tok.startsWith("-") && !tok.startsWith("--") && wrapper.valueFlags.has(tok.slice(0, 2))) {
      i += 1;
      continue;
    }

    // Boolean flags (anything starting with -)
    if (tok.startsWith("-")) {
      i += 1;
      continue;
    }

    // Skip the first non-flag positional when the wrapper has a leading arg
    // (e.g., timeout's duration: `timeout 5s rm foo`)
    if (wrapper.skipFirstPositional && !sawFirstPositional && wrapper.skipFirstPositional.test(tok)) {
      sawFirstPositional = true;
      i += 1;
      continue;
    }

    // First non-flag, non-assignment token is the start of the inner command
    break;
  }

  if (i >= tokens.length) return wrapper.defaultInner ?? null;
  return tokens.slice(i);
}

// ==============================================================================
// Env Var Exec-Sink Detection
// ==============================================================================

// Env vars whose values are executed by the shell or program they're set on.
// Setting these to an attacker-controlled value is equivalent to arbitrary exec.
const EXEC_SINK_ENV_VARS = new Set([
  "PAGER",
  "GIT_PAGER",
  "EDITOR",
  "VISUAL",
  "GIT_EDITOR",
  "GIT_SSH_COMMAND",
  "GIT_EXTERNAL_DIFF",
  "GIT_ASKPASS",
  "GIT_PROXY_COMMAND",
  "BROWSER",
  "FCEDIT",
  "LESSEDIT",
  "LESSOPEN",
  "LESSCLOSE",
  "MANPAGER",
  "PROMPT_COMMAND",
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
]);
/**
 * Classify a single stage's tokens, returning an action type and decision.
 * Tries flag-aware classifiers first, falls back to prefix table.
 */
function classifyStage(tokens: string[], config?: ShushConfig): { actionType: string; decision: Decision } {
  // Bare assignments (e.g., `FOO=bar`) produce empty tokens. The assignment
  // itself is harmless; any command substitution in the value is extracted
  // and classified separately by bash-guard's cmdSubs handling.
  if (tokens.length === 0) {
    return { actionType: "filesystem_read", decision: "allow" };
  }
  // Flag-aware classifiers (git, curl, wget, etc.)
  const flagResult = classifyWithFlags(tokens);
  if (flagResult) {
    const policy = getPolicy(flagResult, config);
    return { actionType: flagResult, decision: policy };
  }
  // Prefix table fallback — use flag-stripped tokens so that e.g.
  // `git -C /path commit` matches the `["git", "commit"]` trie entry.
  const normalized = tokens[0] === "git" ? stripGitGlobalFlags(tokens) : tokens;
  let actionType = classifyTokens(normalized, config);
  // When the trie has no match, check for interpreter script execution
  // (e.g., node script.js, python app.py). Runs after the trie so that
  // specific subcommands (deno test, python -m pytest) take precedence.
  if (actionType === "unknown") {
    actionType = classifyScriptExec(tokens) ?? actionType;
  }
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

  // Extract process substitutions >(cmd)/<(cmd) before parsing.
  // Inner commands are classified separately and composed into the result.
  // Guard: skip the char-by-char scan when no process sub markers are present.
  const hasProcSub = command.includes(">(") || command.includes("<(");
  const { cleaned, subs } = hasProcSub
    ? extractProcessSubs(command)
    : { cleaned: command, subs: [] as string[] };
  const { stages, cmdSubs } = extractStages(cleaned);

  // Shell unwrapping: if the entire command is `bash [-x] -c '...'`, classify
  // the inner command. Flags before -c (e.g., -x, -v) are skipped.
  if (
    depth < MAX_UNWRAP_DEPTH &&
    stages.length === 1 &&
    stages[0].tokens.length >= 3 &&
    SHELL_WRAPPERS.has(stages[0].tokens[0])
  ) {
    const toks = stages[0].tokens;
    const cIdx = toks.indexOf("-c");
    if (cIdx >= 1 && cIdx + 1 < toks.length) {
      const innerCommand = toks.slice(cIdx + 1).join(" ");
      return classifyCommand(innerCommand, depth + 1, config);
    }
  }

  // Classify each stage. Command wrappers (xargs, nice, nohup, timeout, etc.)
  // are unwrapped to expose the inner command without mutating the original
  // stage tokens.
  const stageResults: StageResult[] = stages.map((stage) => {
    const unwrapped = unwrapCommandWrapper(stage.tokens);
    const tokens = unwrapped ?? stage.tokens;

    let { actionType, decision } = classifyStage(tokens, config);
    let reason = decision !== "allow" ? `${tokens[0]}: ${actionType}` : "";

    // Env var assignments that target exec sinks (PAGER, EDITOR, etc.)
    // escalate to at least lang_exec policy, since the value will be executed.
    if (stage.envAssignments) {
      for (const assignment of stage.envAssignments) {
        const eqIdx = assignment.indexOf("=");
        if (eqIdx < 0) continue;
        const varName = assignment.slice(0, eqIdx);
        if (EXEC_SINK_ENV_VARS.has(varName)) {
          const execPolicy = getPolicy(LANG_EXEC, config);
          const combined = stricter(decision, execPolicy);
          if (combined !== decision) {
            actionType = LANG_EXEC;
            decision = combined;
            reason = `${varName}= sets exec sink: ${LANG_EXEC}`;
          }
        }
      }
    }

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

    // git -C / --git-dir / --work-tree paths control where git operates;
    // check them against sensitive-path and project-boundary rules.
    if (tokens[0] === "git") {
      for (const dirPath of extractGitDirPaths(tokens)) {
        const pathResult = checkPath("Bash", dirPath, config);
        if (pathResult) {
          decision = stricter(decision, pathResult.decision);
          reason = pathResult.reason;
        }
      }
    }

    return {
      tokens: stage.tokens,
      actionType,
      decision,
      reason,
    };
  });

  // Check composition rules (pipe chains, etc.)
  const [compDecision, compReason, compRule] = checkComposition(stageResults, stages, config);

  // Aggregate: most restrictive stage decision, keeping the reason
  // from whichever stage produced the strictest decision.
  let finalDecision: Decision = "allow";
  let reason = "";
  for (const sr of stageResults) {
    if (sr.decision !== "allow") {
      const combined = stricter(finalDecision, sr.decision);
      if (combined !== finalDecision || reason === "") {
        reason = sr.reason;
      }
      finalDecision = combined;
    }
  }

  // Composition rules may override
  if (compDecision) {
    finalDecision = stricter(finalDecision, compDecision);
    reason = compReason;
  }

  // Classify inner commands from process substitutions and command
  // substitutions. A dangerous inner command must escalate the decision.
  if (depth < MAX_UNWRAP_DEPTH) {
    for (const sub of [...subs, ...cmdSubs]) {
      const subResult = classifyCommand(sub, depth + 1, config);
      if (subResult.finalDecision !== "allow") {
        finalDecision = stricter(finalDecision, subResult.finalDecision);
        reason = subResult.reason;
      }
    }
  }

  return {
    command,
    stages: stageResults,
    finalDecision,
    reason,
    compositionRule: compRule || undefined,
  };
}
