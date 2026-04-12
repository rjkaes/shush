// src/bash-guard.ts
//
// Orchestrates the full bash command classification pipeline:
// extractStages -> classify each stage -> check composition -> aggregate.

import { extractProcessSubs, extractStages } from "./ast-walk.js";
import { classifyTokens, isShellWrapper, isExecSink, getPolicy, FILESYSTEM_READ, FILESYSTEM_WRITE, LANG_EXEC, UNKNOWN } from "./taxonomy.js";
import { checkFlagRules } from "./flag-rules.js";
import { lookup, checkDangerousGitConfig, stripGitGlobalFlags, extractGitDirPaths, classifyScriptExec } from "./classifiers/index.js";
import { checkComposition } from "./composition.js";
import { globMatch } from "./types.js";
import { checkPath } from "./path-guard.js";
import type { ClassifyResult, StageResult, Decision, ShushConfig } from "./types.js";
import { stricter, asFinal, cmdBasename } from "./types.js";

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
  command: { valueFlags: new Set([]) },
  sudo:    { valueFlags: new Set(["-u", "--user", "-g", "--group", "-C", "--close-from", "-D", "--chdir", "-r", "--role", "-t", "--type", "--host", "--other-user"]), skipAssignments: true },
  doas:    { valueFlags: new Set(["-u", "-C"]) },
  busybox: { valueFlags: new Set([]) },
  entr:    { valueFlags: new Set([]) },
  watchexec: { valueFlags: new Set(["-w", "--watch", "-e", "--exts", "-i", "--ignore", "-f", "--filter", "-d", "--debounce", "-s", "--signal", "--shell", "--project-origin", "--workdir", "--emit-events-to", "--color", "--completions"]) },
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
/** Redirect targets that are device-special and don't create real files. */
const SAFE_REDIRECT_TARGETS = new Set([
  "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin",
]);

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
 * Pipeline: flag rules -> procedural classifiers -> trie -> script-exec fallback.
 */
/** Docker exec/run flags that consume the next token as a value. */
const DOCKER_VALUE_FLAGS = new Set([
  "-u", "--user", "-w", "--workdir", "-e", "--env",
  "--env-file", "--name", "--network", "--pid", "--platform",
  "--runtime", "--volumes-from", "-v", "--volume",
  "--mount", "-p", "--publish", "--label", "-l",
  "--memory", "-m", "--cpus", "--entrypoint",
  "--hostname", "-h", "--ip", "--log-driver",
  "--restart", "--shm-size", "--stop-signal",
  "--ulimit", "--gpus", "--device", "--add-host",
  "--dns", "--expose",
]);

/**
 * Extract the inner command from `docker exec <flags> <container> <cmd...>`
 * or `docker run <flags> <image> <cmd...>`.
 * Returns the inner command tokens, or null if none found.
 */
function extractDockerInnerCommand(tokens: string[]): string[] | null {
  // tokens[0] = "docker", tokens[1] = "exec" or "run"
  let i = 2;
  // Skip flags
  while (i < tokens.length) {
    const t = tokens[i];
    if (t === "--") { i++; break; }  // explicit end of flags
    if (t.startsWith("-")) {
      // Flags like -it, -d, --rm, --privileged are boolean (no value)
      if (DOCKER_VALUE_FLAGS.has(t)) {
        i += 2;  // skip flag + value
      } else if (t.startsWith("--") && t.includes("=")) {
        i++;  // --flag=value, single token
      } else {
        i++;  // boolean flag
      }
    } else {
      break;  // first non-flag = container/image name
    }
  }

  // Now tokens[i] should be the container/image name
  if (i >= tokens.length) return null;
  i++;  // skip container/image name

  // Everything after is the inner command
  if (i >= tokens.length) return null;
  return tokens.slice(i);
}

function classifyStage(tokens: string[], config?: ShushConfig): { actionType: string; decision: Decision } {
  // Bare assignments (e.g., `FOO=bar`) produce empty tokens. The assignment
  // itself is harmless; any command substitution in the value is extracted
  // and classified separately by bash-guard's cmdSubs handling.
  if (tokens.length === 0) {
    return { actionType: FILESYSTEM_READ, decision: "allow" };
  }

  // Git: check dangerous -c config keys (must run on pre-strip tokens)
  if (tokens[0] === "git") {
    const dangerousConfig = checkDangerousGitConfig(tokens);
    if (dangerousConfig) {
      const policy = getPolicy(dangerousConfig, config);
      return { actionType: dangerousConfig, decision: policy };
    }
  }

  // Git: strip global flags for trie/flag-rule matching
  const forLookup = tokens[0] === "git" ? stripGitGlobalFlags(tokens) : tokens;

  // 1. Flag rules (data-driven)
  const flagResult = checkFlagRules(forLookup[0], forLookup);
  if (flagResult) {
    const policy = getPolicy(flagResult, config);
    return { actionType: flagResult, decision: policy };
  }

  // 2. Procedural classifiers (registry)
  const classifierResult = lookup(forLookup[0], forLookup);
  if (classifierResult) {
    const policy = getPolicy(classifierResult, config);
    return { actionType: classifierResult, decision: policy };
  }

  // 3. Trie prefix match (existing)
  let actionType = classifyTokens(forLookup, config);

  // 4. Script exec fallback (when trie has no match)
  if (actionType === UNKNOWN) {
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
      finalDecision: asFinal("allow"),
      actionType: UNKNOWN,
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
    isShellWrapper(stages[0].tokens[0])
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
    let tokens = stage.tokens;

    // Shell -c unwrapping FIRST: pwsh -c '...', bash -c '...', etc.
    // Must run before command wrapper unwrapping so that `pwsh -c "cmd"`
    // is treated as a shell invocation, not a wrapper with a positional arg.
    if (depth < MAX_UNWRAP_DEPTH && tokens.length >= 3 && isShellWrapper(tokens[0])) {
      const cIdx = tokens.indexOf("-c");
      if (cIdx >= 1 && cIdx + 1 < tokens.length) {
        const innerCommand = tokens.slice(cIdx + 1).join(" ");
        const innerResult = classifyCommand(innerCommand, depth + 1, config);
        return {
          tokens,
          actionType: innerResult.stages[0]?.actionType ?? LANG_EXEC,
          decision: innerResult.finalDecision,
          reason: innerResult.reason || `shell -c: ${innerCommand}`,
        };
      }
    }

    // Iteratively unwrap command wrappers (nice, nohup, timeout, env, sudo,
    // pwsh without -c, etc.)
    let unwrapped = unwrapCommandWrapper(tokens);
    while (unwrapped) {
      tokens = unwrapped;
      unwrapped = unwrapCommandWrapper(tokens);
    }

    // Basename-normalize the command name so /usr/bin/curl -> curl
    if (tokens.length > 0 && tokens[0].includes("/")) {
      tokens = [cmdBasename(tokens[0]), ...tokens.slice(1)];
    }

    // After command wrapper unwrapping, check for shell -c
    // (handles: env bash -c '...', sudo bash -c '...', etc.)
    if (depth < MAX_UNWRAP_DEPTH && tokens.length >= 3 && isShellWrapper(tokens[0])) {
      const cIdx = tokens.indexOf("-c");
      if (cIdx >= 1 && cIdx + 1 < tokens.length) {
        const innerCommand = tokens.slice(cIdx + 1).join(" ");
        const innerResult = classifyCommand(innerCommand, depth + 1, config);
        return {
          tokens,
          actionType: innerResult.stages[0]?.actionType ?? LANG_EXEC,
          decision: innerResult.finalDecision,
          reason: innerResult.reason || `shell -c: ${innerCommand}`,
        };
      }
    }

    // Docker exec/run delegation: extract the inner command and classify
    // it instead of treating the whole thing as lang_exec.
    if (depth < MAX_UNWRAP_DEPTH && tokens[0] === "docker" &&
        (tokens[1] === "exec" || tokens[1] === "run")) {
      const innerTokens = extractDockerInnerCommand(tokens);
      if (innerTokens && innerTokens.length > 0) {
        const innerResult = classifyCommand(innerTokens.join(" "), depth + 1, config);
        return {
          tokens,
          actionType: innerResult.stages[0]?.actionType ?? LANG_EXEC,
          decision: innerResult.finalDecision,
          reason: innerResult.reason || `docker ${tokens[1]}: ${innerTokens.join(" ")}`,
        };
      }
    }

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
    // Exempt device-special targets and config-whitelisted patterns.
    const redirectAllowed = stage.redirectTarget && (
      SAFE_REDIRECT_TARGETS.has(stage.redirectTarget) ||
      (config?.allowRedirects ?? []).some((pat) => globMatch(pat, stage.redirectTarget!))
    );
    if (stage.redirectTarget && !redirectAllowed) {
      const writePolicy = getPolicy(FILESYSTEM_WRITE, config);
      const combined = stricter(decision, writePolicy);
      if (combined !== decision) {
        actionType = FILESYSTEM_WRITE;
        decision = combined;
        reason = `${tokens[0]} redirects to ${stage.redirectTarget}: ${FILESYSTEM_WRITE}`;
      }
    }

    // Check redirect target against sensitive/hook paths regardless of
    // whether the redirect was whitelisted (sensitive paths always win).
    // Use "Write" as the tool name so hook paths get Block (matching
    // the Write tool's hook protection), not Ask (Bash's default).
    if (stage.redirectTarget && !SAFE_REDIRECT_TARGETS.has(stage.redirectTarget)) {
      const pathResult = checkPath("Write", stage.redirectTarget, config);
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

    // File-reading commands (cat, head, less, etc.) classified as
    // filesystem_read: check positional arguments against sensitive paths.
    // Without this, "cat ~/.ssh/id_rsa" gets allow because the default
    // policy for filesystem_read is allow and bash-guard doesn't otherwise
    // inspect file arguments.
    if (actionType === FILESYSTEM_READ || actionType === FILESYSTEM_WRITE) {
      for (let ti = 1; ti < tokens.length; ti++) {
        const tok = tokens[ti];
        // Skip flags and flag values
        if (tok.startsWith("-")) continue;
        // Skip tokens that look like non-path arguments
        if (!tok.includes("/") && !tok.startsWith("~") && !tok.startsWith("$")) continue;
        // Use matching tool name: Read for filesystem_read, Write for writes.
        // This ensures hook paths get the same treatment as the equivalent
        // file tool (Read allows hooks, Write blocks hooks).
        const proxyTool = actionType === FILESYSTEM_READ ? "Read" : "Write";
        const pathResult = checkPath(proxyTool, tok, config);
        if (pathResult) {
          decision = stricter(decision, pathResult.decision);
          reason = pathResult.reason;
        }
      }
    }
    return {
      tokens,
      actionType,
      decision,
      reason,
    };
  });

  // Check composition rules (pipe chains, etc.)
  const [compDecision, compReason, compRule] = checkComposition(stageResults, stages, config);

  // Aggregate: most restrictive stage decision, keeping the reason
  // from whichever stage produced the strictest decision.
  let finalDecision = asFinal("allow");
  let actionType = stageResults[0]?.actionType ?? UNKNOWN;
  let reason = "";
  for (const sr of stageResults) {
    if (sr.decision !== "allow") {
      const combined = stricter(finalDecision, sr.decision);
      if (combined !== finalDecision || reason === "") {
        reason = sr.reason;
        actionType = sr.actionType;
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
    for (const subList of [subs, cmdSubs]) {
      for (const sub of subList) {
        const subResult = classifyCommand(sub, depth + 1, config);
        if (subResult.finalDecision !== "allow") {
          finalDecision = stricter(finalDecision, subResult.finalDecision);
          actionType = subResult.actionType;
          reason = subResult.reason;
        }
      }
    }
  }


  return {
    command,
    stages: stageResults,
    finalDecision,
    actionType,
    reason,
    compositionRule: compRule || undefined,
  };
}
