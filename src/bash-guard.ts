// src/bash-guard.ts
//
// Orchestrates the full bash command classification pipeline:
// extractStages -> classify each stage -> check composition -> aggregate.

import { extractProcessSubs, extractStages } from "./ast-walk.js";
import { classifyTokens, classifyTokensFull, isShellWrapper, isExecSink, getPolicy, FILESYSTEM_READ, FILESYSTEM_WRITE, FILESYSTEM_DELETE, DISK_DESTRUCTIVE, NETWORK_OUTBOUND, GIT_SAFE, GIT_WRITE, GIT_DISCARD, GIT_HISTORY_REWRITE, LANG_EXEC, UNKNOWN } from "./taxonomy.js";
import { checkFlagRules } from "./flag-rules.js";
import { lookup, checkDangerousGitConfig, stripGitGlobalFlags, extractGitDirPaths, classifyScriptExec, extractFindRoots } from "./classifiers/index.js";
import { checkComposition } from "./composition.js";
import { writeEmittersFromData } from "./predicates/composition.js";
import { globMatch } from "./types.js";
import { checkPath, checkProjectBoundary } from "./path-guard.js";
import type { ClassifyResult, StageResult, Decision, ShushConfig } from "./types.js";
import { stricter, asFinal, cmdBasename } from "./types.js";

const MAX_UNWRAP_DEPTH = 3;

// Commands classified as a write action (filesystem_write, filesystem_delete,
// disk_destructive) for at least one subcommand variant. Data-driven from
// data/classify_full/*.json via writeEmittersFromData(). Used to force the
// sensitive/hook path check on positional args even when the resolved action
// type is a non-write variant (e.g. bare `make <path>` resolves to package_run
// but `make install <path>` is filesystem_write; both must enforce parity).
const WRITE_EMITTERS = writeEmittersFromData();

// ==============================================================================
// Command Wrapper Unwrapping
// ==============================================================================

import { COMMAND_WRAPPERS, type WrapperSpec } from "./predicates/composition.js";
export { COMMAND_WRAPPERS };

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
 * Classify a single stage's tokens, returning an action type, decision, and
 * any trie-declared pathArgs positions. Pipeline: flag rules -> procedural
 * classifiers -> trie -> script-exec fallback.
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

/**
 * Extract host paths from docker -v/--volume and --mount flags.
 * -v host_path:container_path[:opts]  →  host_path
 * --volume host_path:container_path   →  host_path
 * --mount type=bind,source=host,...   →  host_path
 */
function extractDockerMountPaths(tokens: string[]): string[] {
  const paths: string[] = [];
  for (let i = 2; i < tokens.length; i++) {
    const tok = tokens[i];
    if (tok === "-v" || tok === "--volume") {
      if (i + 1 < tokens.length) {
        const val = tokens[i + 1];
        // Format: host:container[:opts] or named_volume:container
        const colonIdx = val.indexOf(":");
        if (colonIdx > 0) {
          const hostPart = val.slice(0, colonIdx);
          // Named volumes don't start with / ~ $ . — skip them
          if (hostPart.startsWith("/") || hostPart.startsWith("~") ||
              hostPart.startsWith("$") || hostPart.startsWith(".")) {
            paths.push(hostPart);
          }
        }
        i++; // skip value
      }
    } else if (tok === "--mount" && i + 1 < tokens.length) {
      // --mount type=bind,source=/host/path,target=/container/path
      const val = tokens[i + 1];
      const srcMatch = val.match(/(?:^|,)(?:source|src)=([^,]+)/);
      if (srcMatch) {
        paths.push(srcMatch[1]);
      }
      i++;
    } else if (tok.startsWith("--volume=")) {
      const val = tok.slice("--volume=".length);
      const colonIdx = val.indexOf(":");
      if (colonIdx > 0) {
        const hostPart = val.slice(0, colonIdx);
        if (hostPart.startsWith("/") || hostPart.startsWith("~") ||
            hostPart.startsWith("$") || hostPart.startsWith(".")) {
          paths.push(hostPart);
        }
      }
    } else if (tok.startsWith("--mount=")) {
      const val = tok.slice("--mount=".length);
      const srcMatch = val.match(/(?:^|,)(?:source|src)=([^,]+)/);
      if (srcMatch) {
        paths.push(srcMatch[1]);
      }
    } else if (!tok.startsWith("-")) {
      break; // reached container/image name — stop
    }
  }
  return paths;
}

function classifyStage(
  tokens: string[],
  config?: ShushConfig,
): { actionType: string; decision: Decision; triePathArgs: readonly number[] } {
  // Bare assignments (e.g., `FOO=bar`) produce empty tokens. The assignment
  // itself is harmless; any command substitution in the value is extracted
  // and classified separately by bash-guard's cmdSubs handling.
  if (tokens.length === 0) {
    return { actionType: FILESYSTEM_READ, decision: "allow", triePathArgs: [] };
  }

  // Git: check dangerous -c config keys (must run on pre-strip tokens)
  if (tokens[0] === "git") {
    const dangerousConfig = checkDangerousGitConfig(tokens);
    if (dangerousConfig) {
      const policy = getPolicy(dangerousConfig, config);
      return { actionType: dangerousConfig, decision: policy, triePathArgs: [] };
    }
  }

  // Git: strip global flags for trie/flag-rule matching
  const forLookup = tokens[0] === "git" ? stripGitGlobalFlags(tokens) : tokens;

  // 1. Flag rules (data-driven)
  const flagResult = checkFlagRules(forLookup[0], forLookup);
  if (flagResult) {
    const policy = getPolicy(flagResult, config);
    return { actionType: flagResult, decision: policy, triePathArgs: [] };
  }

  // 2. Procedural classifiers (registry)
  const classifierResult = lookup(forLookup[0], forLookup);
  if (classifierResult) {
    const policy = getPolicy(classifierResult, config);
    return { actionType: classifierResult, decision: policy, triePathArgs: [] };
  }

  // 3. Trie prefix match: use full lookup to capture pathArgs annotations.
  const trieResult = classifyTokensFull(forLookup, config);
  let actionType = trieResult.actionType;
  const triePathArgs = trieResult.pathArgs;

  // 4. Script exec fallback (when trie has no match)
  if (actionType === UNKNOWN) {
    actionType = classifyScriptExec(tokens) ?? actionType;
  }

  const decision = getPolicy(actionType, config);
  return { actionType, decision, triePathArgs };
}

/**
 * Resolve a token at position `index` in `tokens`, extracting the path value.
 * Supports negative indices (Python-style: -1 = last token).
 * Recognizes `KEY=VALUE` form and returns the VALUE portion as the path.
 * Returns null when the index is out of range or the resolved path is empty.
 */
function resolvePathArgToken(tokens: string[], index: number): string | null {
  const len = tokens.length;
  const resolved = index < 0 ? len + index : index;
  if (resolved < 0 || resolved >= len) return null;
  const tok = tokens[resolved];
  // KEY=VALUE form (e.g., dd's of=/path): extract everything after '='.
  const eqIdx = /^[a-zA-Z_]+=/.exec(tok);
  const path = eqIdx ? tok.slice(eqIdx[0].length) : tok;
  return path.length > 0 ? path : null;
}

/**
 * Classify a full bash command string. Parses into stages, classifies each,
 * checks composition rules, and returns the most restrictive decision.
 * Handles shell unwrapping (bash -c, sh -c) with depth limit.
 */
export function classifyCommand(
  command: string,
  depth = 0,
  config?: ShushConfig,
  projectRoot: string | null = null,
): ClassifyResult {
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
      return classifyCommand(innerCommand, depth + 1, config, projectRoot);
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
        const innerResult = classifyCommand(innerCommand, depth + 1, config, projectRoot);
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
        const innerResult = classifyCommand(innerCommand, depth + 1, config, projectRoot);
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
        const innerResult = classifyCommand(innerTokens.join(" "), depth + 1, config, projectRoot);
        let dockerDecision = innerResult.finalDecision;
        let dockerReason = innerResult.reason || `docker ${tokens[1]}: ${innerTokens.join(" ")}`;

        // Check volume mount host paths against sensitive-path rules.
        // -v ~/.ssh:/keys mounts a sensitive host directory into the
        // container, enabling exfiltration regardless of inner command.
        for (const mountPath of extractDockerMountPaths(tokens)) {
          const pathResult = checkPath("Write", mountPath, config);
          if (pathResult) {
            dockerDecision = stricter(dockerDecision, pathResult.decision);
            dockerReason = pathResult.reason;
          }
        }

        return {
          tokens,
          actionType: innerResult.stages[0]?.actionType ?? LANG_EXEC,
          decision: dockerDecision,
          reason: dockerReason,
        };
      }
    }

    let { actionType, decision, triePathArgs } = classifyStage(tokens, config);
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

    // Commands that operate on file paths: check positional arguments
    // against sensitive paths. Without this, "cat ~/.ssh/id_rsa" gets allow
    // because the default policy for filesystem_read is allow and bash-guard
    // doesn't otherwise inspect file arguments. Git subcommands (clone,
    // init, archive) can write to arbitrary destinations. Network commands
    // (rsync, scp) exfiltrate via file paths.
    const PATH_CHECKED_TYPES: Set<string> = new Set([
      FILESYSTEM_READ, FILESYSTEM_WRITE, FILESYSTEM_DELETE, NETWORK_OUTBOUND,
      GIT_SAFE, GIT_WRITE, GIT_DISCARD, GIT_HISTORY_REWRITE,
    ]);
    // Write-emitter parity (G1): commands that are classified as
    // filesystem_write/delete/disk_destructive for ANY subcommand variant
    // must path-check positional args regardless of the resolved action
    // type. Example: `make install <path>` is filesystem_write, but bare
    // `make <path>` resolves to package_run. Both must enforce the same
    // sensitive/hook path protection as the Write tool. Membership is
    // data-driven via writeEmittersFromData().
    const isWriteEmitter = tokens.length > 0 && WRITE_EMITTERS.has(tokens[0]);
    // G7.4: stages classified via a user-supplied classify entry carry no
    // shush metadata about which positional arguments are path-like. Force
    // the path-check loop to run so sensitive-path arguments cannot bypass
    // protection through custom classifications (e.g. classifying `mywriter`
    // as `db_read` would otherwise let `mywriter ~/.ssh/id_rsa` through as
    // `allow`).
    const baseCmd = tokens.length > 0 ? cmdBasename(tokens[0]) : "";
    const isUserClassified = baseCmd !== "" && config !== undefined && Object
      .values(config.classify)
      .some((patterns) => patterns.some((p) => {
        // Patterns are first-token-prefix strings ("git clone", "mywriter");
        // a leading-token match is sufficient to flag the stage as user-routed.
        const firstTok = p.split(/\s+/)[0];
        return firstTok === baseCmd;
      }));
    if (PATH_CHECKED_TYPES.has(actionType) || isWriteEmitter || isUserClassified) {
      // Use matching tool name: Read for filesystem_read, Write for writes,
      // deletes, and network commands. Network commands that touch files
      // (scp, rsync) can both read and exfiltrate, so "Write" proxy is
      // conservative — blocks hook-path exfiltration.
      const isReadOnly = actionType === FILESYSTEM_READ || actionType === GIT_SAFE;
      const proxyTool = isReadOnly ? "Read" : "Write";

      // find is special: search roots come before predicate flags, and
      // predicate arguments (e.g. -name "*.log") are not paths.
      const pathArgs = tokens[0] === "find"
        ? extractFindRoots(tokens)
        : tokens.slice(1).filter((tok) => {
            if (tok.startsWith("-")) return false;
            // Skip URLs (git clone https://..., git remote add origin ...)
            if (/^[a-z+]+:\/\//i.test(tok)) return false;
            if (!tok.includes("/") && !tok.includes("\\") && !tok.startsWith("~") && !tok.startsWith("$")) return false;
            return true;
          });

      for (const pathArg of pathArgs) {
        const pathResult = checkPath(proxyTool, pathArg, config);
        if (pathResult) {
          decision = stricter(decision, pathResult.decision);
          reason = pathResult.reason;
        }
        // Write-emitter parity (G1): Bash writes must also respect the
        // project-boundary check that Write/Edit enforce, so `ln -sf src
        // /Users/rjk/x` outside the project tree asks just like `Write`.
        // Only enforce boundary when the resolved action is itself a write;
        // commands like `gh api /repos/...` route through git_write but the
        // argument is a URL path, not a filesystem path. Boundary applies to
        // true disk writes: filesystem_write, filesystem_delete, disk_destructive.
        const isActualWrite =
          actionType === FILESYSTEM_WRITE ||
          actionType === FILESYSTEM_DELETE ||
          actionType === DISK_DESTRUCTIVE;
        if (isWriteEmitter && isActualWrite) {
          const boundaryResult = checkProjectBoundary(
            proxyTool, pathArg, projectRoot, config?.allowedPaths,
          );
          if (boundaryResult) {
            decision = stricter(decision, boundaryResult.decision);
            reason = boundaryResult.reason;
          }
        }
      }
    }

    // Trie-declared pathArgs (I3): route annotated token positions through
    // checkPath. This catches destination paths for commands like cp, mv,
    // tee, install, ln, and dd's of=PATH form that the heuristic loop above
    // may miss (e.g., KEY=VALUE tokens skipped by the startsWith("-") filter).
    if (triePathArgs.length > 0) {
      const isActualWrite =
        actionType === FILESYSTEM_WRITE ||
        actionType === FILESYSTEM_DELETE ||
        actionType === DISK_DESTRUCTIVE;
      const proxyTool = isActualWrite ? "Write" : "Read";
      for (const idx of triePathArgs) {
        const pathStr = resolvePathArgToken(tokens, idx);
        if (pathStr === null) continue;
        const pathResult = checkPath(proxyTool, pathStr, config);
        if (pathResult) {
          decision = stricter(decision, pathResult.decision);
          reason = pathResult.reason;
        }
        if (isActualWrite) {
          const boundaryResult = checkProjectBoundary(
            proxyTool, pathStr, projectRoot, config?.allowedPaths,
          );
          if (boundaryResult) {
            decision = stricter(decision, boundaryResult.decision);
            reason = boundaryResult.reason;
          }
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
        const subResult = classifyCommand(sub, depth + 1, config, projectRoot);
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
