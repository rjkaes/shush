# Data Flow: PreToolUse Hook

How a Claude Code tool call flows through shush's classification
pipeline, from stdin JSON to the final allow/deny decision.

## Entry Point: `hooks/pretooluse.ts`

Claude Code invokes the hook with JSON on stdin. The hook reads it
into a `HookInput { tool_name, tool_input, session_id?, cwd? }`,
loads config from `~/.config/shush/config.yaml` + `.shush.yaml`
(merged with stricter-wins), then calls `evaluate()`.

On the way out: `allow`/`context` exit silently (exit 0, no stdout).
`ask`/`block` write a `HookOutput` with `permissionDecision: "ask"`
or `"deny"`. Crashes always emit `"deny"` (fail closed).

## Dispatch: `src/evaluate.ts`

A `switch(toolName)` routes to the right guard:

| Tool | Guard |
|------|-------|
| `Bash` | `classifyCommand()` (bash-guard) |
| `Read` | `checkPath()` |
| `Write`, `Edit` | `checkPath()` + `checkProjectBoundary()` + `scanContent()` |
| `Glob` | `checkPath()` + `checkProjectBoundary()` on path and pattern |
| `Grep` | `checkPath()` + `checkProjectBoundary()` + `isCredentialSearch()` |
| anything else | no-op (allow) |

## Bash Classification Pipeline: `src/bash-guard.ts`

This is the complex path. `classifyCommand(command, depth, config)`
orchestrates everything:

### 1. Process Substitution Extraction

`ast-walk.ts: extractProcessSubs` scans for `>(cmd)` / `<(cmd)`,
replaces them with placeholders, and collects inner commands as
`subs[]`.

### 2. Stage Extraction

`ast-walk.ts: extractStages`:

- First extracts `$()` and backtick command substitutions, replacing
  with `$__SHUSH_CMD_n` placeholders, collecting into `cmdSubs[]`.
- Parses with `unbash` into a shell AST (falls back to quote-aware
  splitting on parse error).
- Walks the AST to produce `Stage[]`, where each stage has `tokens[]`,
  `operator`, `redirectTarget?`, `envAssignments?`.

### 3. Shell Unwrapping

Recursive, depth-limited to `MAX_UNWRAP_DEPTH` (3). If the whole
command is `bash -c '...'` (single stage, first token in
`SHELL_WRAPPERS`), recurse into the inner command string.

### 4. Per-Stage Classification

For each stage, before calling `classifyStage`:

- **Command wrapper unwrapping**: iteratively strips `sudo`, `env`,
  `nice`, `nohup`, `timeout`, `xargs`, `doas`, `busybox`, `pwsh`,
  etc. and their flags to expose the actual command.
- **Basename normalization**: `/usr/bin/curl` -> `curl` via
  `cmdBasename()`.
- **Shell -c re-check**: catches `sudo bash -c '...'` patterns
  revealed by unwrapping.

Then `classifyStage(tokens, config)` runs a priority pipeline,
returning the first match:

```
1. checkDangerousGitConfig()  -- git -c core.hookspath=... etc.
2. stripGitGlobalFlags()      -- clean tokens for downstream matching
3. checkFlagRules()           -- data-driven flag rules (flag_rules key in classify_full/*.json)
4. lookup()                   -- procedural classifier registry (git, curl, wget, etc.)
5. classifyTokens()           -- trie prefix match (data/classifier-trie.json)
6. classifyScriptExec()       -- fallback: ./script.sh patterns
```

Each returns an action type string. `getPolicy(actionType, config)`
resolves it to a `Decision` (checking user config overrides first,
then `data/policies.json` defaults).

**Post-classification augmentations** per stage:

- **Exec-sink env vars**: `PAGER=malicious git log` escalates to
  `lang_exec` policy.
- **Redirect targets**: `cmd > file` applies `filesystem_write` +
  `checkPath` on the target.
- **Git dir paths**: `git -C /path` runs `checkPath` on the directory
  argument.

### 5. Composition Check

`src/composition.ts: checkComposition` scans the stage sequence,
tracking data-flow state through pipe chains:

| Pattern | Rule | Decision |
|---------|------|----------|
| sensitive_read \| ... \| network | data exfiltration | `block` |
| network \| exec_sink | remote code execution | `block` |
| decode \| exec_sink | obfuscated execution | `block` |
| any_read \| exec_sink | local code execution | `ask` |

Non-pipe operators (`&&`, `||`, `;`) reset the chain. Exec sinks
with inline code flags (`-c`, `-e`) are exempt since stdin is data,
not code.

### 6. Aggregation

All stage decisions are reduced with `stricter()` (`allow < context <
ask < block`). Composition can escalate further. Then process subs
and command subs are recursively classified (depth-limited) and can
escalate the final decision.

Returns `ClassifyResult { command, stages, finalDecision, actionType,
reason, compositionRule? }`.

## Non-Bash Guards

### `src/path-guard.ts`

Resolves `~`, strips null bytes, then checks against:

- Hardcoded `SENSITIVE_DIRS` (`~/.ssh` -> block, `~/.aws` -> ask,
  etc.)
- `SENSITIVE_BASENAMES` (`.env`, `.npmrc`, etc.)
- User-configured `sensitivePaths`
- Hook-path self-protection (`~/.claude/hooks/`)
- Project boundary enforcement

### `src/content-guard.ts`

Regex scans Write/Edit content for destructive patterns, exfiltration
payloads, credential access, obfuscation, and embedded secrets
(private keys, AWS keys, GitHub tokens, JWTs). Hits escalate to
`ask`.

## The Invariant

At every aggregation point (stages, composition, subs, path+content),
`stricter()` ensures the most restrictive decision wins. No layer can
loosen a decision made by a previous layer.
