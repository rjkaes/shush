# Data Flow: PreToolUse Hook

This document traces the code path executed for each tool call,
with `file:function:line` references. For architecture, invariants,
decision lattice algebra, and composition semantics, see `DESIGN.md`.

---

## Entry trace

```
stdin (JSON)
  -> hooks/pretooluse.ts:6  readStdin()       Buffer accumulation
  -> hooks/pretooluse.ts:15 JSON.parse()      -> HookInput
  -> hooks/pretooluse.ts:18 loadConfig()      src/config.ts:408
  -> hooks/pretooluse.ts:20 evaluate()        src/evaluate.ts:78
  -> hooks/pretooluse.ts:37 toPermissionDecision()
  -> hooks/pretooluse.ts:26 exit 0            (allow or context: silent)
     or
  -> hooks/pretooluse.ts:47 stdout JSON       (ask or block)
```

`allow` and `context` both exit 0 with no stdout. `ask` emits
`permissionDecision: "ask"`. `block` emits `permissionDecision: "deny"`.

See `DESIGN.md — Failure modes and failsafe behavior` for crash
handling (`hooks/pretooluse.ts:51`).

---

## Dispatch table

`evaluate()` at `src/evaluate.ts:78` dispatches on `toolName`:

| Tool | Entry point | Lines |
|------|-------------|-------|
| `Bash` | `classifyCommand()` | `src/evaluate.ts:89` |
| `Read` | `checkPath()` | `src/evaluate.ts:97` |
| `Write` | `checkFileWrite()` | `src/evaluate.ts:106` |
| `Edit` | `checkFileWrite()` | `src/evaluate.ts:118` |
| `MultiEdit` | `checkFileWrite()` | `src/evaluate.ts:130` |
| `NotebookEdit` | `checkFileWrite()` | `src/evaluate.ts:140` |
| `Glob` | `checkPath()` + `checkProjectBoundary()` | `src/evaluate.ts:148` |
| `Grep` | `checkPath()` + `checkProjectBoundary()` + `isCredentialSearch()` | `src/evaluate.ts:171` |
| `mcp__*` | deny_tools / allow_tools / mcp_path_params | `src/evaluate.ts:195` |
| everything else | no-op (allow) | `src/evaluate.ts:195` default |

`checkFileWrite()` at `src/evaluate.ts:30` sequences
`checkPath()` -> `checkProjectBoundary()` -> `scanContent()`.

See `DESIGN.md — Architecture at a glance` for the full flow diagram.

---

## Bash trace

`classifyCommand(command, depth=0, config, projectRoot)`
at `src/bash-guard.ts:301`.

### 1. Process-substitution extraction (`src/bash-guard.ts:320`)

```
command.includes(">(" ) || command.includes("<(")
  -> extractProcessSubs()   src/ast-walk.ts
     returns { cleaned, subs[] }
```

Inner commands in `subs[]` are classified after the main pipeline
and can escalate the final decision.

### 2. Stage extraction (`src/bash-guard.ts:324`)

```
extractStages(cleaned)   src/ast-walk.ts
  returns { stages: Stage[], cmdSubs: string[] }
```

`extractStages` extracts `$()` / backtick substitutions as
`cmdSubs[]`, parses with `unbash`, walks the AST to produce
`Stage[]`. Falls back to `fallbackSplit` on parse error.

See `DESIGN.md — Bash pipeline semantics` for fallback details.

### 3. Shell unwrap loop (`src/bash-guard.ts:328`)

```
if depth < MAX_UNWRAP_DEPTH (src/bash-guard.ts:17)
&& stages.length === 1
&& isShellWrapper(stages[0].tokens[0])  src/taxonomy.ts:137
  -> classifyCommand(innerCommand, depth+1, ...)  recursive
```

Shell wrappers: `bash`, `sh`, `dash`, `zsh`, `pwsh`, `powershell`
(`src/taxonomy.ts:128`).

### 4. Per-stage classification (`src/bash-guard.ts:342`)

For each stage in `stages.map(...)`:

```
a. shell -c unwrap        src/bash-guard.ts:351
b. command wrapper strip  src/bash-guard.ts:367  (COMMAND_WRAPPERS loop)
c. post-unwrap shell -c   src/bash-guard.ts:380
d. docker delegation      src/bash-guard.ts:396
e. basename normalize     src/bash-guard.ts:374
f. classifyStage()        src/bash-guard.ts:228
     1. checkDangerousGitConfig()   src/classifiers/git.ts
     2. checkFlagRules()            src/flag-rules.ts
     3. lookup()                    src/classifiers/index.ts
     4. classifyTokensFull()        src/taxonomy.ts  (trie)
        + classifyScriptExec()      src/classifiers/script-exec.ts
```

`getPolicy(actionType, config)` at `src/taxonomy.ts:122` resolves
the action type to a Decision (config override first, then
`DEFAULT_POLICIES` from `data/policies.json`).

See `DESIGN.md — Bash pipeline semantics` for post-classification
augmentations (redirect targets, exec-sink env vars, git -C paths).

### 5. Composition check (`src/bash-guard.ts:404+`)

```
checkComposition(stageResults, stages, config)   src/composition.ts:26
  returns [Decision | "", reason, ruleName]
```

See `DESIGN.md — Composition rules` for the five rules.

### 6. Aggregation

```
stricter() over all stage decisions   src/types.ts:47
stricter() with composition decision
classify each sub in cmdSubs[] and subs[] (depth+1, recursive)
stricter() with sub decisions
-> ClassifyResult.finalDecision
```

---

## File-tool trace

Shared path for `Write`, `Edit`, `MultiEdit`, `NotebookEdit`
via `checkFileWrite()` at `src/evaluate.ts:30`:

```
checkPath(toolName, filePath, config)         src/path-guard.ts:13
  -> resolvePath()                            src/predicates/path.ts
  -> isHookPath()
  -> isSensitive()
  -> returns { decision, reason } | null

if decision == "allow":
  checkProjectBoundary(toolName, filePath,    src/path-guard.ts:69
    projectRoot, config.allowedPaths)
    -> resolveReal()  (symlink resolution)
    -> returns { decision, reason } | null

if decision == "allow":
  scanContent(content)                        src/content-guard.ts:74
    -> CONTENT_PATTERNS regexes (capped at    src/content-guard.ts:68
       MAX_SCAN_BYTES=256KB for
       EXPENSIVE_CATEGORIES)
    -> returns ContentMatch[]

  if matches.length > 0:
    decision = "ask"
```

`Read` runs only `checkPath()` (`src/evaluate.ts:97`); no boundary
or content check.

`Glob` and `Grep` run `checkPath` + `checkProjectBoundary` but not
`scanContent`. `Grep` additionally calls `isCredentialSearch(pattern)`
at `src/evaluate.ts:189`.

See `DESIGN.md — Non-Bash tools` for path-guard and content-guard
details.

---

## MCP tool trace

Default branch at `src/evaluate.ts:195`:

```
toolName.startsWith("mcp__")
  -> check config.denyTools patterns (globMatch)   src/evaluate.ts:200
     decision = "block" on first match
  -> if not denied: check config.allowTools        src/evaluate.ts:209
     if not in list: decision = "ask"
  -> config.mcpPathParams: for each matching glob  src/evaluate.ts:215
     extract path params from toolInput
     run checkPath() + checkProjectBoundary() on each
     stricter() with current decision
```

`denyTools` is checked before `allowTools`: a deny pattern wins even
if the tool also matches an allow pattern.

---

## Config load trace

`loadConfig(projectRoot, globalPath)` at `src/config.ts:408`:

```
loadConfigFile(globalPath)           src/config.ts:331
  -> readFileSync()
  -> loadConfigFromString()          src/config.ts:290
       parseConfigYaml()             src/config.ts:19
         parseSimpleYaml()           src/mini-yaml.ts
         catch -> EMPTY_CONFIG + stderr warning
       filterAllowedPaths()
  -> returns ShushConfig | EMPTY_CONFIG | null

loadConfigFile(projectPath)          src/config.ts:331

filterClassifyTightenOnly(           src/config.ts:360
  projectConfig.classify,
  globalConfig.classify,
  baseActions)
  drops entries that would loosen; stderr warning per drop

mergeConfigs(effectiveBase,          src/config.ts:178
  filteredProject)
  mergeStricter() on actions + sensitivePaths
  additive union on classify, allowTools, mcpPathParams
  -> ShushConfig
```

Global path defaults to `~/.config/shush/config.yaml`. Project path
is `<projectRoot>/.shush.yaml`. Both are optional; missing file
returns null (treated as `EMPTY_CONFIG`).

See `DESIGN.md — Configuration model` for tighten-only enforcement.

---

## Build trace

`scripts/build-trie.ts` reads every JSON file under
`data/classify_full/`, skips the `flag_rules` key, validates action
types against `data/types.json`, and writes a nested prefix trie to
`data/classifier-trie.json`. Each terminal trie node carries `_`
(action type) and optionally `_p` (pathArgs indices).

Flag rules (`flag_rules` key in `classify_full/` files) are compiled
by `scripts/build-flag-rules.ts` into `data/flag-rules.json`, loaded
at runtime by `src/flag-rules.ts`.

---

## Failsafe trace

Any unhandled rejection in `main()` (`hooks/pretooluse.ts:51`):

```
main().catch((err) => {
  process.stderr.write(`shush: ${err}\n`)
  emit HookOutput { permissionDecision: "deny" }
  process.exit(0)
})
```

Exit code is always 0. A crash produces `"deny"`, never a missing
response that could be interpreted as allow.

See `DESIGN.md — Failure modes and failsafe behavior`.
