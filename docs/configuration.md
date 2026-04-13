# Configuration

Works out of the box with zero config. Optionally tune behavior with
YAML files at two levels:

- **Global**: `~/.config/shush/config.yaml`
- **Per-project**: `.shush.yaml` (in the project root)

Both are merged at load time, with the stricter policy always winning.

## `actions` -- override default policies

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

## `sensitive_paths` -- protect additional locations

Adds directories or files to the sensitive-path list.
Supports `~` expansion. Values are decision levels.

```yaml
sensitive_paths:
  ~/.kube: ask
  ~/Documents/taxes: block
```

## `classify` -- teach shush new commands

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

## `allow_tools` -- allowlist MCP tools

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

## `messages` -- explain blocked commands to the AI

When shush blocks or prompts for a command, you can attach a message
that the AI sees. This guides Claude toward the right alternative:

```yaml
messages:
  "python *": "Use uv run python instead"
  "git push --force *": "Force-pushing rewrites shared history"
  "rm -rf /*": "Never delete from root"
```

Messages are appended to the decision reason. Glob patterns match
against the full command string. First matching pattern wins.

## `allow_redirects` -- whitelist redirect targets

By default, any output redirect (`>`, `>>`) escalates to
`filesystem_write`. If you have known-safe output directories, exempt
them:

```yaml
allow_redirects:
  - "/tmp/**"
  - "build/**"
  - "dist/**"
```

Sensitive-path checks still apply independently, so
`echo key > ~/.ssh/authorized_keys` is still caught even if you
whitelist `**`.

## `deny_tools` -- block specific MCP tools

The inverse of `allow_tools`. Block specific MCP tool patterns with
an explanation:

```yaml
deny_tools:
  "mcp__*__delete_*": "Deletions not allowed"
  "mcp__filesystem__write_*": "Use the Write tool instead"
```

`deny_tools` is checked before `allow_tools`, so a deny pattern wins
even if the tool matches an allow pattern.

## `after_messages` -- post-execution reminders

Show the AI a reminder after specific commands complete. Requires
registering the PostToolUse hook (the plugin handles this
automatically):

```yaml
after_messages:
  "git push *": "Check CI status"
  "npm publish *": "Update the changelog"
```

## `allowed_paths` -- whitelist paths outside the project

Grant read/write access to directories outside the project boundary.
Useful for MCP tools that need access to config or memory files:

```yaml
allowed_paths:
  - "~/.claude/"
  - "~/Documents/shared-configs/"
```

Trailing `/` means "this directory and everything under it". Without
a trailing slash, matches the exact file. `~` is expanded to your home
directory.

**Global-only.** Per-project `.shush.yaml` cannot add allowed paths
(same restriction as `allow_tools`). Allowed paths bypass the project
boundary check only; sensitive-path detection and content scanning
still apply.

## Supply-chain safety

Per-project `.shush.yaml` can add classifications and tighten policies,
but **can never relax them**. A malicious repo cannot use `.shush.yaml`
to allowlist dangerous commands or MCP tools. Only your global config
has that power. Loosening-only settings (`allow_tools`, `allow_redirects`,
`allowed_paths`) are restricted to the global config.
