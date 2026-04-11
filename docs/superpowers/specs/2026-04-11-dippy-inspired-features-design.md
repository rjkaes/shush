# Dippy-Inspired Feature Additions

Features inspired by reviewing the Dippy project's test suite and source code.

## P0: Block Messages

### Problem
When shush blocks a command, the AI sees `shush(block) Bash: reason` but
gets no guidance on what to do instead. Dippy's `deny` rules include a
message (e.g., `deny python "Use uv run python"`).

### Design
Add `block_messages` to `ShushConfig`: a map of glob patterns to messages.
When `evaluate()` produces a `block` decision, check the full command
string against these patterns. If matched, append the message to the
reason string so the AI sees it.

```yaml
block_messages:
  "python *": "Use uv run python instead"
  "rm -rf /": "Never delete root filesystem"
```

### Implementation
- `types.ts`: add `blockMessages?: Record<string, string>` to `ShushConfig`
- `config.ts`: parse `block_messages` section (map of string to string)
- `evaluate.ts`: after classification, if decision is `block` or `ask`,
  check command against `blockMessages` patterns; append message to reason
- Merge: additive (global + project messages both apply)

### Scope extension: apply to `ask` too
Messages are useful for `ask` decisions too (e.g., "this command modifies
production data"). Rename to `messages` and apply to any non-allow
decision. Pattern matching is glob-based on the full command string.

**Final field name**: `messages` (not `block_messages`).

```yaml
messages:
  "git push --force *": "Force-pushing rewrites history"
  "python *": "Use uv run python instead"
```

## P1a: Docker Exec Inner-Command Delegation

### Problem
`docker exec mycontainer ls` is currently classified by the `docker`
prefix trie entry. Shush doesn't look at the inner command, so safe
commands inside containers get the same treatment as `docker exec bash`.

### Design
In `bash-guard.ts`, after classifying `docker exec`, extract the inner
command (skip docker flags), and classify it separately. The inner
command classification determines the final decision. Path-guard checks
are skipped for inner commands (paths are container-local).

Docker flags that take values: `-u/--user`, `-w/--workdir`,
`-e/--env`, `--privileged`, `--name`, etc. After skipping these,
the next non-flag token is the container name, and everything after
is the inner command.

Also handle `docker run <image> <cmd>` similarly: extract the command
after the image name.

### Implementation
- `bash-guard.ts`: add `extractDockerInnerCommand(tokens)` helper
- When command is `docker exec` or `docker run`, extract inner tokens
- Classify inner tokens through normal pipeline (but skip path guards)
- If inner command is safe, use `allow`; if dangerous, escalate
- If no inner command found (e.g., `docker exec -it container bash`),
  fall through to default docker classification

## P1b: Config Redirect Rules

### Problem
All file redirects escalate to `filesystem_write`. Users cannot
whitelist common redirect targets like `/tmp/**` or `build/**`.

### Design
Add `allow_redirects` to `ShushConfig`: array of glob patterns. In
`bash-guard.ts` where redirect escalation happens, check the target
against these patterns. If matched, skip the `filesystem_write`
escalation (but still check sensitive paths and project boundaries).

```yaml
allow_redirects:
  - "/tmp/**"
  - "build/**"
  - "dist/**"
```

### Implementation
- `types.ts`: add `allowRedirects?: string[]` to `ShushConfig`
- `config.ts`: parse `allow_redirects` section (string array)
- `bash-guard.ts`: before redirect escalation, check target against
  `allowRedirects` patterns using `globMatch()`
- Relative patterns resolved against project root
- Merge: additive union

## P2a: MCP Tool Deny Patterns

### Problem
`allow_tools` is an allowlist. There's no way to explicitly deny
specific MCP tools with a message. Unclassified tools get `ask`,
but you can't `block` specific dangerous ones.

### Design
Add `deny_tools` to `ShushConfig`: map of glob patterns to messages.
Checked before `allow_tools`. If a tool matches a deny pattern, the
decision is `block` with the message as reason.

```yaml
deny_tools:
  "mcp__*__delete_*": "Deletions not allowed"
  "mcp__filesystem__write_*": "Use Write tool instead"
```

### Implementation
- `types.ts`: add `denyTools?: Record<string, string>` to `ShushConfig`
- `config.ts`: parse `deny_tools` section
- `evaluate.ts`: in MCP default branch, check `denyTools` first;
  if matched, return `block` with message. Then check `allowTools`.
- Merge: additive (both global and project deny patterns apply)

## P2b: PostToolUse After Messages

### Problem
No way to show the AI a reminder after a command completes. Dippy's
`after` rules fire on PostToolUse and print feedback.

### Design
Add `after_messages` to config and a new `hooks/posttooluse.ts` entry
point. The PostToolUse hook reads the completed tool call, matches
the command against `after_messages` patterns, and outputs a message.

```yaml
after_messages:
  "git push *": "Check CI status"
  "npm publish *": "Update changelog"
```

### Implementation
- `types.ts`: add `afterMessages?: Record<string, string>` to `ShushConfig`
- `config.ts`: parse `after_messages` section
- New `hooks/posttooluse.ts`: reads HookInput, extracts command,
  matches against patterns, outputs message via `permissionDecisionReason`
- Build script updated to also bundle posttooluse.ts
- User must register the PostToolUse hook separately in settings.json

## Testing Strategy

TDD for all features. Tests written first, then implementation.

## Order of Implementation

1. P0: messages (config + evaluate, smallest surface area)
2. P1b: allow_redirects (config + bash-guard, builds on redirect work)
3. P2a: deny_tools (config + evaluate, similar to messages)
4. P1a: docker exec delegation (bash-guard, most complex)
5. P2b: after_messages (new hook entry point, most independent)
