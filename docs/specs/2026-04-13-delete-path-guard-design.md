# Delete Command Path-Guard Equivalence

**Date**: 2026-04-13
**Origin**: Dippy issue tracker review (#130 find -delete, #136 git -C)
**Status**: Approved

## Problem

File tools (Read, Write, Edit) get path-checked against sensitive paths,
hook paths, and project boundaries via `path-guard.ts`. Bash commands
that read/write files (`cat`, `echo >`) get equivalent checks (lines
427-444 of `bash-guard.ts`). But delete commands (`rm`, `find -delete`)
skip path checking entirely.

`rm ~/.ssh/id_rsa` currently gets `filesystem_delete` -> `context`
(proceed with info). It should get `block` (sensitive path), matching
what `Write ~/.ssh/id_rsa` would produce.

## Design

### Change 1: Extend path-check condition in bash-guard.ts

`bash-guard.ts` line 427 currently checks:
```typescript
if (actionType === FILESYSTEM_READ || actionType === FILESYSTEM_WRITE)
```

Extend to:
```typescript
if (actionType === FILESYSTEM_READ || actionType === FILESYSTEM_WRITE || actionType === FILESYSTEM_DELETE)
```

The existing loop (lines 428-443) iterates positional args, skips flags,
and calls `checkPath()` with a proxy tool name. For deletes, use `"Write"`
as the proxy tool, since deleting is at least as destructive as writing.
This ensures hook paths get `block` (matching Write tool behavior).

This handles `rm` correctly: `rm ~/.ssh/id_rsa` -> tokens are
`["rm", "~/.ssh/id_rsa"]`, the path arg gets checked, sensitive match
-> block.

### Change 2: Find search-root extraction in classifyFind

`find` is structurally different from `rm`. Target paths are search roots
that appear *before* predicate flags:

```
find /path1 /path2 -name "*.tmp" -delete
      ^^^^^  ^^^^^  search roots (check these)
                     ^^^^^^^^^^^^^^^^^^^^^ predicates (skip)
```

Add a `extractFindRoots(tokens: string[]): string[]` function to
`src/classifiers/find.ts` that returns path arguments before the first
predicate flag. Known predicate prefixes: `-name`, `-type`, `-path`,
`-regex`, `-size`, `-mtime`, `-perm`, `-user`, `-group`, `-newer`,
`-maxdepth`, `-mindepth`, `-delete`, `-exec`, `-print`, `-prune`,
`-empty`, `-not`, `!`, `(`, `)`.

Export this from the find classifier. In bash-guard, when the command is
`find` and actionType is `FILESYSTEM_DELETE`, use `extractFindRoots()`
instead of the generic positional-arg loop to get paths to check.

### Change 3: Z3 proofs

**Update D1**: Currently proves `find -delete` pipeline >= context.
Strengthen: when sensitive path is involved, decision >= sensitive
path policy.

**New D4**: `rm sensitive-path` >= `Write sensitive-path`. Extends the
E1/E2 bash-file equivalence to delete operations. Model: delete command
on a path with policy P gets `stricter(filesystem_delete_policy, P)`.
Write tool on same path gets P. Since `stricter(x, P) >= P`, delete
is always at least as strict. UNSAT expected.

**New D5**: `find -delete` on sensitive root >= `Write` to that root.
Same structure as D4 but for find's search-root path extraction.

### Change 4: Property-based tests

Add fast-check properties to `test/property.test.ts`:

1. `rm <sensitive-path>` never allows (for all sensitive paths from
   path-guard's list)
2. `find <sensitive-path> -delete` never allows
3. `rm <path>` decision >= `Write <path>` decision (equivalence)

### Change 5: Unit tests

Add to existing test files:

- `rm ~/.ssh/id_rsa` -> block
- `rm -rf ~/.ssh` -> block
- `rm __pycache__` -> context (in-project, non-sensitive)
- `find ~/.ssh -delete` -> block
- `find . -name "*.pyc" -delete` -> context (in-project)
- `find /etc -name "*.conf" -delete` -> block (sensitive)

## Non-goals

- Changing `filesystem_delete` default policy (stays `context`)
- Adding recursive-flag escalation (future work)
- Handling `find` without `-delete` (already `filesystem_read`)

## Invariant

After this change, the bash-file equivalence invariant extends to:

| Bash command | Equivalent file tool | Path-checked? |
|---|---|---|
| `cat path` | `Read path` | Yes (existing) |
| `echo > path` | `Write path` | Yes (existing) |
| `rm path` | `Write path` (delete) | **Yes (new)** |
| `find root -delete` | `Write root` (delete) | **Yes (new)** |

Z3 proofs cover all four equivalences.
