# Z3 Gap Closure Follow-up Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining deferred items from `docs/specs/2026-04-16-z3-gap-closure-followup-design.md`. The parent plan (PR #1) is already merged; this plan stands alone as additive work on top of `main`.

**Architecture:** Each task is a small, independent commit. New tests drive every behavior change (TDD: failing test first, minimal fix, passing test, commit). Predicate changes land in existing `src/predicates/*.ts` files (created by the parent plan).

**Tech Stack:** bun (test + bundler), TypeScript, fast-check, z3-solver (WASM, run via `npx tsx`), YAML config.

## Post-merge state audit (2026-04-16)

| Design item | State on `main` | Work required |
|---|---|---|
| I1 golden corpus (G4) | ABSENT | Task F5: create 100-entry corpus + gate |
| I2 G7.2 fail-closed | SOFT (drop + stderr warn at `src/predicates/config.ts:37-53`) | Task F4: convert to fail-closed + `allowOverlapWarn` opt-in |
| I3 `pathArgs` schema | ABSENT | Task F2: add schema + wire through evaluate |
| I4 pinned seed | PARTIAL (enumeration exists, no seed pin) | Task F6: pin seed + document |
| I5 data-driven build guard | ALREADY DATA-DRIVEN (via `PRECOMPUTED_WRITE_EMITTERS`) | no work |
| I6 three-commit split | OBSOLETE (parent merged per-task) | no work |
| I7 `COMMAND_WRAPPERS` | DEFINED inline in `src/bash-guard.ts:58`, not in predicates | Task F1: relocate to `src/predicates/composition.ts` |
| I8 operator parity | PARTIAL (`test/operator-reset.test.ts` covers 4 operators for escalation only; no parity assertion vs ast-walk output) | Task F3: add real parity test |
| I9 wall-time per-shard | ABSENT | Task F7: add `scripts/measure-z3.ts` + CI step |

Seven additive tasks (F1-F7). No interleaving, no parent-task cross-references.

---

## Task F1: Relocate `COMMAND_WRAPPERS` to predicates

Move the wrapper set from `src/bash-guard.ts` into `src/predicates/composition.ts` so both `bash-guard.ts` and `ast-walk.ts` import one source of truth.

**Files:**
- Modify: `src/predicates/composition.ts`
- Modify: `src/bash-guard.ts` (replace local `COMMAND_WRAPPERS` with import)
- Modify: `src/ast-walk.ts` (replace any inline wrapper list with import)
- Test: `test/command-wrappers.test.ts`

- [ ] **Step 1: Locate the current wrapper definition**

Run: `grep -n "COMMAND_WRAPPERS\|WrapperSpec" src/bash-guard.ts`
Expected: the current `const COMMAND_WRAPPERS: Record<string, WrapperSpec>` declaration (line ~58) plus `WrapperSpec` type if defined locally.

Copy the full object verbatim into a scratch buffer. It must round-trip to predicates without altering keys or values.

- [ ] **Step 2: Write the failing test**

Create `test/command-wrappers.test.ts`:

```ts
import { describe, test, expect } from "bun:test";
import { COMMAND_WRAPPERS as FROM_PREDICATES } from "../src/predicates/composition";
import { COMMAND_WRAPPERS as FROM_BASH_GUARD } from "../src/bash-guard";

describe("COMMAND_WRAPPERS relocation", () => {
  test("predicates export matches bash-guard re-export key-for-key", () => {
    expect(Object.keys(FROM_PREDICATES).sort()).toEqual(Object.keys(FROM_BASH_GUARD).sort());
  });

  test("predicates export matches bash-guard re-export value-for-value", () => {
    for (const k of Object.keys(FROM_PREDICATES)) {
      expect(FROM_BASH_GUARD[k]).toEqual(FROM_PREDICATES[k]);
    }
  });

  test("contains the canonical wrappers", () => {
    for (const w of ["bash", "sh", "zsh", "dash", "ash", "env", "nice", "nohup", "stdbuf", "time", "timeout", "sudo", "doas", "xargs"]) {
      expect(FROM_PREDICATES[w]).toBeDefined();
    }
  });
});
```

- [ ] **Step 3: Run the test**

Run: `bun test test/command-wrappers.test.ts`
Expected: FAIL with "COMMAND_WRAPPERS is not exported from predicates/composition".

- [ ] **Step 4: Move the definition**

In `src/predicates/composition.ts`, add (with `WrapperSpec` type if it lived in `bash-guard.ts`):

```ts
export type WrapperSpec = /* copy from bash-guard.ts verbatim */;
export const COMMAND_WRAPPERS: Record<string, WrapperSpec> = {
  /* copy the object body verbatim from bash-guard.ts */
};
```

In `src/bash-guard.ts`, replace the inline definition with:

```ts
import { COMMAND_WRAPPERS, type WrapperSpec } from "./predicates/composition";
export { COMMAND_WRAPPERS };
```

(The re-export keeps existing import sites working until they're migrated.)

In `src/ast-walk.ts`, if any inline wrapper list exists, replace with `import { COMMAND_WRAPPERS } from "./predicates/composition";`.

- [ ] **Step 5: Run tests and typecheck**

Run: `bun run typecheck && bun test`
Expected: all pass. No behavior change.

- [ ] **Step 6: Commit**

```bash
git add src/predicates/composition.ts src/bash-guard.ts src/ast-walk.ts test/command-wrappers.test.ts
git commit -m "refactor(predicates): relocate COMMAND_WRAPPERS to predicates/composition

Single source of truth for the wrapper set (bash/sh/env/sudo/xargs/
etc.). bash-guard.ts re-exports the same symbol for backward
compatibility. No behavior change. Resolves design item I7."
```

---

## Task F2: `pathArgs` schema for classify entries

Add an optional `pathArgs` field to classify entries. Built-in write emitters gain annotations. Evaluate routes the declared positions through `checkPath`.

**Files:**
- Modify: `src/types.ts`
- Modify: `src/taxonomy.ts`
- Modify: `scripts/build-trie.ts`
- Modify: `data/classifier-trie.json` (regenerated)
- Modify: `data/classify_full/cp.json`, `mv.json`, `tee.json`, `dd.json`, `install.json`, `ln.json`
- Modify: `src/bash-guard.ts` (route pathArgs through checkPath)
- Modify: `src/classify.ts` (parser for `of=PATH` form if needed)
- Test: `test/path-args-schema.test.ts`
- Test: `test/path-args-wiring.test.ts`

- [ ] **Step 1: Write the schema test**

Create `test/path-args-schema.test.ts`:

```ts
import { describe, test, expect } from "bun:test";
import { parseClassifyEntry } from "../src/taxonomy";

describe("pathArgs schema", () => {
  test("bare array form parses with empty pathArgs", () => {
    expect(parseClassifyEntry(["mycmd", "noop"])).toEqual({
      prefix: ["mycmd", "noop"],
      pathArgs: [],
    });
  });

  test("object form parses with explicit pathArgs", () => {
    expect(parseClassifyEntry({ prefix: ["mycmd", "save"], pathArgs: [2] })).toEqual({
      prefix: ["mycmd", "save"],
      pathArgs: [2],
    });
  });

  test("negative indices allowed", () => {
    expect(parseClassifyEntry({ prefix: ["cp"], pathArgs: [-1] }).pathArgs).toEqual([-1]);
  });

  test("rejects duplicate indices", () => {
    expect(() => parseClassifyEntry({ prefix: ["x"], pathArgs: [1, 1] })).toThrow(/duplicate/);
  });

  test("rejects non-integer index", () => {
    expect(() => parseClassifyEntry({ prefix: ["x"], pathArgs: [1.5 as unknown as number] })).toThrow(/integer/);
  });

  test("rejects unknown fields", () => {
    expect(() => parseClassifyEntry({ prefix: ["x"], pathArgs: [0], extra: true } as unknown)).toThrow(/unknown field/);
  });

  test("rejects non-string token in prefix", () => {
    expect(() => parseClassifyEntry({ prefix: ["x", 2 as unknown as string], pathArgs: [] })).toThrow(/string/);
  });
});
```

- [ ] **Step 2: Run the test to confirm failure**

Run: `bun test test/path-args-schema.test.ts`
Expected: FAIL — `parseClassifyEntry` undefined.

- [ ] **Step 3: Add the type and parser**

Add to `src/types.ts`:

```ts
export type ClassifyEntry = {
  prefix: readonly string[];
  pathArgs: readonly number[];
};
```

Add to `src/taxonomy.ts`:

```ts
export function parseClassifyEntry(raw: unknown): ClassifyEntry {
  if (Array.isArray(raw)) {
    if (!raw.every(t => typeof t === "string")) {
      throw new Error(`classify entry: prefix tokens must be strings`);
    }
    return { prefix: raw as string[], pathArgs: [] };
  }
  if (raw === null || typeof raw !== "object") {
    throw new Error(`classify entry: must be array or object, got ${typeof raw}`);
  }
  const allowed = new Set(["prefix", "pathArgs"]);
  for (const k of Object.keys(raw)) {
    if (!allowed.has(k)) throw new Error(`classify entry: unknown field "${k}"`);
  }
  const obj = raw as { prefix?: unknown; pathArgs?: unknown };
  if (!Array.isArray(obj.prefix) || !obj.prefix.every(t => typeof t === "string")) {
    throw new Error(`classify entry: prefix must be array of strings`);
  }
  const args = obj.pathArgs ?? [];
  if (!Array.isArray(args)) throw new Error(`classify entry: pathArgs must be array`);
  for (const n of args as unknown[]) {
    if (typeof n !== "number" || !Number.isInteger(n)) {
      throw new Error(`classify entry: pathArgs must contain integer indices`);
    }
  }
  const seen = new Set<number>();
  for (const n of args as number[]) {
    if (seen.has(n)) throw new Error(`classify entry: duplicate pathArgs index ${n}`);
    seen.add(n);
  }
  return { prefix: obj.prefix as string[], pathArgs: args as number[] };
}
```

- [ ] **Step 4: Run schema tests**

Run: `bun test test/path-args-schema.test.ts`
Expected: PASS.

- [ ] **Step 5: Thread `pathArgs` through trie build**

Modify `scripts/build-trie.ts` so every entry is normalized via `parseClassifyEntry` and trie terminals carry `pathArgs`.

Add to trie node type and write logic:

```ts
// node type
type TrieTerminal = { actionType: string; pathArgs: readonly number[] };

// when building, call:
const entry = parseClassifyEntry(rawEntry);
addToTrie(trie, entry.prefix, { actionType, pathArgs: entry.pathArgs });
```

Ensure the trie lookup API returns `pathArgs` alongside the action type.

- [ ] **Step 6: Write the wiring test**

Create `test/path-args-wiring.test.ts`:

```ts
import { describe, test, expect } from "bun:test";
import { evaluate } from "../src/bash-guard";

describe("pathArgs wiring for built-in write emitters", () => {
  test("cp <src> ~/.ssh/id_rsa escalates on dest", () => {
    expect(evaluate("cp /tmp/x /Users/x/.ssh/id_rsa")).toMatch(/ask|block/);
  });
  test("mv /tmp/x ~/.aws/credentials escalates", () => {
    expect(evaluate("mv /tmp/x /Users/x/.aws/credentials")).toMatch(/ask|block/);
  });
  test("tee -a ~/.ssh/config escalates", () => {
    expect(evaluate("tee -a /Users/x/.ssh/config")).toMatch(/ask|block/);
  });
  test("dd of=~/.ssh/config escalates", () => {
    expect(evaluate("dd if=/dev/zero of=/Users/x/.ssh/config")).toMatch(/ask|block/);
  });
  test("install -m 644 src ~/.ssh/authorized_keys escalates", () => {
    expect(evaluate("install -m 644 /tmp/src /Users/x/.ssh/authorized_keys")).toMatch(/ask|block/);
  });
  test("ln -sf /etc/passwd ~/x escalates", () => {
    expect(evaluate("ln -sf /etc/passwd /Users/x/x")).toMatch(/ask|block/);
  });
});
```

- [ ] **Step 7: Run to surface gaps**

Run: `bun test test/path-args-wiring.test.ts`
Expected: most may already PASS because G1 in the parent plan added `WRITE_EMITTERS` path-checking. Any FAIL indicates a missing pathArgs annotation or a parse gap (e.g. `dd`'s `of=` form).

- [ ] **Step 8: Annotate built-in entries**

Edit each of `data/classify_full/cp.json`, `mv.json`, `tee.json`, `install.json`, `ln.json` to use the object form with `pathArgs`. Example `cp.json`:

```json
{
  "filesystem_write": [
    { "prefix": ["cp"], "pathArgs": [-1] },
    { "prefix": ["cp", "-r"], "pathArgs": [-1] },
    { "prefix": ["cp", "-a"], "pathArgs": [-1] }
  ]
}
```

For `dd.json`, `pathArgs` alone is insufficient because `of=PATH` is a key=value token. Add a small parser path in `src/classify.ts` (or in evaluate's pathArgs resolver) that recognizes `of=` prefix and treats the value as a path.

- [ ] **Step 9: Route pathArgs through checkPath in evaluate**

In `src/bash-guard.ts` where classification resolves, after obtaining the entry's `pathArgs`, for each index `i`:

- If `i < 0`, use `tokens.length + i`.
- Extract the token at that position.
- If the token matches `/^[a-zA-Z_]+=/`, take everything after `=` as the path.
- Call `checkPath(path)` and escalate the decision.

- [ ] **Step 10: Rebuild trie and run all tests**

Run: `bun run build && bun test`
Expected: all PASS.

- [ ] **Step 11: Commit**

```bash
git add src/types.ts src/taxonomy.ts scripts/build-trie.ts data/classifier-trie.json data/classify_full src/bash-guard.ts src/classify.ts test/path-args-schema.test.ts test/path-args-wiring.test.ts
git commit -m "feat(classify): add pathArgs schema + wire through evaluate

Classify entries accept an optional pathArgs field listing token
indices that must route through checkPath. Bare-array form remains
valid. Annotates cp/mv/tee/dd/install/ln with destination
positions. dd's of=PATH form is handled by the pathArg resolver.
Resolves design item I3."
```

---

## Task F3: Operator parity test against `ast-walk`

Add a real parity test: iterate a fixture corpus through `ast-walk` and assert every emitted operator lives in `PIPE_OPERATORS ∪ RESET_OPERATORS`.

**Files:**
- Create: `test/fixtures/operator-corpus.txt`
- Create: `test/operator-parity.test.ts`

- [ ] **Step 1: Seed the corpus**

Create `test/fixtures/operator-corpus.txt`:

```
echo a && echo b
echo a || echo b
echo a ; echo b
curl x | sh
echo $(date)
echo `date`
cat <(echo x)
tee >(cat)
sleep 1 &
cmd |& grep x
coproc cat
printf "a\nb\n" | read x
echo a
echo b
```

(14 non-empty lines covering `&&`, `||`, `;`, `|`, `$(..)`, backticks, `<(..)`, `>(..)`, `&`, `|&`, `coproc`, newline-separated commands, plain commands.)

- [ ] **Step 2: Write the failing parity test**

Create `test/operator-parity.test.ts`:

```ts
import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { PIPE_OPERATORS, RESET_OPERATORS } from "../src/predicates/composition";
import { walk } from "../src/ast-walk";

describe("operator parity", () => {
  test("every operator ast-walk emits is covered by a predicate set", () => {
    const corpus = readFileSync("test/fixtures/operator-corpus.txt", "utf8")
      .split("\n").filter(l => l.trim().length > 0);
    const seen = new Set<string>();
    for (const line of corpus) {
      for (const stage of walk(line)) {
        if (stage.op) seen.add(stage.op);
      }
    }
    const covered = new Set<string>([...PIPE_OPERATORS, ...RESET_OPERATORS]);
    const missing = [...seen].filter(op => !covered.has(op));
    expect(missing).toEqual([]);
  });
});
```

- [ ] **Step 3: Run to confirm coverage**

Run: `bun test test/operator-parity.test.ts`
Expected: PASS if every operator `ast-walk` emits for the corpus lives in one of the two sets. FAIL prints `missing` — add each listed operator to the appropriate predicate set in `src/predicates/composition.ts` (reset if it bounds a stage, pipe if it forwards stdin).

Note: adjust the `walk` import name to whatever the module exports (`walk`, `parseStages`, etc.).

- [ ] **Step 4: Commit**

```bash
git add test/fixtures/operator-corpus.txt test/operator-parity.test.ts src/predicates/composition.ts
git commit -m "test(composition): operator parity vs ast-walk

Iterates a 14-line corpus through ast-walk and asserts every
emitted operator lives in PIPE_OPERATORS or RESET_OPERATORS.
Fails CI if a new operator is added to ast-walk without updating
predicates. Resolves design item I8."
```

---

## Task F4: G7.2 fail-closed with `allowOverlapWarn` opt-in

Convert `filterAllowedPaths` + `mergeConfigs` from drop-with-warn to reject-config-load on overlap. Preserve one-release opt-in soft mode via `allowOverlapWarn: true`.

**Files:**
- Modify: `src/predicates/config.ts` (currently lines ~37-53 in `filterAllowedPaths`)
- Modify: `src/config.ts` (loader return type + caller updates)
- Modify: `test/config-containment.test.ts` (existing property test, adapt to new API)
- Test: `test/config-fail-closed.test.ts`

- [ ] **Step 1: Read the current behavior**

Open `src/predicates/config.ts` lines 37-53 and `src/config.ts` `loadConfig` (or equivalent). Note the current signatures. The new API returns a discriminated union:

```ts
type LoadResult =
  | { ok: true; config: Config; warnings: string[] }
  | { ok: false; reason: string };
```

- [ ] **Step 2: Write the failing tests**

Create `test/config-fail-closed.test.ts`:

```ts
import { describe, test, expect } from "bun:test";
import { loadConfigFromString } from "../src/config";

describe("G7.2 fail-closed", () => {
  test("rejects config when allowed_paths overlaps sensitive", () => {
    const yaml = `allowed_paths:\n  - ~/.ssh\n`;
    const r = loadConfigFromString(yaml);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/allowed_paths.*overlaps sensitive/i);
  });

  test("accepts overlap when allowOverlapWarn: true (deprecated soft mode)", () => {
    const yaml = `allowOverlapWarn: true\nallowed_paths:\n  - ~/.ssh\n`;
    const r = loadConfigFromString(yaml);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.config.allowed_paths).toEqual([]);
      expect(r.warnings.some(w => /deprecated/i.test(w))).toBe(true);
    }
  });

  test("non-overlap loads cleanly", () => {
    const yaml = `allowed_paths:\n  - /tmp/scratch\n`;
    const r = loadConfigFromString(yaml);
    expect(r.ok).toBe(true);
  });
});
```

- [ ] **Step 3: Run the test**

Run: `bun test test/config-fail-closed.test.ts`
Expected: FAIL. Current loader returns a bare `Config` with silent drops.

- [ ] **Step 4: Convert the loader**

In `src/config.ts`, change `loadConfigFromString` (and its callers that still use the old shape) to return `LoadResult`. In the overlap check:

```ts
import { allowedPathOverlapsSensitive } from "./predicates/config";

// ... after YAML parse ...

const requested = parsed.allowed_paths ?? [];
const overlaps = requested.filter(allowedPathOverlapsSensitive);

if (overlaps.length > 0 && !parsed.allowOverlapWarn) {
  return {
    ok: false,
    reason:
      `allowed_paths overlaps sensitive dirs: ${overlaps.join(", ")}. ` +
      `Remove the entries, or set allowOverlapWarn: true (deprecated, removed next release).`,
  };
}

const warnings: string[] = [];
if (parsed.allowOverlapWarn && overlaps.length > 0) {
  warnings.push(
    `allowOverlapWarn is deprecated and will be removed in the next release. ` +
      `Dropped overlapping allowed_paths: ${overlaps.join(", ")}`,
  );
}

const allowed_paths = requested.filter(p => !allowedPathOverlapsSensitive(p));
return { ok: true, config: { ...parsed, allowed_paths }, warnings };
```

Update every call site (`hooks/pretooluse.ts`, `src/evaluate.ts`, etc.) to destructure the result. On `ok: false`: write `reason` to stderr, fall back to the default config, and let the hook still emit a valid `HookOutput` (favoring `ask` for the triggering call if a decision is required).

- [ ] **Step 5: Remove the silent-drop branch**

In `src/predicates/config.ts`, `filterAllowedPaths` now only runs during the soft-mode path (because the fail-closed branch exits earlier). Keep the function; it's still called when `allowOverlapWarn` is true. Remove any `process.stderr.write` inside the predicate (warnings flow through `LoadResult.warnings` now).

- [ ] **Step 6: Adapt the existing property test**

Open `test/config-containment.test.ts`. Every place it treats the return of the loader as a bare `Config`, unwrap via `if (r.ok) ...`. For overlap-generating inputs in the property generator, either (a) add `allowOverlapWarn: true` so the soft path runs, or (b) assert `r.ok === false`. Prefer (a) if the property is about "overrides can't loosen"; prefer (b) if the property is about "overlap rejected".

- [ ] **Step 7: Run all tests**

Run: `bun run typecheck && bun test`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/predicates/config.ts src/config.ts test/config-fail-closed.test.ts test/config-containment.test.ts
git commit -m "feat(config): fail-closed on allowed_paths overlap

Config load now rejects overlapping allowed_paths by default and
falls back to the default config with an stderr reason. The
previous drop-with-warn behavior remains available for one release
via \`allowOverlapWarn: true\`, gated with a deprecation notice.
Resolves design item I2."
```

---

## Task F5: G4 golden-corpus regression gate

Add a 100-entry corpus of real-world multi-stage benign commands and assert each stays at `allow` or `context`.

**Files:**
- Create: `test/fixtures/composition-golden.txt`
- Create: `test/composition-golden.test.ts`

- [ ] **Step 1: Write the 100-entry corpus**

Create `test/fixtures/composition-golden.txt`. 100 non-empty, non-comment lines. Seed from the design doc's starter list and expand with common dev-workflow incantations. Examples (fill out to 100):

```
cd /tmp && ls
git pull && npm test
make && make install
mkdir build && cd build
find . -name '*.ts' && echo done
[ -f x ] || touch x
test -d .git && git status
npm ci && npm run build
docker compose up -d && docker compose logs -f
kubectl apply -f k.yaml && kubectl get pods
terraform plan && terraform apply -auto-approve
git fetch && git rebase origin/main
mvn -q package && java -jar target/app.jar
go build ./... && go test ./...
cargo build --release && cargo test
rustup update && rustc --version
pip install -r requirements.txt && pytest
poetry install && poetry run pytest
uv sync && uv run pytest
bundle install && bundle exec rspec
git add . && git commit -m 'wip'
git stash && git pull
git stash pop || git status
make clean && make
cd src && ls *.ts
[ -d node_modules ] || npm install
echo "hello" > /tmp/a.txt
sort /tmp/a.txt | uniq -c
ps aux | grep node
df -h && du -sh *
tar czf /tmp/a.tar.gz src
gzip -d /tmp/a.gz && cat /tmp/a
tree -L 2 && du -sh .
wc -l src/*.ts
ls -la && pwd
history | tail -20
jobs ; wait
echo $?
cat /etc/hostname
uname -a
which bash
type cd
command -v git
hash -r
set | head
env | grep PATH
export X=1 && echo $X
unset X && echo ${X:-default}
source ~/.bashrc
. ~/.bashrc
alias ll='ls -la' && ll
declare -p PATH
readonly FOO=1
shopt -s globstar
bash --version
sh -c 'echo hi'
time ls
nice -n 10 echo hi
nohup sleep 60 &
stdbuf -o0 ls
timeout 1 sleep 10 || echo timed-out
xargs echo < /tmp/a.txt
seq 1 10 | xargs -n1 echo
printf "%s\n" a b c
read -r x < /dev/null
test -n "$PATH"
expr 1 + 2
let x=1+2
bc <<<"1+2"
true && echo ok
false || echo err
: noop
(echo subshell)
{ echo group ; echo group2 ; }
for i in 1 2 3 ; do echo $i ; done
while read x ; do echo $x ; done < /tmp/a.txt
until false ; do break ; done
case x in x) echo match ;; esac
if true ; then echo yes ; fi
select x in a b ; do break ; done <<<1
function foo { echo in-foo ; } ; foo
trap 'echo trap' INT
exec > /tmp/log
exec 3< /tmp/a.txt
ulimit -n
umask 022
cd - && ls
pushd /tmp && popd
dirs -v
complete -W "a b" foo
bind -P | head
help cd
declare -f cd
typeset -i x=1
compgen -c | head
shopt -p
set -o | head
compopt -o nospace cd
```

Count: verify `wc -l` reports ≥ 100 non-empty lines.

- [ ] **Step 2: Write the failing regression test**

Create `test/composition-golden.test.ts`:

```ts
import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { evaluate } from "../src/bash-guard";

const lines = readFileSync("test/fixtures/composition-golden.txt", "utf8")
  .split("\n")
  .map(l => l.trim())
  .filter(l => l.length > 0 && !l.startsWith("#"));

describe("G4 golden corpus: benign multi-stage commands stay permissive", () => {
  test("corpus has at least 100 entries", () => {
    expect(lines.length).toBeGreaterThanOrEqual(100);
  });

  for (const line of lines) {
    test(`benign: ${line}`, () => {
      const decision = evaluate(line);
      expect(["allow", "context"]).toContain(decision);
    });
  }
});
```

- [ ] **Step 3: Run and triage over-firing**

Run: `bun test test/composition-golden.test.ts`
Expected: PASS. Any FAIL means G4's cross-reset persistence is over-firing on a benign pattern. Two options:

1. Remove the offending line from the corpus only if it is genuinely not benign (document why in a comment above the line).
2. Tighten the persistence rule in `src/composition.ts`: the persisted flags should fire only when the downstream stage consumes data from the upstream stage (shared file, `$(..)`, read pipe). Pure sequential operators (`&&`/`||`/`;`/newline) without data flow should not trigger escalation by themselves.

Iterate until the corpus is clean.

- [ ] **Step 4: Commit**

```bash
git add test/fixtures/composition-golden.txt test/composition-golden.test.ts src/composition.ts
git commit -m "test(composition): 100-entry golden corpus for G4

Asserts real-world multi-stage benign commands (cd && ls, git pull
&& npm test, docker compose up -d && logs, etc.) stay at allow or
context after G4's cross-reset persistence. Fails CI if
persistence over-fires. Resolves design item I1."
```

---

## Task F6: Pin fast-check seed

`test/parity-writes-property.test.ts` (and any other fast-check users) are deterministic in structure but not seed-reproducible. Pin a global seed.

**Files:**
- Modify: `test/parity-writes-property.test.ts`
- Modify: any other `test/*.test.ts` that calls `fc.assert` (enumerate with grep)
- Create: `test/fast-check-setup.ts`

- [ ] **Step 1: Enumerate fast-check call sites**

Run: `grep -rn "fc.assert\|fc.property\|fc.configureGlobal" test/`
Expected: list of files. Note each file path.

- [ ] **Step 2: Create a shared setup module**

Create `test/fast-check-setup.ts`:

```ts
import fc from "fast-check";

const SEED = 0x5EED;
fc.configureGlobal({ seed: SEED, numRuns: 200 });

export const FAST_CHECK_SEED = SEED;
```

- [ ] **Step 3: Import the setup from every fast-check test**

At the top of each file listed in Step 1, add:

```ts
import "./fast-check-setup";
```

(Adjust relative path if a subdir is involved.)

- [ ] **Step 4: Add a regression test that the seed is pinned**

Create `test/fast-check-seed.test.ts`:

```ts
import { describe, test, expect } from "bun:test";
import fc from "fast-check";
import { FAST_CHECK_SEED } from "./fast-check-setup";

describe("fast-check seed", () => {
  test("global seed is pinned to FAST_CHECK_SEED", () => {
    const cfg = fc.readConfigureGlobal();
    expect(cfg.seed).toBe(FAST_CHECK_SEED);
  });
});
```

- [ ] **Step 5: Run the suite twice and diff**

Run: `bun test > /tmp/run1.txt 2>&1 && bun test > /tmp/run2.txt 2>&1 && diff /tmp/run1.txt /tmp/run2.txt`
Expected: no diff in fast-check failure seeds (timestamps and test durations are allowed to differ; fast-check counterexample reports, if any, must be identical across runs).

- [ ] **Step 6: Commit**

```bash
git add test/fast-check-setup.ts test/fast-check-seed.test.ts test/parity-writes-property.test.ts test/config-containment.test.ts test/operator-reset.test.ts
# add any other test/*.test.ts updated in Step 3
git commit -m "test: pin fast-check global seed for reproducibility

All fast-check tests now share test/fast-check-setup.ts which
configures seed=0x5EED and numRuns=200. Reruns produce identical
counterexamples. Resolves design item I4."
```

---

## Task F7: CI wall-time per-shard enforcement

Add `scripts/measure-z3.ts` to enforce per-shard and total budgets. Wire it into CI.

**Files:**
- Create: `scripts/measure-z3.ts`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the measurement script**

Create `scripts/measure-z3.ts`:

```ts
#!/usr/bin/env -S npx tsx
import { readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";

const SHARD_BUDGET_MS = 30_000;
const SUITE_BUDGET_MS = 60_000;

const shards = readdirSync("test")
  .filter(f => /^z3-.*\.test\.ts$/.test(f))
  .map(f => `test/${f}`);

let totalMs = 0;
let failed = false;

for (const shard of shards) {
  const start = Date.now();
  const r = spawnSync("bun", ["test", shard], { stdio: "inherit" });
  const elapsed = Date.now() - start;
  totalMs += elapsed;

  if (r.status !== 0) {
    console.error(`measure-z3: ${shard} FAILED`);
    failed = true;
  }
  if (elapsed > SHARD_BUDGET_MS) {
    console.error(`measure-z3: ${shard} took ${elapsed}ms (budget ${SHARD_BUDGET_MS}ms)`);
    failed = true;
  } else {
    console.log(`measure-z3: ${shard} ok (${elapsed}ms)`);
  }
}

console.log(`measure-z3: total ${totalMs}ms`);
if (totalMs > SUITE_BUDGET_MS) {
  console.error(`measure-z3: total ${totalMs}ms exceeds suite budget ${SUITE_BUDGET_MS}ms`);
  failed = true;
}

process.exit(failed ? 1 : 0);
```

- [ ] **Step 2: Run locally to establish baseline**

Run: `npx tsx scripts/measure-z3.ts`
Expected: all shards PASS and stay under 30s each; total under 60s. If a shard exceeds 20s, split it by action-type group at the test-file level (create `test/z3-<shard>-<group>.test.ts`, move half the proofs) until each shard has at least 50% headroom.

- [ ] **Step 3: Wire into CI**

Open `.github/workflows/ci.yml`. After the existing `bun test` step, add:

```yaml
      - name: Z3 wall-time gate
        run: npx tsx scripts/measure-z3.ts
```

- [ ] **Step 4: Strip any stale nightly references**

Run: `grep -rn "nightly" .github scripts docs/specs test 2>/dev/null | grep -i z3`
Expected: no matches after cleanup. If any appear, delete them.

- [ ] **Step 5: Commit**

```bash
git add scripts/measure-z3.ts .github/workflows/ci.yml
git commit -m "ci(z3): enforce per-shard wall-time budget

scripts/measure-z3.ts runs every test/z3-*.test.ts shard serially
and fails CI if any shard exceeds 30s or the total exceeds 60s.
Resolves design item I9."
```

---

## Final verification

- [ ] **Run everything**

Run: `bun run typecheck && bun run build && bun test && npx tsx scripts/measure-z3.ts`
Expected: all pass.

- [ ] **Confirm each design item is resolved in a commit**

Run: `git log --grep 'design item' --oneline origin/main..HEAD`
Expected: commits referencing I1, I2, I3, I4, I7, I8, I9 in their bodies.

- [ ] **PR description**

Reference `docs/specs/2026-04-16-z3-gap-closure-followup-design.md`. List F1-F7 with their issue resolutions. Note that I5 and I6 required no code changes (already satisfied / obsolete).
