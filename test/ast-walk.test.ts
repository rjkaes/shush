import { describe, expect, test } from "bun:test";
import { extractProcessSubs, extractStages, PROCSUB_PLACEHOLDER } from "../src/ast-walk";

describe("extractStages", () => {
  test("simple command", () => {
    const stages = extractStages("ls -la");
    expect(stages).toHaveLength(1);
    expect(stages[0].tokens).toEqual(["ls", "-la"]);
    expect(stages[0].operator).toBe("");
  });

  test("pipeline", () => {
    const stages = extractStages("cat file | grep pattern");
    expect(stages).toHaveLength(2);
    expect(stages[0].tokens).toEqual(["cat", "file"]);
    expect(stages[0].operator).toBe("|");
    expect(stages[1].tokens).toEqual(["grep", "pattern"]);
  });

  test("logical AND", () => {
    const stages = extractStages("mkdir dir && cd dir");
    expect(stages).toHaveLength(2);
    expect(stages[0].tokens).toEqual(["mkdir", "dir"]);
    expect(stages[0].operator).toBe("&&");
    expect(stages[1].tokens).toEqual(["cd", "dir"]);
  });

  test("logical OR", () => {
    const stages = extractStages("test -f file || echo missing");
    expect(stages).toHaveLength(2);
    expect(stages[0].operator).toBe("||");
  });

  test("semicolons", () => {
    const stages = extractStages("echo a; echo b; echo c");
    expect(stages).toHaveLength(3);
  });

  test("redirect detection", () => {
    const stages = extractStages("echo hello > output.txt");
    expect(stages).toHaveLength(1);
    expect(stages[0].tokens).toEqual(["echo", "hello"]);
    expect(stages[0].redirectTarget).toBe("output.txt");
  });

  test("append redirect", () => {
    const stages = extractStages("echo hello >> log.txt");
    expect(stages).toHaveLength(1);
    expect(stages[0].redirectTarget).toBe("log.txt");
    expect(stages[0].redirectAppend).toBe(true);
  });

  test("subshell extraction", () => {
    const stages = extractStages("(cd dir && ls)");
    expect(stages.length).toBeGreaterThanOrEqual(1);
  });

  test("env var prefix stripped", () => {
    const stages = extractStages("FOO=bar baz qux");
    expect(stages).toHaveLength(1);
    expect(stages[0].tokens).toEqual(["baz", "qux"]);
  });

  test("empty command", () => {
    const stages = extractStages("");
    expect(stages).toHaveLength(0);
  });

  test("fallback split detects redirect", () => {
    // [[ ]] forces fallback; redirect should still be extracted
    const stages = extractStages("[[ -f file ]] && echo hello > out.txt");
    const echoStage = stages.find((s) => s.tokens[0] === "echo");
    expect(echoStage).toBeDefined();
    expect(echoStage!.redirectTarget).toBe("out.txt");
    expect(echoStage!.redirectAppend).toBe(false);
    // > and out.txt should NOT appear in tokens
    expect(echoStage!.tokens).not.toContain(">");
    expect(echoStage!.tokens).not.toContain("out.txt");
  });

  test("parse failure falls back to shlex-like split", () => {
    // bash-parser can't handle [[ ]] — should fall back gracefully
    const stages = extractStages("[[ -f file ]]");
    expect(stages.length).toBeGreaterThanOrEqual(1);
  });

  test("fallback split respects quoted pipe symbols", () => {
    // Force fallback by using [[ ]] syntax that bash-parser can't handle.
    // The key assertion: grep and its arguments stay in one stage,
    // not split on the \| inside quotes.
    const stages = extractStages("[[ -f file ]] && grep -rn 'deleteFrom\\|clearTable' .");
    const grepStage = stages.find((s) => s.tokens[0] === "grep");
    expect(grepStage).toBeDefined();
    expect(grepStage!.tokens[0]).toBe("grep");
    expect(grepStage!.tokens).toHaveLength(4); // grep -rn <pattern> .
  });
});

describe("extractProcessSubs", () => {
  test("extracts output process substitution", () => {
    const { cleaned, subs } = extractProcessSubs("tee >(cat -n)");
    expect(cleaned).toBe(`tee ${PROCSUB_PLACEHOLDER}`);
    expect(subs).toEqual(["cat -n"]);
  });

  test("extracts input process substitution", () => {
    const { cleaned, subs } = extractProcessSubs("diff <(ls dir1) <(ls dir2)");
    expect(cleaned).toBe(`diff ${PROCSUB_PLACEHOLDER} ${PROCSUB_PLACEHOLDER}`);
    expect(subs).toEqual(["ls dir1", "ls dir2"]);
  });

  test("ignores process subs inside single quotes", () => {
    const { cleaned, subs } = extractProcessSubs("echo '>(not a sub)'");
    expect(cleaned).toBe("echo '>(not a sub)'");
    expect(subs).toHaveLength(0);
  });

  test("ignores process subs inside double quotes", () => {
    const { cleaned, subs } = extractProcessSubs('echo ">(not a sub)"');
    expect(cleaned).toBe('echo ">(not a sub)"');
    expect(subs).toHaveLength(0);
  });

  test("handles nested parens", () => {
    const { cleaned, subs } = extractProcessSubs("tee >(grep $(echo pattern))");
    expect(cleaned).toBe(`tee ${PROCSUB_PLACEHOLDER}`);
    expect(subs).toEqual(["grep $(echo pattern)"]);
  });

  test("no-op when no process subs present", () => {
    const { cleaned, subs } = extractProcessSubs("ls -la");
    expect(cleaned).toBe("ls -la");
    expect(subs).toHaveLength(0);
  });
});
