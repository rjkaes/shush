import { describe, expect, test } from "bun:test";
import {
  hydrate,
  checkFlagRules,
  type CompiledFlagRulesJSON,
} from "../src/flag-rules";

// ---------------------------------------------------------------------------
// Helpers — build inline rule sets for each test scenario
// ---------------------------------------------------------------------------

function rules(json: CompiledFlagRulesJSON) {
  return hydrate(json);
}

// ---------------------------------------------------------------------------
// anyFlagPrefix
// ---------------------------------------------------------------------------

describe("anyFlagPrefix", () => {
  const map = rules({
    sed: [
      {
        match: { anyFlagPrefix: ["-i", "-I", "--in-place"] },
        type: "filesystem_write",
      },
    ],
  });

  test("sed -i matches", () => {
    expect(checkFlagRules("sed", ["sed", "-i", "s/a/b/", "file"], map)).toBe(
      "filesystem_write",
    );
  });

  test("sed -i.bak matches prefix", () => {
    expect(
      checkFlagRules("sed", ["sed", "-i.bak", "s/a/b/", "file"], map),
    ).toBe("filesystem_write");
  });

  test("sed --in-place=.bak matches", () => {
    expect(
      checkFlagRules("sed", ["sed", "--in-place=.bak", "s/a/b/", "file"], map),
    ).toBe("filesystem_write");
  });

  test("sed without -i returns null", () => {
    expect(checkFlagRules("sed", ["sed", "s/a/b/", "file"], map)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// tokenMatches (regex on individual tokens)
// ---------------------------------------------------------------------------

describe("tokenMatches", () => {
  const map = rules({
    sed: [
      {
        match: { tokenMatches: "^-[^-]*[iI]" },
        type: "filesystem_write",
      },
    ],
  });

  test("sed -ni matches combined short flag", () => {
    expect(
      checkFlagRules("sed", ["sed", "-ni", "s/a/b/", "file"], map),
    ).toBe("filesystem_write");
  });

  test("sed without matching token returns null", () => {
    expect(
      checkFlagRules("sed", ["sed", "-e", "s/a/b/", "file"], map),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// anyFlag (exact match from a set)
// ---------------------------------------------------------------------------

describe("anyFlag", () => {
  const map = rules({
    curl: [
      {
        match: { anyFlag: ["-d", "--data", "--data-raw", "--data-binary"] },
        type: "network_write",
      },
    ],
  });

  test("curl -d matches", () => {
    expect(
      checkFlagRules("curl", ["curl", "-d", "payload", "http://x"], map),
    ).toBe("network_write");
  });

  test("curl without data flags returns null", () => {
    expect(
      checkFlagRules("curl", ["curl", "http://x"], map),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// flag + nextIn
// ---------------------------------------------------------------------------

describe("flag + nextIn", () => {
  const map = rules({
    curl: [
      {
        match: { flag: "-X", nextIn: ["POST", "PUT", "PATCH", "DELETE"] },
        type: "network_write",
      },
    ],
  });

  test("curl -X POST matches", () => {
    expect(
      checkFlagRules("curl", ["curl", "-X", "POST", "http://x"], map),
    ).toBe("network_write");
  });

  test("curl -X GET does not match", () => {
    expect(
      checkFlagRules("curl", ["curl", "-X", "GET", "http://x"], map),
    ).toBeNull();
  });

  test("curl -X at end of tokens (no next) returns null", () => {
    expect(
      checkFlagRules("curl", ["curl", "-X"], map),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// anyToken (substring match across all tokens)
// ---------------------------------------------------------------------------

describe("anyToken", () => {
  const map = rules({
    awk: [
      {
        match: { anyToken: "system(" },
        type: "process_launch",
      },
    ],
  });

  test("awk with system( matches", () => {
    expect(
      checkFlagRules("awk", ["awk", '{system("rm -rf /")}'], map),
    ).toBe("process_launch");
  });

  test("awk without dangerous patterns returns null", () => {
    expect(
      checkFlagRules("awk", ["awk", "{print $1}", "file"], map),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Unknown command returns null
// ---------------------------------------------------------------------------

describe("unknown command", () => {
  const map = rules({
    sed: [
      {
        match: { anyFlagPrefix: ["-i"] },
        type: "filesystem_write",
      },
    ],
  });

  test("unknown command returns null", () => {
    expect(
      checkFlagRules("ls", ["ls", "-la"], map),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Set hydration — verify O(1) behavior works with large flag set
// ---------------------------------------------------------------------------

describe("set hydration", () => {
  test("large anyFlag set hydrates and lookups work", () => {
    const flags = Array.from({ length: 1000 }, (_, i) => `--flag-${i}`);
    const map = rules({
      bigcmd: [{ match: { anyFlag: flags }, type: "some_type" }],
    });

    // First and last flag should match
    expect(
      checkFlagRules("bigcmd", ["bigcmd", "--flag-0"], map),
    ).toBe("some_type");
    expect(
      checkFlagRules("bigcmd", ["bigcmd", "--flag-999"], map),
    ).toBe("some_type");

    // A flag not in the set should not match
    expect(
      checkFlagRules("bigcmd", ["bigcmd", "--flag-1000"], map),
    ).toBeNull();
  });

  test("large nextIn set hydrates and lookups work", () => {
    const values = Array.from({ length: 1000 }, (_, i) => `VAL${i}`);
    const map = rules({
      bigcmd: [{ match: { flag: "-X", nextIn: values }, type: "some_type" }],
    });

    expect(
      checkFlagRules("bigcmd", ["bigcmd", "-X", "VAL500"], map),
    ).toBe("some_type");
    expect(
      checkFlagRules("bigcmd", ["bigcmd", "-X", "NOPE"], map),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// First match wins ordering
// ---------------------------------------------------------------------------

describe("first match wins", () => {
  test("earlier rule takes precedence over later rule", () => {
    const map = rules({
      sed: [
        {
          match: { anyFlagPrefix: ["-i"] },
          type: "filesystem_write",
        },
        {
          match: { tokenMatches: "^-[^-]*[iI]" },
          type: "filesystem_modify",
        },
      ],
    });

    // -i matches both rules; first should win
    expect(
      checkFlagRules("sed", ["sed", "-i", "s/a/b/", "file"], map),
    ).toBe("filesystem_write");
  });

  test("second rule matches when first does not", () => {
    const map = rules({
      sed: [
        {
          match: { anyFlagPrefix: ["-i"] },
          type: "filesystem_write",
        },
        {
          match: { tokenMatches: "^-[^-]*[iI]" },
          type: "filesystem_modify",
        },
      ],
    });

    // -nI does not match anyFlagPrefix -i, but matches tokenMatches
    expect(
      checkFlagRules("sed", ["sed", "-nI", "s/a/b/", "file"], map),
    ).toBe("filesystem_modify");
  });
});
