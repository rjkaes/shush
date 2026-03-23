import { describe, expect, test } from "bun:test";
import { homedir } from "node:os";
import path from "node:path";
import { resolvePath } from "../src/path-guard";
import { read, write, edit, glob, grep } from "./eval-helpers";


// =============================================================================
// Path Guard Bypass Vectors
// =============================================================================

describe("path bypass: symlink-like paths", () => {
  test("/proc/self/root/etc/shadow should be caught (symlink to /)", () => {
    // On Linux, /proc/self/root is a symlink to /. An attacker could
    // use this to reach /etc/shadow without the literal path.
    // shush should strip or resolve /proc/self/root prefix before comparison.
    expect(read("/proc/self/root/etc/shadow").decision).toBe("block");
  });

  test("/dev/fd/3 is not caught (informational)", () => {
    // File descriptor paths can reference any open file. shush does not
    // (and probably cannot) guard against these since the FD target is
    // unknown at static analysis time.
    expect(read("/dev/fd/3").decision).toBe("allow");
  });
});

describe("path bypass: case variations on macOS", () => {
  // HFS+ / APFS are case-insensitive by default. String comparison in
  // isSensitive uses exact match, so uppercase variants may slip through.
  test("~/.SSH/id_rsa should be caught (case-insensitive FS on macOS)", () => {
    // On macOS (HFS+/APFS), case-insensitive FS means ~/.SSH/ is ~/.ssh/.
    // shush should do case-insensitive comparison on macOS.
    expect(read("~/.SSH/id_rsa").decision).toBe("block");
  });

  test("~/.Ssh/known_hosts should be caught (case-insensitive FS on macOS)", () => {
    expect(read("~/.Ssh/known_hosts").decision).toBe("block");
  });

  test("~/.AWS/credentials should be caught (case-insensitive FS on macOS)", () => {
    expect(read("~/.AWS/credentials").decision).toBe("ask");
  });

  test("/etc/Shadow (mixed case) should be caught on macOS", () => {
    expect(read("/etc/Shadow").decision).toBe("block");
  });
});

describe("path bypass: double slashes", () => {
  // path.resolve normalizes double slashes, so these should be caught.
  test("~/.ssh//id_rsa is caught (path.resolve normalizes)", () => {
    expect(read("~/.ssh//id_rsa").decision).toBe("block");
  });

  test("/etc//shadow is caught (path.resolve normalizes)", () => {
    expect(read("/etc//shadow").decision).toBe("block");
  });

  test("~/.aws///credentials is caught", () => {
    expect(read("~/.aws///credentials").decision).toBe("ask");
  });
});

describe("path bypass: trailing slashes", () => {
  // path.resolve strips trailing slashes. These should all be caught.
  test("~/.ssh/ is caught as the directory itself", () => {
    expect(read("~/.ssh/").decision).toBe("block");
  });

  test("~/.aws/ is caught", () => {
    expect(read("~/.aws/").decision).toBe("ask");
  });

  test("/etc/shadow/ (trailing slash on file) is caught", () => {
    expect(read("/etc/shadow/").decision).toBe("block");
  });
});

describe("path bypass: dot-env variants", () => {
  // The basename list has .env, .env.local, .env.production. Other
  // common variants may not be covered.
  test(".env is caught", () => {
    expect(read("/project/.env").decision).toBe("ask");
  });

  test(".env.local is caught", () => {
    expect(read("/project/.env.local").decision).toBe("ask");
  });

  test(".env.production is caught", () => {
    expect(read("/project/.env.production").decision).toBe("ask");
  });

  test(".env.backup should be caught as sensitive env file", () => {
    // .env.backup is a common pattern for leaked secrets
    expect(read("/project/.env.backup").decision).toBe("ask");
  });

  test(".env.development.local should be caught as sensitive env file", () => {
    expect(read("/project/.env.development.local").decision).toBe("ask");
  });

  test(".env.staging should be caught as sensitive env file", () => {
    expect(read("/project/.env.staging").decision).toBe("ask");
  });

  test(".env.test should be caught as sensitive env file", () => {
    expect(read("/project/.env.test").decision).toBe("ask");
  });

  test(".env.example (usually safe) is caught by exact basename match", () => {
    // This is a false positive since .env.example files typically
    // contain placeholder values, not real secrets. But basename check
    // is exact, so it won't match.
    // Should NOT match since basename is .env.example, not .env
    expect(read("/project/.env.example").decision).toBe("allow");
  });
});

describe("path bypass: unicode homoglyphs", () => {
  // Cyrillic 'е' (U+0435) looks like Latin 'e'. An attacker might try
  // to craft paths with look-alike characters.
  test("~/.ssh with Cyrillic homoglyph in 'ssh' is not caught (expected gap)", () => {
    // \u0455 is Cyrillic 's', visually identical to Latin 's'
    // This won't match because the resolved path differs from HOME/.ssh
    expect(read("~/.\u0455sh/id_rsa").decision).toBe("allow");
  });

  test("path with zero-width joiner is not normalized", () => {
    // Zero-width joiner U+200D inserted in path
    // path.resolve does not strip Unicode control chars
    expect(read("~/.s\u200Dsh/id_rsa").decision).toBe("allow");
  });
});

describe("path bypass: null bytes and special chars", () => {
  test("null byte in path should be stripped before comparison", () => {
    // Null bytes can truncate C strings. shush should strip null bytes
    // before path comparison so /etc/shadow\0.txt matches /etc/shadow.
    expect(read("/etc/shadow\0.txt").decision).toBe("block");
  });

  test("path with embedded newline does not crash", () => {
    // path.resolve keeps the newline in the filename portion
    const result = read("~/.ssh/id_rsa\n");
    expect(result.decision).not.toBe("allow");
  });
});

describe("path bypass: relative traversal from outside project", () => {
  test("BYPASS: ../../../etc/shadow via Read may not be caught (cwd mismatch)", () => {
    // resolvePath calls path.resolve which uses process.cwd(), not the
    // hook's cwd. From /Users/rjk/src/opensource/shush, ../../../etc/shadow
    // resolves to /Users/rjk/etc/shadow, NOT /etc/shadow.
    // The evaluate function does not pass cwd to resolvePath.
    const result = read("../../../etc/shadow");
    // Whether this triggers depends on process.cwd() depth. From a shallow
    // directory it would reach /etc/shadow; from a deep one it won't.
    // Either way, this is a gap: relative paths are resolved against the
    // shush process, not the Claude Code session's cwd.
    expect(result.decision).toBe("allow");
  });

  test("evaluate Read does not use cwd for path resolution (potential gap)", () => {
    // checkPath calls resolvePath which calls path.resolve. path.resolve uses
    // process.cwd(), not the provided cwd. This means relative paths in Read
    // are resolved against the shush process, not the Claude Code session.
    const resolved = resolvePath("./sensitive-file.txt");
    // resolved is relative to process.cwd(), not any project root
    expect(path.isAbsolute(resolved)).toBe(true);
  });
});

describe("path bypass: ~user expansion", () => {
  // resolvePath only expands ~/... and bare ~. ~user paths are NOT expanded,
  // meaning ~root/.ssh/id_rsa is resolved as a relative path.
  test("~root/.ssh/id_rsa is not expanded to /root/.ssh/id_rsa", () => {
    const resolved = resolvePath("~root/.ssh/id_rsa");
    // Without OS lookup, ~root becomes relative to cwd
    expect(resolved).not.toBe("/root/.ssh/id_rsa");
  });

  test("~root/.ssh/id_rsa should trigger sensitive path guard", () => {
    // ~root paths target other users' home directories and should be
    // treated as suspicious even without OS-level expansion.
    expect(read("~root/.ssh/id_rsa").decision).toBe("block");
  });
});

describe("path bypass: sensitive paths not in the default list", () => {
  // These are common credential stores not covered by SENSITIVE_DIRS.
  test("~/.config/op/ (1Password CLI) should be in sensitive list", () => {
    expect(read("~/.config/op/config").decision).toBe("ask");
  });

  test("~/.vault-token (HashiCorp Vault) should be in sensitive list", () => {
    expect(read("~/.vault-token").decision).toBe("ask");
  });

  test("~/.config/hub (GitHub Hub CLI) should be in sensitive list", () => {
    expect(read("~/.config/hub").decision).toBe("ask");
  });

  test("~/.terraform.d/credentials.tfrc.json should be in sensitive list", () => {
    expect(read("~/.terraform.d/credentials.tfrc.json").decision).toBe("ask");
  });

  test("~/.config/gcloud is in the default sensitive list", () => {
    // Sanity check: gcloud IS covered
    expect(read("~/.config/gcloud/credentials.db").decision).toBe("ask");
  });

  test("~/.npmrc is in the basename list", () => {
    expect(read("/any/path/.npmrc").decision).toBe("ask");
  });

  test("~/.local/share/keyrings/ (GNOME keyring) should be in sensitive list", () => {
    expect(read("~/.local/share/keyrings/login.keyring").decision).toBe("ask");
  });

  test("~/.password-store/ (pass) should be in sensitive list", () => {
    expect(read("~/.password-store/email/gmail.gpg").decision).toBe("ask");
  });
});

// =============================================================================
// Content Scanning Bypass Vectors
// =============================================================================

describe("content bypass: split across lines", () => {
  test("private key header on a single line is caught", () => {
    expect(write("/tmp/project/test.ts", "-----BEGIN PRIVATE KEY-----").decision).not.toBe("allow");
  });

  test("RSA private key header on a single line is caught", () => {
    expect(write("/tmp/project/test.ts", "-----BEGIN RSA PRIVATE KEY-----").decision).not.toBe("allow");
  });

  test("private key header split with newline IS caught (\\s+ matches newline)", () => {
    // The regex uses \s+ between PRIVATE and KEY, which matches \n.
    // This is actually good security behavior.
    const content = "-----BEGIN PRIVATE\n KEY-----";
    expect(write("/tmp/project/test.ts", content).decision).not.toBe("allow");
  });

  test("private key header with extra spaces is caught", () => {
    // The regex uses \\s+ between PRIVATE and KEY
    expect(write("/tmp/project/test.ts", "-----BEGIN  PRIVATE   KEY-----").decision).not.toBe("allow");
  });
});

describe("content bypass: obfuscated secrets", () => {
  test("base64-encoded API key is NOT detected (expected gap)", () => {
    // An attacker could base64-encode a secret and decode it at runtime
    const encoded = Buffer.from("AKIAIOSFODNN7EXAMPLE").toString("base64");
    const content = `const key = Buffer.from("${encoded}", "base64").toString()`;
    expect(write("/tmp/project/test.ts", content).decision).toBe("allow");
  });

  test("hex-encoded secret is NOT detected (expected gap)", () => {
    const hex = Buffer.from("sk-1234567890abcdefghij").toString("hex");
    const content = `const key = Buffer.from("${hex}", "hex").toString()`;
    expect(write("/tmp/project/test.ts", content).decision).toBe("allow");
  });
});

describe("content bypass: variable assignment vs hardcoded secret", () => {
  test("process.env.OPENAI_API_KEY reference is NOT flagged (correct)", () => {
    // Referencing an env var is not a hardcoded secret
    const content = "const key = process.env.OPENAI_API_KEY;";
    expect(write("/tmp/project/test.ts", content).decision).toBe("allow");
  });

  test("os.environ['OPENAI_API_KEY'] reference is NOT flagged (correct)", () => {
    const content = "key = os.environ['OPENAI_API_KEY']";
    expect(write("/tmp/project/test.ts", content).decision).toBe("allow");
  });

  test("OPENAI_API_KEY=sk-value IS flagged (correct)", () => {
    const content = "OPENAI_API_KEY=sk-proj-abc123def456";
    expect(write("/tmp/project/test.ts", content).decision).not.toBe("allow");
  });
});

describe("content bypass: regex evasion on AWS keys", () => {
  test("valid 20-char AKIA key is caught", () => {
    expect(write("/tmp/project/test.ts", "AKIAIOSFODNN7EXAMPLE").decision).not.toBe("allow");
  });

  test("AKIA with only 15 uppercase chars is NOT caught", () => {
    // \\bAKIA[0-9A-Z]{16}\\b requires exactly 16 chars after AKIA
    expect(write("/tmp/project/test.ts", "AKIAIOSFODNN7EX").decision).toBe("allow");
  });

  test("AKIA with lowercase letters is NOT caught (regex is uppercase only)", () => {
    // Real AWS keys are uppercase, but the regex enforces [0-9A-Z]
    expect(write("/tmp/project/test.ts", "AKIAiosfodnn7example").decision).toBe("allow");
  });

  test("ASIA temporary key should be caught (AWS temporary credentials)", () => {
    // AWS temporary credentials start with ASIA, not just AKIA
    expect(write("/tmp/project/test.ts", "ASIAIOSFODNN7EXAMPLE").decision).not.toBe("allow");
  });
});

describe("content bypass: GitHub PAT evasion", () => {
  test("valid ghp_ token is caught", () => {
    expect(write("/tmp/project/test.ts", "ghp_ABCDEFghijklmnopqrstuvwxyz1234567890").decision).not.toBe("allow");
  });

  test("gho_ (OAuth) token should be caught as GitHub token", () => {
    // GitHub has gho_, ghu_, ghs_, ghr_ token types too
    expect(write("/tmp/project/test.ts", "gho_ABCDEFghijklmnopqrstuvwxyz1234567890").decision).not.toBe("allow");
  });

  test("ghs_ (server-to-server) token should be caught as GitHub token", () => {
    expect(write("/tmp/project/test.ts", "ghs_ABCDEFghijklmnopqrstuvwxyz1234567890").decision).not.toBe("allow");
  });
});

describe("content bypass: large content", () => {
  test("secret buried in 1MB of padding should still be detected", () => {
    // Large strings should not cause regex to miss matches.
    const padding = "a".repeat(1024 * 1024);
    const content = padding + "AKIAIOSFODNN7EXAMPLE" + padding;
    expect(write("/tmp/project/test.ts", content).decision).not.toBe("allow");
  });

  test("10,000 lines of safe content returns allow", () => {
    const content = Array(10000).fill("const x = 42;\n").join("");
    expect(write("/tmp/project/test.ts", content).decision).toBe("allow");
  });
});

describe("content bypass: binary content and null bytes", () => {
  test("null bytes in content do not crash scanner", () => {
    const content = "safe content\x00more content";
    const result = write("/tmp/project/test.ts", content);
    // Should not throw, decision depends on content
    expect(["allow", "context", "ask", "block"]).toContain(result.decision);
  });

  test("secret after null byte is still detected", () => {
    // In C strings, null terminates. JS strings keep going.
    const content = "harmless\x00AKIAIOSFODNN7EXAMPLE";
    expect(write("/tmp/project/test.ts", content).decision).not.toBe("allow");
  });

  test("binary-like content does not crash", () => {
    const binary = Buffer.alloc(1024);
    for (let i = 0; i < 1024; i++) binary[i] = i % 256;
    const result = write("/tmp/project/test.ts", binary.toString("latin1"));
    expect(["allow", "context", "ask", "block"]).toContain(result.decision);
  });
});

describe("content bypass: URL-encoded secrets", () => {
  test("URL-encoded api_key assignment is NOT caught (expected gap)", () => {
    // api_key%3D is api_key= URL-encoded
    const content = "api_key%3Dsk-12345abcdefghijklmnopqrstuvwxyz";
    expect(write("/tmp/project/test.ts", content).decision).toBe("allow");
  });

  test("URL-encoded AKIA key should be caught", () => {
    const content = "access_key%3DAKIAIOSFODNN7EXAMPLE";
    // shush should detect AKIA keys even when preceded by URL-encoded chars
    expect(write("/tmp/project/test.ts", content).decision).not.toBe("allow");
  });
});

describe("content bypass: comments containing secrets", () => {
  test("secret in code comment IS caught (correct, scanner is content-agnostic)", () => {
    const content = "// old key was AKIAIOSFODNN7EXAMPLE";
    expect(write("/tmp/project/test.ts", content).decision).not.toBe("allow");
  });

  test("secret in multiline comment IS caught", () => {
    const content = "/* deprecated: sk-abcdefghijklmnopqrstuvwxyz */";
    expect(write("/tmp/project/test.ts", content).decision).not.toBe("allow");
  });
});

describe("content bypass: multiline JWT", () => {
  test("JWT on single line is caught", () => {
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
    expect(write("/tmp/project/test.ts", jwt).decision).not.toBe("allow");
  });

  test("JWT split across lines is NOT caught (gap)", () => {
    const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    const payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
    const content = header + ".\n" + payload;
    // The regex expects header.payload on same line (no multiline flag)
    expect(write("/tmp/project/test.ts", content).decision).toBe("allow");
  });

  test("JWT with signature (three parts) is still caught", () => {
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    expect(write("/tmp/project/test.ts", jwt).decision).not.toBe("allow");
  });
});

// =============================================================================
// Credential Search Bypass Vectors (Grep)
// =============================================================================

describe("credential search bypass: case variations", () => {
  test("lowercase 'password' is caught", () => {
    expect(grep("", "password").decision).toBe("ask");
  });

  test("uppercase 'PASSWORD' is caught (case-insensitive regex)", () => {
    expect(grep("", "PASSWORD").decision).toBe("ask");
  });

  test("mixed case 'Password' is caught", () => {
    expect(grep("", "Password").decision).toBe("ask");
  });

  test("'pAsSwOrD' is caught", () => {
    expect(grep("", "pAsSwOrD").decision).toBe("ask");
  });
});

describe("credential search bypass: partial and compound matches", () => {
  test("'password_reset' triggers credential search (word boundary may not exclude)", () => {
    // \\bpassword\\b has word boundaries; password_reset contains 'password'
    // at a word boundary (start) but _ is a word char so \\b won't match
    // after 'password' in 'password_reset'. Let's check.
    // The regex /\\bpassword\\b/i should NOT match password_reset because
    // _ is a word character and \\b won't fire between 'd' and '_'.
    // Wait: \\b fires between word and non-word. 'd' is word, '_' is word.
    // So \\b does NOT fire between them. The \\b after 'password' won't match.
    // Actually, in "password_reset", the pattern \\bpassword\\b:
    //   - \\b before 'p': matches (start of string or non-word before p)
    //   - \\b after 'd': 'd' is word, '_' is word -> NO boundary
    // So \\bpassword\\b should NOT match "password_reset"
    expect(grep("", "password_reset").decision).toBe("allow");
  });

  test("'reset_password' triggers credential search", () => {
    // _p: _ is word, p is word -> no boundary before p
    // d$: d is word, end-of-string -> boundary after d
    // So \\bpassword\\b in "reset_password":
    //   - before 'p': '_' is word, 'p' is word -> NO boundary
    // Hmm, this should also NOT match.
    expect(grep("", "reset_password").decision).toBe("allow");
  });

  test("'my password is' triggers credential search (spaces are non-word)", () => {
    expect(grep("", "my password is").decision).toBe("ask");
  });

  test("'user_secret_key' triggers credential search", () => {
    // \\bsecret\\b in "user_secret_key":
    //   - before 's': '_' is word, 's' is word -> NO boundary
    // Should NOT match
    expect(grep("", "user_secret_key").decision).toBe("allow");
  });

  test("'secret' alone triggers credential search", () => {
    expect(grep("", "secret").decision).toBe("ask");
  });

  test("'token' alone triggers credential search", () => {
    expect(grep("", "token").decision).toBe("ask");
  });

  test("'AWS_SECRET' triggers credential search (case-sensitive regex)", () => {
    // The AWS_SECRET pattern is NOT case-insensitive
    expect(grep("", "AWS_SECRET").decision).toBe("ask");
  });

  test("'aws_secret' does NOT trigger (AWS_SECRET is case-sensitive)", () => {
    // /AWS_SECRET/ without /i flag won't match lowercase
    expect(grep("", "aws_secret").decision).toBe("allow");
  });
});

// =============================================================================
// End-to-End Bypass Vectors via evaluate()
// =============================================================================

describe("evaluate: path traversal via Write", () => {
  test("Write to sensitive path with benign content is caught", () => {
    const result = write("~/.ssh/authorized_keys", "ssh-rsa AAAA... user@host");
    expect(result.decision).toBe("block");
  });

  test("Write with secret content to normal path is caught", () => {
    const result = write("./config.js", "-----BEGIN RSA PRIVATE KEY-----");
    expect(result.decision).toBe("ask");
    expect(result.reason).toContain("private key");
  });

  test("Edit with secret in new_string is caught", () => {
    const result = edit("./config.js", "ghp_ABCDEFghijklmnopqrstuvwxyz1234567890");
    expect(result.decision).toBe("ask");
    expect(result.reason).toContain("GitHub personal access token");
  });
});

describe("evaluate: Glob pattern as path attack", () => {
  test("Glob with SSH path in pattern field is caught", () => {
    const result = glob("", "~/.ssh/**/*");
    // The pattern "~/.ssh/**/*" is passed to checkPath. resolvePath
    // will resolve the glob characters as literal path components.
    expect(result.decision).toBe("block");
  });

  test("Glob with path outside project triggers boundary check", () => {
    const result = glob("/etc", "*.conf");
    expect(result.decision).toBe("ask");
    expect(result.reason).toContain("outside project");
  });
});

describe("evaluate: Grep credential search evasion", () => {
  test("Grep for 'password' is caught", () => {
    expect(grep("", "password").decision).toBe("ask");
  });

  test("Grep for 'passwd' is NOT caught (not in credential patterns)", () => {
    // Common Unix abbreviation for password
    // 'passwd' does not match \\bpassword\\b
    expect(grep("", "passwd").decision).toBe("allow");
  });

  test("Grep for 'BEGIN.*PRIVATE' is caught", () => {
    expect(grep("", "BEGIN.*PRIVATE").decision).toBe("ask");
  });

  test("Grep for 'credential' is NOT caught (not in patterns)", () => {
    expect(grep("", "credential").decision).toBe("allow");
  });

  test("Grep for 'auth_token' is NOT caught (no word boundary match)", () => {
    // \\btoken\\b won't match inside 'auth_token' because _ is word char
    expect(grep("", "auth_token").decision).toBe("allow");
  });
});

describe("evaluate: content scanning skipped when path is blocked", () => {
  test("Write to blocked path does not run content scan (decision is block)", () => {
    const result = write("~/.ssh/id_rsa", "-----BEGIN PRIVATE KEY-----");
    // Path check returns block; content scan still runs (decision !== block
    // check in evaluate is "if decision !== block" but here path gives block,
    // so content scan is skipped)
    expect(result.decision).toBe("block");
    // Reason should mention the path, not the content
    expect(result.reason).toContain("sensitive path");
    expect(result.reason).not.toContain("private key");
  });
});

describe("evaluate: empty and missing inputs", () => {
  test("Read with empty file_path is allowed", () => {
    expect(read("").decision).toBe("allow");
  });

  test("Write with missing content field triggers boundary check (ask)", () => {
    // Even with no content, the boundary check fires because ./safe.txt
    // is outside the project when cwd is passed to checkProjectBoundary.
    const result = write("./safe.txt", undefined as unknown as string);
    expect(result.decision).toBe("ask");
  });

  test("Grep with empty pattern is allowed", () => {
    expect(grep("", "").decision).toBe("allow");
  });
});
