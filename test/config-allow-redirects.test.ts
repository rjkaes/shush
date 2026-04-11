import { describe, expect, test } from "bun:test";
import { bash } from "./eval-helpers";
import type { ShushConfig } from "../src/types";

// =============================================================================
// P1b: Config allow_redirects — whitelist redirect targets via glob patterns
// =============================================================================

describe("config allow_redirects", () => {
  test("redirect to whitelisted path stays at base classification", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      allowRedirects: ["/tmp/**"],
    };
    const result = bash("echo hello > /tmp/out.txt", config);
    // Without allow_redirects, this would be context (filesystem_write).
    // With /tmp/** whitelisted, the redirect is exempt.
    expect(result.decision).toBe("allow");
  });

  test("redirect to non-whitelisted path still escalates", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      allowRedirects: ["/tmp/**"],
    };
    const result = bash("echo hello > /var/data/out.txt", config);
    expect(result.decision).toBe("context");
  });

  test("relative glob pattern matches relative redirect target", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      allowRedirects: ["build/**"],
    };
    const result = bash("echo hello > build/output.js", config);
    expect(result.decision).toBe("allow");
  });

  test("append redirect to whitelisted path also exempt", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      allowRedirects: ["/tmp/**"],
    };
    const result = bash("echo hello >> /tmp/log.txt", config);
    expect(result.decision).toBe("allow");
  });

  test("empty allow_redirects does not affect behavior", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: {},
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      allowRedirects: [],
    };
    const result = bash("echo hello > /tmp/out.txt", config);
    expect(result.decision).toBe("context");
  });

  test("sensitive path check still applies even if redirect whitelisted", () => {
    const config: ShushConfig = {
      actions: {},
      sensitivePaths: { "~/.ssh/*": "block" },
      classify: {},
      allowTools: [],
      mcpPathParams: {},
      allowRedirects: ["**"],  // whitelist everything
    };
    // Even though redirect is whitelisted, sensitive path check should escalate
    const result = bash("echo key > ~/.ssh/authorized_keys", config);
    expect(result.decision).not.toBe("allow");
  });
});
