import { expect, test } from "bun:test";
import { bash } from "./eval-helpers";

test("bash -x -c 'rm -rf /' - flag before -c", () => {
  // Expected: block (disk_destructive), but if bug exists: ask (lang_exec)
  const result = bash("bash -x -c 'rm -rf /'");
  expect(result.decision).not.toBe("allow");
});

test("bash -c 'rm -rf /' - baseline", () => {
  const result = bash("bash -c 'rm -rf /'");
  expect(result.decision).not.toBe("allow");
});
