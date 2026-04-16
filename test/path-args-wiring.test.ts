import { describe, test, expect } from "bun:test";
import { bash } from "./eval-helpers";

describe("pathArgs wiring for built-in write emitters", () => {
  test("cp <src> ~/.ssh/id_rsa escalates on dest", () => {
    expect(bash("cp /tmp/x /Users/x/.ssh/id_rsa").decision).toMatch(/ask|block/);
  });
  test("mv /tmp/x ~/.aws/credentials escalates", () => {
    expect(bash("mv /tmp/x /Users/x/.aws/credentials").decision).toMatch(/ask|block/);
  });
  test("tee -a ~/.ssh/config escalates", () => {
    expect(bash("tee -a /Users/x/.ssh/config").decision).toMatch(/ask|block/);
  });
  test("dd of=~/.ssh/config escalates", () => {
    expect(bash("dd if=/dev/zero of=/Users/x/.ssh/config").decision).toMatch(/ask|block/);
  });
  test("install -m 644 src ~/.ssh/authorized_keys escalates", () => {
    expect(bash("install -m 644 /tmp/src /Users/x/.ssh/authorized_keys").decision).toMatch(/ask|block/);
  });
  test("ln -sf /etc/passwd ~/x escalates", () => {
    expect(bash("ln -sf /etc/passwd /Users/x/x").decision).toMatch(/ask|block/);
  });
});
