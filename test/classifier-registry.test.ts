import { describe, expect, test } from "bun:test";
import { lookup, register, resetForTest } from "../src/classifiers/index";

describe("classifier registry", () => {
  test("returns null for unregistered command", () => {
    expect(lookup("nonexistent", ["nonexistent", "arg"])).toBeNull();
  });

  test("single classifier returns its result", () => {
    resetForTest();
    register("mycmd", [(_tokens) => "network_write"]);
    expect(lookup("mycmd", ["mycmd", "-X"])).toBe("network_write");
  });

  test("classifier returning null falls through", () => {
    resetForTest();
    register("mycmd", [
      (_tokens) => null,
      (_tokens) => "filesystem_read",
    ]);
    expect(lookup("mycmd", ["mycmd"])).toBe("filesystem_read");
  });

  test("first non-null result wins", () => {
    resetForTest();
    register("mycmd", [
      (_tokens) => "network_write",
      (_tokens) => "filesystem_delete",
    ]);
    expect(lookup("mycmd", ["mycmd"])).toBe("network_write");
  });

  test("all classifiers returning null yields null", () => {
    resetForTest();
    register("mycmd", [(_tokens) => null, (_tokens) => null]);
    expect(lookup("mycmd", ["mycmd"])).toBeNull();
  });
});
