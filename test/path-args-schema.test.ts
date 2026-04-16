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
