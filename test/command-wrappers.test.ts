import { describe, test, expect } from "bun:test";
import { COMMAND_WRAPPERS as FROM_PREDICATES } from "../src/predicates/composition";
import { COMMAND_WRAPPERS as FROM_BASH_GUARD } from "../src/bash-guard";

describe("COMMAND_WRAPPERS relocation", () => {
  test("predicates export matches bash-guard re-export key-for-key", () => {
    expect(Object.keys(FROM_PREDICATES).sort()).toEqual(Object.keys(FROM_BASH_GUARD).sort());
  });

  test("predicates export matches bash-guard re-export value-for-value", () => {
    for (const k of Object.keys(FROM_PREDICATES)) {
      expect(FROM_BASH_GUARD[k]).toEqual(FROM_PREDICATES[k]);
    }
  });

  test("contains the canonical wrappers", () => {
    for (const w of ["env", "nice", "nohup", "stdbuf", "timeout", "sudo", "doas", "xargs"]) {
      expect(FROM_PREDICATES[w]).toBeDefined();
    }
  });
});
