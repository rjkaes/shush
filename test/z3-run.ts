import { execFileSync } from "node:child_process";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..");

export interface ProofResult {
  name: string;
  result: "unsat" | "sat" | "unknown";
}

export function runProof(proofFile: string): ProofResult[] {
  const output = execFileSync("npx", ["tsx", proofFile], {
    cwd: ROOT,
    timeout: 60_000,
    encoding: "utf-8",
  }).trim();

  return output
    .split("\n")
    .filter((line) => line.startsWith("{"))
    .map((line) => JSON.parse(line) as ProofResult);
}
