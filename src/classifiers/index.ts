// src/classifiers/index.ts
//
// Classifier registry. Maps command names to ordered lists of
// classifier functions. lookup() iterates the list, returning
// the first non-null result.

export type Classifier = (tokens: string[]) => string | null;

const REGISTRY: Map<string, Classifier[]> = new Map();

/** Register classifiers for a command. */
export function register(command: string, classifiers: Classifier[]): void {
  REGISTRY.set(command, classifiers);
}

/** Register a single classifier for multiple command names. */
export function registerMany(commands: string[], classifier: Classifier): void {
  for (const cmd of commands) {
    const existing = REGISTRY.get(cmd) ?? [];
    existing.push(classifier);
    REGISTRY.set(cmd, existing);
  }
}

/**
 * Look up classifiers for a command and run them in order.
 * Returns the first non-null result, or null if none match.
 */
export function lookup(command: string, tokens: string[]): string | null {
  const classifiers = REGISTRY.get(command);
  if (!classifiers) return null;

  for (const classifier of classifiers) {
    const result = classifier(tokens);
    if (result !== null) return result;
  }
  return null;
}

/** Reset registry for testing. */
export function resetForTest(): void {
  REGISTRY.clear();
}
