// src/after-messages.ts
//
// Match completed commands against after_messages config patterns.
// Used by the PostToolUse hook to display feedback messages.

import { globMatch } from "./types.js";
import type { ShushConfig } from "./types.js";

/**
 * Check if a completed command matches any after_messages pattern.
 * Returns the message string if matched, null otherwise.
 */
export function matchAfterMessage(command: string, config: ShushConfig): string | null {
  const afterMessages = config.afterMessages;
  if (!afterMessages) return null;

  for (const [pattern, message] of Object.entries(afterMessages)) {
    if (globMatch(pattern, command)) {
      return message;
    }
  }

  return null;
}
