// src/content-guard.ts

import type { Decision } from "./types.js";

/** A single content match from scanning. */
export interface ContentMatch {
  category: string;
  patternDesc: string;
  matchedText: string;
  policy: Decision;
}

// Compiled regexes by category. Each entry: [regex, description].
// Categories in EXPENSIVE_CATEGORIES use .* or open-ended quantifiers
// and are only scanned on the size-capped prefix.
const CONTENT_PATTERNS: Record<string, Array<[RegExp, string]>> = {
  destructive: [
    [/\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b/, "rm -rf"],
    [/\brm\s+-[a-zA-Z]*f[a-zA-Z]*r\b/, "rm -rf"],
    [/\bshutil\.rmtree\b/, "shutil.rmtree"],
    [/\bos\.remove\b/, "os.remove"],
    [/\bos\.unlink\b/, "os.unlink"],
  ],
  exfiltration: [
    [/\bcurl\s+.*-[a-zA-Z]*X\s+POST\b/, "curl -X POST"],
    [/\bcurl\s+.*--data\b/, "curl --data"],
    [/\bcurl\s+.*-d\s/, "curl -d"],
    [/\brequests\.post\b/, "requests.post"],
    [/\burllib\.request\.urlopen\b.*data\s*=/, "urllib POST"],
  ],
  credential_access: [
    [/~\/\.ssh\//, "~/.ssh/ access"],
    [/~\/\.aws\//, "~/.aws/ access"],
    [/~\/\.gnupg\//, "~/.gnupg/ access"],
  ],
  obfuscation: [
    [/\bbase64\s+.*-d\s*\|\s*bash\b/, "base64 -d | bash"],
    [/\beval\s*\(\s*base64\.b64decode\b/, "eval(base64.b64decode"],
    [/\bexec\s*\(\s*compile\b/, "exec(compile"],
  ],
  secret: [
    [/-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/, "private key"],
    [/(?:AKIA|ASIA)[0-9A-Z]{16}/, "AWS access key"],
    [/\bgh[pousr]_[0-9a-zA-Z]{36}\b/, "GitHub personal access token"],
    [/\bsk-[0-9a-zA-Z]{20,}\b/, "secret key token (sk-)"],
    [/(?:api_key|apikey|api_secret)\s*[=:]\s*['"][^'"]{8,}['"]/, "hardcoded API key"],
    [/\b(?:GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY)\s*=\s*\S+/, "token env var assignment"],
    [/eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}/, "JWT token"],
  ],
};

// Categories with backtracking-prone patterns (use .* or open quantifiers).
// These are only scanned on the capped prefix to avoid regex DoS.
const EXPENSIVE_CATEGORIES = new Set(["exfiltration", "obfuscation"]);

// Patterns for detecting credential-searching Grep queries.
const CREDENTIAL_SEARCH_PATTERNS: RegExp[] = [
  /\bpassword\b/i,
  /\bsecret\b/i,
  /\btoken\b/i,
  /\bapi_key\b/i,
  /\bprivate_key\b/i,
  /\bAWS_SECRET/,
  /BEGIN.*PRIVATE/i,
];

// Cap expensive regex scanning to avoid timeout on huge file writes.
const MAX_SCAN_BYTES = 256 * 1024; // 256 KB

/** Scan content for dangerous patterns. Returns matches (empty = safe).
 *  Collects at most one match per category for the reason string.
 *  Expensive (backtracking) patterns are capped at MAX_SCAN_BYTES;
 *  cheap patterns (secrets, destructive) scan the full content. */
export function scanContent(content: string): ContentMatch[] {
  if (!content) return [];
  const capped = content.length > MAX_SCAN_BYTES
    ? content.slice(0, MAX_SCAN_BYTES)
    : content;

  const matches: ContentMatch[] = [];
  for (const [category, patterns] of Object.entries(CONTENT_PATTERNS)) {
    // Expensive categories (backtracking regexes) only scan the capped prefix.
    const target = EXPENSIVE_CATEGORIES.has(category) ? capped : content;
    for (const [regex, desc] of patterns) {
      const m = regex.exec(target);
      if (m) {
        matches.push({
          category,
          patternDesc: desc,
          matchedText: m[0].slice(0, 80),
          policy: "ask",
        });
        break; // one match per category is enough
      }
    }
  }
  return matches;
}

/** Check if a Grep pattern looks like a credential search. */
export function isCredentialSearch(pattern: string): boolean {
  if (!pattern) return false;
  return CREDENTIAL_SEARCH_PATTERNS.some((regex) => regex.test(pattern));
}

/** Format a human-readable message from content scan matches. */
export function formatContentMessage(toolName: string, matches: ContentMatch[]): string {
  const items = matches.map((m) => `${m.category}: ${m.patternDesc}`).join(", ");
  return `${toolName} content contains: ${items}`;
}
