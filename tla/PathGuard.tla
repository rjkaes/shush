--------------------------- MODULE PathGuard ---------------------------
(* TLA+ model of shush's path-guard security decisions.

   Models the decision pipeline for file-access tools:
   Read, Write, Edit, MultiEdit, NotebookEdit, Glob, Grep, and MCP tools.

   Decision layers (evaluated in order, strictest wins):
     1. Hook path protection
     2. Sensitive path/file check (dirs, basenames, .env.*, config paths)
     3. Project boundary check
     4. Content scanning (Write/Edit/MultiEdit/NotebookEdit only)
     5. Tool-specific checks (Grep credential search, Glob dual-path)
     6. MCP tool deny/allow filtering + path param checks

   The model explores all combinations of:
     - Tool types (read-only, write, glob, grep, mcp)
     - Path categories (hook, sensitive-block, sensitive-ask, env-file, normal)
     - Boundary status (inside, outside, no-root)
     - Content status (clean, suspicious)
     - Symlink resolution outcomes (same, different-category)
     - Grep pattern types (normal, credential-search)
     - Glob pattern path category
     - MCP tool policy (denied, allowed, unclassified)
     - MCP path param categories
*)

EXTENDS Naturals, FiniteSets, ShushTypes

VARIABLES tool, pathCategory, boundary, content, resolvedCategory,
          grepPattern, globPatternCategory, mcpPolicy, mcpPathCategory,
          tildeUserCategory, decision

(* ---------- Tool classifications ---------- *)

ReadOnlyTools == {"Read"}
WriteTools    == {"Write", "Edit", "MultiEdit", "NotebookEdit"}
GlobTool      == {"Glob"}
GrepTool      == {"Grep"}
McpTool       == {"mcp__"}
AllTools      == ReadOnlyTools \cup WriteTools \cup GlobTool \cup GrepTool \cup McpTool

(* ---------- Path categories ---------- *)

(* Mirrors SENSITIVE_DIRS + SENSITIVE_BASENAMES + .env.* in path-guard.ts *)
PathCategories == {
    "hook",              \* ~/.claude/hooks/...
    "sensitive_block",   \* ~/.ssh, ~/.gnupg, ~/.docker/config.json, etc.
    "sensitive_ask",     \* ~/.aws, ~/.config/gcloud, etc.
    "env_file",          \* .env, .env.local, .env.production, .env.*
    "config_sensitive",  \* Config-defined sensitive paths
    "tilde_user",        \* ~user/... paths (expanded, checked against sensitive)
    "normal"             \* everything else
}

(* ---------- Boundary status ---------- *)
BoundaryStatus == {"inside", "outside", "no_root"}

(* ---------- Content status ---------- *)
ContentStatus == {"clean", "suspicious"}

(* ---------- Grep pattern types ---------- *)
GrepPatternTypes == {"normal", "credential_search"}

(* ---------- MCP tool policy ---------- *)
McpPolicyTypes == {"denied", "allowed", "unclassified"}

(* ---------- Decision functions ---------- *)

(* Hook path decision: write tools blocked, read-only/glob/grep allowed *)
HookDecision(t) ==
    IF t \in WriteTools THEN Block
    ELSE IF t \in ReadOnlyTools \cup GlobTool \cup GrepTool THEN Allow
    ELSE Ask

(* Sensitive path decision based on category *)
SensitiveDecision(cat) ==
    CASE cat = "sensitive_block"  -> Block
      [] cat = "sensitive_ask"    -> Ask
      [] cat = "env_file"         -> Ask
      [] cat = "config_sensitive" -> Ask
      [] OTHER                    -> Allow

(* Boundary decision: applies to Write, Edit, Glob, Grep, MCP *)
BoundaryDecision(b) ==
    CASE b = "inside"  -> Allow
      [] b = "outside" -> Ask
      [] b = "no_root" -> Ask

(* Content scan decision (only for Write/Edit/MultiEdit/NotebookEdit)
   Real code: only runs when decision != block (short-circuit) *)
ContentDecision(t, c, currentD) ==
    IF t \in WriteTools /\ c = "suspicious" /\ currentD /= Block THEN Ask
    ELSE Allow

(* Grep credential search escalation (evaluate.ts:188-191) *)
GrepCredentialDecision(t, pat) ==
    IF t \in GrepTool /\ pat = "credential_search" THEN Ask
    ELSE Allow

(* MCP tool policy decision (evaluate.ts:195-248) *)
McpPolicyDecision(t, mp) ==
    IF t \in McpTool THEN
        CASE mp = "denied"       -> Block
          [] mp = "unclassified" -> Ask
          [] mp = "allowed"      -> Allow
    ELSE Allow

(* ---------- Full decision pipeline ---------- *)

(* Whether this tool gets boundary checks.
   Real code: Write, Edit, MultiEdit, NotebookEdit, Glob, Grep, MCP *)
HasBoundaryCheck(t) ==
    t \in WriteTools \cup GlobTool \cup GrepTool \cup McpTool

ComputeDecision(t, pc, rc, b, c, gp, gpc, mp, mpc, tuc) ==
    LET
        \* Hook path: checked on both raw and resolved path
        hookD     == IF pc = "hook" \/ rc = "hook"
                     THEN HookDecision(t)
                     ELSE Allow

        \* Sensitive path: both raw and resolved, plus ~user expansion
        sensD     == StricterAll({SensitiveDecision(pc),
                                  SensitiveDecision(rc),
                                  SensitiveDecision(tuc)})

        \* Boundary: applies to write tools, Glob, Grep, MCP
        boundD    == IF HasBoundaryCheck(t) THEN BoundaryDecision(b) ELSE Allow

        \* Content scan: short-circuits on block
        prelimD   == StricterAll({hookD, sensD, boundD})
        contentD  == ContentDecision(t, c, prelimD)

        \* Grep credential pattern check
        grepD     == GrepCredentialDecision(t, gp)

        \* Glob dual-path: pattern also checked against sensitive paths
        globPatD  == IF t \in GlobTool THEN SensitiveDecision(gpc) ELSE Allow

        \* MCP: deny/allow policy + path param sensitivity
        mcpPolD   == McpPolicyDecision(t, mp)
        mcpPathD  == IF t \in McpTool THEN SensitiveDecision(mpc) ELSE Allow

    IN  StricterAll({hookD, sensD, boundD, contentD, grepD,
                     globPatD, mcpPolD, mcpPathD})

(* ---------- State machine ---------- *)

Init ==
    /\ tool               \in AllTools
    /\ pathCategory       \in PathCategories
    /\ boundary           \in BoundaryStatus
    /\ content            \in ContentStatus
    /\ resolvedCategory   \in PathCategories
    /\ grepPattern        \in GrepPatternTypes
    /\ globPatternCategory \in PathCategories
    /\ mcpPolicy          \in McpPolicyTypes
    /\ mcpPathCategory    \in PathCategories
    /\ tildeUserCategory  \in PathCategories
    /\ decision = ComputeDecision(tool, pathCategory, resolvedCategory,
                                   boundary, content, grepPattern,
                                   globPatternCategory, mcpPolicy,
                                   mcpPathCategory, tildeUserCategory)

(* Single-state model: explore all initial configurations *)
Next == UNCHANGED <<tool, pathCategory, boundary, content,
                     resolvedCategory, grepPattern, globPatternCategory,
                     mcpPolicy, mcpPathCategory, tildeUserCategory, decision>>

(* ---------- SAFETY INVARIANTS ---------- *)

TypeOK ==
    /\ tool \in AllTools
    /\ pathCategory \in PathCategories
    /\ boundary \in BoundaryStatus
    /\ content \in ContentStatus
    /\ resolvedCategory \in PathCategories
    /\ decision \in Decisions

(* INV-1: Sensitive-block paths NEVER get allow or context *)
SensitiveBlockNeverAllowed ==
    (pathCategory = "sensitive_block" \/ resolvedCategory = "sensitive_block")
    => decision \in {Ask, Block}

(* INV-2: Hook paths ALWAYS blocked for write tools *)
HookWriteAlwaysBlocked ==
    ((pathCategory = "hook" \/ resolvedCategory = "hook") /\ tool \in WriteTools)
    => decision = Block

(* INV-3: Hook paths allow read-only access *)
HookReadAllowed ==
    (pathCategory = "hook" /\ resolvedCategory = "hook"
     /\ tool \in ReadOnlyTools /\ tildeUserCategory = "normal")
    => decision \in {Allow, Context}

(* INV-4: Suspicious content never gets Allow for write tools *)
SuspiciousContentEscalated ==
    (tool \in WriteTools /\ content = "suspicious")
    => Strictness[decision] >= Strictness[Ask]

(* INV-5: Outside-boundary operations require at least Ask
   (applies to Write, Edit, Glob, Grep, MCP - not just writes) *)
OutsideBoundaryEscalated ==
    (HasBoundaryCheck(tool) /\ boundary \in {"outside", "no_root"})
    => Strictness[decision] >= Strictness[Ask]

(* INV-6: Symlink resolution cannot downgrade security *)
SymlinkNoDowngrade ==
    Strictness[decision] >= Strictness[SensitiveDecision(resolvedCategory)]

(* INV-7: Normal paths inside boundary with clean content -> Allow
   for read-only tools *)
NormalReadInsideIsAllow ==
    (pathCategory = "normal" /\ resolvedCategory = "normal"
     /\ boundary = "inside" /\ tool \in ReadOnlyTools
     /\ tildeUserCategory = "normal")
    => decision = Allow

(* INV-8: Decision monotonicity *)
DecisionMonotonicity ==
    LET sensD == Stricter(SensitiveDecision(pathCategory),
                          SensitiveDecision(resolvedCategory))
    IN  Strictness[decision] >= Strictness[sensD]

(* INV-9: .env files always at least Ask *)
EnvFileAlwaysAsk ==
    (pathCategory = "env_file" \/ resolvedCategory = "env_file")
    => Strictness[decision] >= Strictness[Ask]

(* INV-10: Grep credential search patterns escalate to Ask *)
GrepCredentialEscalated ==
    (tool \in GrepTool /\ grepPattern = "credential_search")
    => Strictness[decision] >= Strictness[Ask]

(* INV-11: Glob pattern pointing to sensitive-block path -> Block *)
GlobPatternSensitiveBlocked ==
    (tool \in GlobTool /\ globPatternCategory = "sensitive_block")
    => Strictness[decision] >= Strictness[Block]

(* INV-12: Denied MCP tools always blocked *)
McpDeniedAlwaysBlocked ==
    (tool \in McpTool /\ mcpPolicy = "denied")
    => decision = Block

(* INV-13: Unclassified MCP tools at least Ask *)
McpUnclassifiedAsk ==
    (tool \in McpTool /\ mcpPolicy = "unclassified")
    => Strictness[decision] >= Strictness[Ask]

(* INV-14: MCP path params pointing to sensitive paths escalate *)
McpPathSensitiveEscalated ==
    (tool \in McpTool /\ mcpPathCategory = "sensitive_block")
    => Strictness[decision] >= Strictness[Block]

(* INV-15: ~user paths resolving to sensitive locations escalate *)
TildeUserSensitiveEscalated ==
    tildeUserCategory = "sensitive_block"
    => Strictness[decision] >= Strictness[Block]

(* INV-16: Config-defined sensitive paths at least Ask *)
ConfigSensitiveEscalated ==
    (pathCategory = "config_sensitive" \/ resolvedCategory = "config_sensitive")
    => Strictness[decision] >= Strictness[Ask]

(* Combined invariant *)
SafetyInvariant ==
    /\ TypeOK
    /\ SensitiveBlockNeverAllowed
    /\ HookWriteAlwaysBlocked
    /\ HookReadAllowed
    /\ SuspiciousContentEscalated
    /\ OutsideBoundaryEscalated
    /\ SymlinkNoDowngrade
    /\ NormalReadInsideIsAllow
    /\ DecisionMonotonicity
    /\ EnvFileAlwaysAsk
    /\ GrepCredentialEscalated
    /\ GlobPatternSensitiveBlocked
    /\ McpDeniedAlwaysBlocked
    /\ McpUnclassifiedAsk
    /\ McpPathSensitiveEscalated
    /\ TildeUserSensitiveEscalated
    /\ ConfigSensitiveEscalated

=========================================================================
