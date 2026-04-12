--------------------------- MODULE PathGuard ---------------------------
(* TLA+ model of shush's path-guard security decisions.

   Models the decision pipeline for file-access tools:
   Read, Write, Edit, MultiEdit, NotebookEdit, Glob, Grep, and MCP tools.

   IMPORTANT: The real code uses EARLY RETURN semantics in checkPath():
     ~user check -> hook check -> sensitive check -> return null (allow)
   Each returns on first match. The model must reflect this priority order.

   Decision layers:
     1. ~user path expansion + sensitive check (returns early if matched)
     2. Hook path protection (returns early if matched)
     3. Sensitive path/file check (returns early if matched)
     4. Project boundary check (only when path check returned null/allow)
     5. Content scanning (Write/Edit only, only when not already block)
     6. Tool-specific: Grep credential search, Glob dual-path
     7. MCP: deny/allow filtering + path param checks (via checkPath)

   Content escalation ceiling: scanContent can only escalate
   allow/context -> ask. It NEVER produces block on its own.
*)

EXTENDS Naturals, FiniteSets, ShushTypes

VARIABLES tool, pathCategory, boundary, content, resolvedCategory,
          grepPattern, globPatternCategory, mcpPolicy, mcpPathCategory,
          tildeUserCategory, decision

(* ---------- Tool classifications ---------- *)

(* Matches evaluate.ts switch cases exactly *)
ReadOnlyTools == {"Read"}
WriteTools    == {"Write", "Edit", "MultiEdit", "NotebookEdit"}
GlobTool      == {"Glob"}
GrepTool      == {"Grep"}
McpTool       == {"mcp__"}
AllTools      == ReadOnlyTools \cup WriteTools \cup GlobTool \cup GrepTool \cup McpTool

(* ---------- Path categories ---------- *)

(* checkPath returns null (= allow) for unmatched paths.
   These categories represent what isSensitive/isHookPath would match. *)
PathCategories == {
    "hook",              \* ~/.claude/hooks/...
    "sensitive_block",   \* ~/.ssh, ~/.gnupg, ~/.docker/config.json, etc.
    "sensitive_ask",     \* ~/.aws, ~/.config/gcloud, .env files, config paths
    "normal"             \* everything else (checkPath returns null)
}

(* ---------- Other domains ---------- *)
BoundaryStatus == {"inside", "outside", "no_root"}
ContentStatus == {"clean", "suspicious"}
GrepPatternTypes == {"normal", "credential_search"}
McpPolicyTypes == {"denied", "allowed", "unclassified"}

(* ---------- Decision functions ---------- *)

(* checkPath hook decision (path-guard.ts:187-203).
   Real code: HOOK_BLOCK_TOOLS = {Write, Edit, MultiEdit, NotebookEdit}
              HOOK_READONLY_TOOLS = {Read, Glob, Grep}
   MCP tools fall through to the else branch -> Ask *)
HookDecision(t) ==
    IF t \in WriteTools THEN Block
    ELSE IF t \in ReadOnlyTools \cup GlobTool \cup GrepTool THEN Allow
    ELSE Ask  \* MCP and any future tool

(* isSensitive() result -> decision (path-guard.ts:117-159).
   All sensitive matches return the stored policy directly. *)
SensitiveDecision(cat) ==
    CASE cat = "sensitive_block" -> Block
      [] cat = "sensitive_ask"   -> Ask
      [] OTHER                   -> Allow

(* checkProjectBoundary (path-guard.ts:218-243) *)
BoundaryDecision(b) ==
    CASE b = "inside"  -> Allow
      [] b = "outside" -> Ask
      [] b = "no_root" -> Ask

(* checkPath early-return logic (path-guard.ts:162-215):
   1. ~user match -> return {policy}
   2. hook match -> return block/null/ask based on tool
   3. sensitive match -> return {policy}
   4. no match -> return null (allow)

   The model computes the FIRST matching layer's result.
   When ~user matches, hook/sensitive are not checked.
   When hook matches, sensitive is not checked. *)
CheckPathResult(t, pc, rc, tuc) ==
    \* Step 1: ~user check (only fires when tildeUserCategory != normal)
    IF tuc /= "normal" THEN SensitiveDecision(tuc)
    \* Step 2: hook check (on resolved path)
    ELSE IF rc = "hook" THEN HookDecision(t)
    \* Step 3: sensitive check (on resolved path)
    ELSE IF rc /= "normal" THEN SensitiveDecision(rc)
    \* Step 4: no match
    ELSE Allow

(* Content scan (evaluate.ts:56-66):
   Only runs when decision != block.
   Can ONLY escalate allow/context -> ask. Never produces block.
   If decision is already ask, content scan changes nothing. *)
ContentDecision(currentD, t, c) ==
    IF t \in WriteTools /\ c = "suspicious" /\ currentD /= Block
    THEN Stricter(currentD, Ask)
    ELSE currentD

(* Whether tool gets boundary check *)
HasBoundaryCheck(t) ==
    t \in WriteTools \cup GlobTool \cup GrepTool \cup McpTool

(* MCP deny/allow policy (evaluate.ts:195-211) *)
McpPolicyDecision(t, mp) ==
    IF t \in McpTool THEN
        CASE mp = "denied"       -> Block
          [] mp = "unclassified" -> Ask
          [] mp = "allowed"      -> Allow
    ELSE Allow

(* ---------- Full decision pipeline ---------- *)

(* Models evaluate.ts for each tool type, matching the real control flow. *)
ComputeDecision(t, pc, rc, b, c, gp, gpc, mp, mpc, tuc) ==
    LET
        \* checkPath result (early-return semantics)
        pathD     == CheckPathResult(t, pc, rc, tuc)

        \* Boundary: only when pathD == Allow (evaluate.ts: `if decision === "allow"`)
        afterBound == IF HasBoundaryCheck(t) /\ pathD = Allow
                      THEN BoundaryDecision(b)
                      ELSE pathD

        \* Content: only for write tools, only when not block
        afterContent == ContentDecision(afterBound, t, c)

        \* Grep credential search (evaluate.ts:188-191)
        grepD     == IF t \in GrepTool /\ gp = "credential_search" THEN Ask
                     ELSE Allow

        \* Glob dual-path: pattern string goes through checkPath too
        \* (evaluate.ts:151-158). Uses SensitiveDecision since checkPath
        \* runs on the pattern string.
        globPatD  == IF t \in GlobTool THEN SensitiveDecision(gpc) ELSE Allow

        \* MCP: deny/allow policy
        mcpPolD   == McpPolicyDecision(t, mp)

        \* MCP: path params go through checkPath (evaluate.ts:229-246)
        \* This IS how MCP tools get hook protection (if configured)
        mcpPathD  == IF t \in McpTool THEN CheckPathResult(t, "normal", mpc, "normal")
                     ELSE Allow

    IN  StricterAll({afterContent, grepD, globPatD, mcpPolD, mcpPathD})

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

(* INV-1: Sensitive-block resolved path NEVER gets allow or context *)
SensitiveBlockNeverAllowed ==
    (resolvedCategory = "sensitive_block" /\ tildeUserCategory = "normal")
    => decision \in {Ask, Block}

(* INV-2: Hook paths ALWAYS blocked for write tools *)
HookWriteAlwaysBlocked ==
    (resolvedCategory = "hook" /\ tildeUserCategory = "normal"
     /\ tool \in WriteTools)
    => decision = Block

(* INV-3: Hook paths allow read-only access
   (checkPath returns null for readonly tools on hooks) *)
HookReadAllowed ==
    (resolvedCategory = "hook" /\ tildeUserCategory = "normal"
     /\ tool \in ReadOnlyTools)
    => decision = Allow

(* INV-4: Suspicious content escalates write tools to at least Ask *)
SuspiciousContentEscalated ==
    (tool \in WriteTools /\ content = "suspicious")
    => Strictness[decision] >= Strictness[Ask]

(* INV-5: Content scan NEVER produces Block on its own.
   If path is normal and inside boundary, suspicious content -> Ask, not Block *)
ContentNeverBlocks ==
    (resolvedCategory = "normal" /\ tildeUserCategory = "normal"
     /\ boundary = "inside" /\ tool \in WriteTools /\ content = "suspicious")
    => decision = Ask

(* INV-6: Outside-boundary operations require at least Ask *)
OutsideBoundaryEscalated ==
    (HasBoundaryCheck(tool) /\ boundary \in {"outside", "no_root"}
     /\ resolvedCategory = "normal" /\ tildeUserCategory = "normal")
    => Strictness[decision] >= Strictness[Ask]

(* INV-7: Symlink resolution cannot downgrade security.
   The resolved path category drives the decision. *)
SymlinkNoDowngrade ==
    (tildeUserCategory = "normal")
    => Strictness[decision] >= Strictness[SensitiveDecision(resolvedCategory)]

(* INV-8: Normal everything -> Allow for read-only tools *)
NormalReadInsideIsAllow ==
    (resolvedCategory = "normal" /\ tildeUserCategory = "normal"
     /\ boundary = "inside" /\ tool \in ReadOnlyTools)
    => decision = Allow

(* INV-9: Decision monotonicity - sensitive always reflected *)
DecisionMonotonicity ==
    (tildeUserCategory = "normal")
    => Strictness[decision] >= Strictness[SensitiveDecision(resolvedCategory)]

(* INV-10: Grep credential search escalates to at least Ask *)
GrepCredentialEscalated ==
    (tool \in GrepTool /\ grepPattern = "credential_search")
    => Strictness[decision] >= Strictness[Ask]

(* INV-11: Glob pattern pointing to sensitive-block -> Block *)
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

(* INV-14: MCP path params to sensitive-block -> Block *)
McpPathSensitiveEscalated ==
    (tool \in McpTool /\ mcpPathCategory = "sensitive_block")
    => Strictness[decision] >= Strictness[Block]

(* INV-15: MCP path params to hook -> Block for write-equivalent tools
   Note: MCP tools go through checkPath which checks hooks,
   but only if mcp_path_params is configured. The model assumes
   it is configured (mcpPathCategory reflects the param's resolved path). *)
McpHookPathBlocked ==
    (tool \in McpTool /\ mcpPathCategory = "hook")
    => Strictness[decision] >= Strictness[Ask]

(* INV-16: ~user paths to sensitive-block -> Block *)
TildeUserSensitiveBlocked ==
    tildeUserCategory = "sensitive_block"
    => Strictness[decision] >= Strictness[Block]

(* INV-17: ~user early return takes priority over hook check.
   If ~user matches sensitive_ask, decision is Ask even if resolved
   path is a hook and tool is read-only (which would normally be Allow). *)
TildeUserPriority ==
    (tildeUserCategory = "sensitive_ask" /\ resolvedCategory = "hook"
     /\ tool \in ReadOnlyTools)
    => Strictness[decision] >= Strictness[Ask]

(* INV-18: Read tool never gets boundary check.
   Normal path + outside boundary + Read -> still Allow *)
ReadNoBoundaryCheck ==
    (tool \in ReadOnlyTools /\ resolvedCategory = "normal"
     /\ tildeUserCategory = "normal" /\ boundary = "outside")
    => decision = Allow

(* Combined invariant *)
SafetyInvariant ==
    /\ TypeOK
    /\ SensitiveBlockNeverAllowed
    /\ HookWriteAlwaysBlocked
    /\ HookReadAllowed
    /\ SuspiciousContentEscalated
    /\ ContentNeverBlocks
    /\ OutsideBoundaryEscalated
    /\ SymlinkNoDowngrade
    /\ NormalReadInsideIsAllow
    /\ DecisionMonotonicity
    /\ GrepCredentialEscalated
    /\ GlobPatternSensitiveBlocked
    /\ McpDeniedAlwaysBlocked
    /\ McpUnclassifiedAsk
    /\ McpPathSensitiveEscalated
    /\ McpHookPathBlocked
    /\ TildeUserSensitiveBlocked
    /\ TildeUserPriority
    /\ ReadNoBoundaryCheck

=========================================================================
