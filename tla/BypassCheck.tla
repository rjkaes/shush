--------------------------- MODULE BypassCheck -------------------------
(* Adversarial analysis of shush's security model.

   Rather than checking that known-bad states are blocked, this module
   asks: "when does shush produce Allow?" and checks whether any of
   those Allow states represent a security bypass.

   Method: define what SHOULD be blocked/asked, then verify the model
   never produces Allow for those conditions.

   This is the inverse of the safety invariants: instead of "bad -> not allow",
   we ask "allow -> not bad" (the contrapositive). *)

EXTENDS Naturals, FiniteSets, ShushTypes

(* ======================================================================
   PART 1: PathGuard bypass analysis
   ====================================================================== *)

VARIABLES tool, pathCategory, boundary, content, resolvedCategory,
          grepPattern, globPatternCategory, mcpPolicy, mcpPathCategory,
          tildeUserCategory, pgDecision

(* Reuse PathGuard definitions inline *)
ReadOnlyTools == {"Read"}
WriteTools    == {"Write", "Edit", "MultiEdit", "NotebookEdit"}
GlobTool      == {"Glob"}
GrepTool      == {"Grep"}
McpTool       == {"mcp__"}
AllTools      == ReadOnlyTools \cup WriteTools \cup GlobTool \cup GrepTool \cup McpTool

PathCategories == {"hook", "sensitive_block", "sensitive_ask", "normal"}
BoundaryStatus == {"inside", "outside", "no_root"}
ContentStatus  == {"clean", "suspicious"}
GrepPatternTypes == {"normal", "credential_search"}
McpPolicyTypes   == {"denied", "allowed", "unclassified"}

HookDecision(t) ==
    IF t \in WriteTools THEN Block
    ELSE IF t \in ReadOnlyTools \cup GlobTool \cup GrepTool THEN Allow
    ELSE Ask

SensitiveDecision(cat) ==
    CASE cat = "sensitive_block" -> Block
      [] cat = "sensitive_ask"   -> Ask
      [] OTHER                   -> Allow

BoundaryDecision(b) ==
    CASE b = "inside"  -> Allow
      [] b = "outside" -> Ask
      [] b = "no_root" -> Ask

CheckPathResult(t, pc, rc, tuc) ==
    IF tuc /= "normal" THEN SensitiveDecision(tuc)
    ELSE IF rc = "hook" THEN HookDecision(t)
    ELSE IF rc /= "normal" THEN SensitiveDecision(rc)
    ELSE Allow

ContentDecision(currentD, t, c) ==
    IF t \in WriteTools /\ c = "suspicious" /\ currentD /= Block
    THEN Stricter(currentD, Ask)
    ELSE currentD

HasBoundaryCheck(t) ==
    t \in WriteTools \cup GlobTool \cup GrepTool \cup McpTool

McpPolicyDecision(t, mp) ==
    IF t \in McpTool THEN
        CASE mp = "denied"       -> Block
          [] mp = "unclassified" -> Ask
          [] mp = "allowed"      -> Allow
    ELSE Allow

ComputePGDecision(t, pc, rc, b, c, gp, gpc, mp, mpc, tuc) ==
    LET pathD     == CheckPathResult(t, pc, rc, tuc)
        afterBound == IF HasBoundaryCheck(t) /\ pathD = Allow
                      THEN BoundaryDecision(b)
                      ELSE pathD
        afterContent == ContentDecision(afterBound, t, c)
        grepD     == IF t \in GrepTool /\ gp = "credential_search" THEN Ask
                     ELSE Allow
        globPatD  == IF t \in GlobTool THEN SensitiveDecision(gpc) ELSE Allow
        mcpPolD   == McpPolicyDecision(t, mp)
        mcpPathD  == IF t \in McpTool THEN CheckPathResult(t, "normal", mpc, "normal")
                     ELSE Allow
    IN  StricterAll({afterContent, grepD, globPatD, mcpPolD, mcpPathD})

PGInit ==
    /\ tool               \in AllTools
    /\ pathCategory       \in PathCategories
    /\ boundary           \in BoundaryStatus
    /\ content            \in ContentStatus
    /\ resolvedCategory   \in PathCategories
    /\ grepPattern        \in GrepPatternTypes
    /\ globPatternCategory \in PathCategories
    /\ mcpPolicy          \in McpPolicyTypes
    /\ mcpPathCategory    \in PathCategories
    \* ~user paths resolve to CWD (not home), so they can never be
    \* "hook" or "sensitive_block" in practice. Constrain to reachable states.
    /\ tildeUserCategory  \in {"sensitive_ask", "normal"}
    /\ pgDecision = ComputePGDecision(tool, pathCategory, resolvedCategory,
                                       boundary, content, grepPattern,
                                       globPatternCategory, mcpPolicy,
                                       mcpPathCategory, tildeUserCategory)

PGNext == UNCHANGED <<tool, pathCategory, boundary, content,
                       resolvedCategory, grepPattern, globPatternCategory,
                       mcpPolicy, mcpPathCategory, tildeUserCategory,
                       pgDecision>>

(* ======================================================================
   BYPASS PROPERTIES: if any of these FAIL, we found a bypass vector.
   TLC will print the counterexample showing the exact bypass state.
   ====================================================================== *)

(* BYPASS-1: Can a write tool reach Allow on a sensitive-block path?
   This would mean writing to ~/.ssh with no prompt. *)
PG_NoWriteToSensitiveBlock ==
    (tool \in WriteTools /\ resolvedCategory = "sensitive_block"
     /\ tildeUserCategory = "normal")
    => pgDecision /= Allow

(* BYPASS-2: Can ANY tool reach Allow on a sensitive-block path?
   Even Read should not silently access ~/.ssh. *)
PG_NoSilentSensitiveBlockAccess ==
    (resolvedCategory = "sensitive_block" /\ tildeUserCategory = "normal")
    => pgDecision /= Allow

(* BYPASS-3: Can a write tool modify hooks with Allow? *)
PG_NoWriteToHooksAllow ==
    (tool \in WriteTools /\ resolvedCategory = "hook"
     /\ tildeUserCategory = "normal")
    => pgDecision = Block

(* BYPASS-4: Can an MCP tool access sensitive paths with Allow?
   If mcpPathCategory is sensitive-block but tool gets Allow. *)
PG_NoMcpSensitiveAllow ==
    (tool \in McpTool /\ mcpPathCategory = "sensitive_block")
    => pgDecision /= Allow

(* BYPASS-5: Can a Glob pattern targeting ~/.ssh get Allow? *)
PG_NoGlobPatternSensitiveAllow ==
    (tool \in GlobTool /\ globPatternCategory = "sensitive_block")
    => pgDecision /= Allow

(* BYPASS-6: Read tool bypasses boundary but can it read hooks
   when path resolves to hook AND tildeUser overrides?
   ~user path to hook dir -> should it be blocked? *)
PG_TildeUserHookInteraction ==
    \* If ~user resolves to sensitive-ask, and real path is hook,
    \* early return on ~user means hook check never runs.
    \* Is this a bypass? ~user → sensitive_ask → Ask, so not Allow. OK.
    (tildeUserCategory = "sensitive_ask" /\ resolvedCategory = "hook")
    => pgDecision /= Allow

(* BYPASS-7: Can MCP tool with "allowed" policy and normal path params
   access hooks? The model shows mcpPathD uses CheckPathResult which
   checks hooks. But what if mpc = "normal"? *)
PG_McpAllowedNoHookBypass ==
    (tool \in McpTool /\ mcpPolicy = "allowed"
     /\ mcpPathCategory = "normal" /\ resolvedCategory = "hook")
    => pgDecision /= Allow

(* BYPASS-8: Write outside boundary with suspicious content - never Allow *)
PG_NoWriteOutsideBoundaryAllow ==
    (tool \in WriteTools /\ boundary \in {"outside", "no_root"}
     /\ resolvedCategory = "normal" /\ tildeUserCategory = "normal")
    => pgDecision /= Allow

(* Combined *)
PGBypassInvariant ==
    /\ PG_NoWriteToSensitiveBlock
    /\ PG_NoSilentSensitiveBlockAccess
    /\ PG_NoWriteToHooksAllow
    /\ PG_NoMcpSensitiveAllow
    /\ PG_NoGlobPatternSensitiveAllow
    /\ PG_TildeUserHookInteraction
    /\ PG_McpAllowedNoHookBypass
    /\ PG_NoWriteOutsideBoundaryAllow

(* ======================================================================
   RESOLVED VULNERABILITIES
   ====================================================================== *)

(* VULN-1 (FIXED): $HOME variable expansion bypass.
   resolvePath() now expands $HOME and ${HOME} before path resolution.
*)

(* VULN-2 (ACCEPTED RISK): Shell unwrap depth exhaustion.
   MAX_UNWRAP_DEPTH=3 means bash -c at depth >= 3 -> unknown -> ask.
   Not an allow bypass. Safe because unknown policy is ask.
*)

(* VULN-3 (FIXED): Same root cause as VULN-1. Fixed together. *)

=========================================================================
