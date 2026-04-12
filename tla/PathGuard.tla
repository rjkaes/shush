--------------------------- MODULE PathGuard ---------------------------
(* TLA+ model of shush's path-guard security decisions.

   Models the decision pipeline for file-access tools:
   Read, Write, Edit, Glob, Grep.

   Decision layers (evaluated in order, strictest wins):
     1. Hook path protection
     2. Sensitive path/file check
     3. Project boundary check
     4. Content scanning (Write/Edit only)

   The model explores all combinations of:
     - Tool types (read-only vs write)
     - Path categories (hook, sensitive-block, sensitive-ask, normal)
     - Boundary status (inside, outside, no-root)
     - Content status (clean, suspicious)
     - Symlink resolution outcomes (same, different-category)
*)

EXTENDS Naturals, FiniteSets, ShushTypes

VARIABLES tool, pathCategory, boundary, content, resolvedCategory, decision

(* ---------- Tool classifications ---------- *)

ReadOnlyTools == {"Read", "Glob", "Grep"}
WriteTools    == {"Write", "Edit"}
AllTools      == ReadOnlyTools \cup WriteTools

(* ---------- Path categories ---------- *)

PathCategories == {
    "hook",              \* ~/.claude/hooks/...
    "sensitive_block",   \* ~/.ssh, ~/.gnupg, etc.
    "sensitive_ask",     \* ~/.aws, ~/.config/gcloud, etc.
    "normal"             \* everything else
}

(* ---------- Boundary status ---------- *)
BoundaryStatus == {"inside", "outside", "no_root"}

(* ---------- Content status ---------- *)
ContentStatus == {"clean", "suspicious"}

(* ---------- Decision functions ---------- *)

(* Hook path decision: write tools blocked, read-only allowed *)
HookDecision(t) ==
    IF t \in WriteTools THEN Block
    ELSE IF t \in ReadOnlyTools THEN Allow
    ELSE Ask

(* Sensitive path decision based on category *)
SensitiveDecision(cat) ==
    CASE cat = "sensitive_block" -> Block
      [] cat = "sensitive_ask"   -> Ask
      [] OTHER                   -> Allow

(* Boundary decision *)
BoundaryDecision(b) ==
    CASE b = "inside"  -> Allow
      [] b = "outside" -> Ask
      [] b = "no_root" -> Ask

(* Content scan decision (only for Write/Edit) *)
ContentDecision(t, c) ==
    IF t \in WriteTools /\ c = "suspicious" THEN Ask
    ELSE Allow

(* ---------- Full decision pipeline ---------- *)

ComputeDecision(t, pc, rc, b, c) ==
    LET hookD     == IF pc = "hook" \/ rc = "hook"
                     THEN HookDecision(t)
                     ELSE Allow
        sensD     == Stricter(SensitiveDecision(pc), SensitiveDecision(rc))
        boundD    == IF t \in WriteTools THEN BoundaryDecision(b) ELSE Allow
        contentD  == ContentDecision(t, c)
    IN  StricterAll({hookD, sensD, boundD, contentD})

(* ---------- State machine ---------- *)

Init ==
    /\ tool            \in AllTools
    /\ pathCategory    \in PathCategories
    /\ boundary        \in BoundaryStatus
    /\ content         \in ContentStatus
    /\ resolvedCategory \in PathCategories
    /\ decision = ComputeDecision(tool, pathCategory, resolvedCategory,
                                   boundary, content)

(* Single-state model: explore all initial configurations *)
Next == UNCHANGED <<tool, pathCategory, boundary, content,
                     resolvedCategory, decision>>

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
     /\ tool \in ReadOnlyTools)
    => decision \in {Allow, Context}

(* INV-4: Suspicious content never gets Allow for write tools *)
SuspiciousContentEscalated ==
    (tool \in WriteTools /\ content = "suspicious")
    => Strictness[decision] >= Strictness[Ask]

(* INV-5: Outside-boundary writes require at least Ask *)
OutsideBoundaryWriteEscalated ==
    (tool \in WriteTools /\ boundary \in {"outside", "no_root"})
    => Strictness[decision] >= Strictness[Ask]

(* INV-6: Symlink resolution cannot downgrade security *)
SymlinkNoDowngrade ==
    Strictness[decision] >= Strictness[SensitiveDecision(resolvedCategory)]

(* INV-7: Normal paths inside boundary with clean content → Allow
   for read-only tools *)
NormalReadInsideIsAllow ==
    (pathCategory = "normal" /\ resolvedCategory = "normal"
     /\ boundary = "inside" /\ tool \in ReadOnlyTools)
    => decision = Allow

(* INV-8: Decision monotonicity *)
DecisionMonotonicity ==
    LET sensD == Stricter(SensitiveDecision(pathCategory),
                          SensitiveDecision(resolvedCategory))
    IN  Strictness[decision] >= Strictness[sensD]

(* Combined invariant *)
SafetyInvariant ==
    /\ TypeOK
    /\ SensitiveBlockNeverAllowed
    /\ HookWriteAlwaysBlocked
    /\ HookReadAllowed
    /\ SuspiciousContentEscalated
    /\ OutsideBoundaryWriteEscalated
    /\ SymlinkNoDowngrade
    /\ NormalReadInsideIsAllow
    /\ DecisionMonotonicity

=========================================================================
