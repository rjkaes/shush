--------------------------- MODULE BashGuard ---------------------------
(* TLA+ model of shush's Bash command classification pipeline.

   Models the multi-stage decision pipeline:
     1. Per-stage classification (trie lookup → actionType → policy)
     2. Env var escalation (PAGER, EDITOR → lang_exec)
     3. Redirect escalation (> file → filesystem_write + path check)
     4. Git path validation (-C, --git-dir flags)
     5. Composition detection (exfil, decode→exec, obfuscation)
     6. Shell -c unwrapping (recursive classification)
     7. Final: stricter() across all stages *)

EXTENDS Naturals, FiniteSets, Sequences, ShushTypes

VARIABLES
    stageAction,       \* Action type from trie/classifier
    stagePolicy,       \* Base policy for that action
    hasExecEnv,        \* Stage has PAGER/EDITOR env assignment
    hasRedirect,       \* Stage redirects to a file
    redirectPath,      \* Category of redirect target path
    hasGitPath,        \* git command with -C/--git-dir
    gitPathCategory,   \* Category of git dir path
    isShellWrapper,    \* bash -c / sh -c wrapper
    innerDecision,     \* Decision from recursive inner classification
    compositionType,   \* Multi-stage composition pattern detected
    finalDecision      \* Computed final decision

(* ---------- Action types and default policies ---------- *)

ActionTypes == {
    "filesystem_read",    "filesystem_write",   "filesystem_delete",
    "git_safe",           "git_write",          "git_discard",
    "git_history_rewrite",
    "network_outbound",   "network_write",
    "package_install",    "package_run",        "package_uninstall",
    "script_exec",        "lang_exec",
    "process_signal",     "container_destructive", "disk_destructive",
    "db_read",            "db_write",
    "obfuscated",         "unknown"
}

DefaultPolicy(at) ==
    CASE at = "filesystem_read"      -> Allow
      [] at = "filesystem_write"     -> Context
      [] at = "filesystem_delete"    -> Context
      [] at = "git_safe"             -> Allow
      [] at = "git_write"            -> Allow
      [] at = "git_discard"          -> Ask
      [] at = "git_history_rewrite"  -> Ask
      [] at = "network_outbound"     -> Context
      [] at = "network_write"        -> Ask
      [] at = "package_install"      -> Allow
      [] at = "package_run"          -> Allow
      [] at = "package_uninstall"    -> Ask
      [] at = "script_exec"          -> Context
      [] at = "lang_exec"            -> Ask
      [] at = "process_signal"       -> Ask
      [] at = "container_destructive" -> Ask
      [] at = "disk_destructive"     -> Ask
      [] at = "db_read"              -> Allow
      [] at = "db_write"             -> Ask
      [] at = "obfuscated"           -> Block
      [] at = "unknown"              -> Ask

(* ---------- Path categories ---------- *)

PathCategories == {"hook", "sensitive_block", "sensitive_ask", "normal"}

(* ---------- Composition patterns ---------- *)

CompositionTypes == {
    "none",           \* No composition pattern
    "exfil",          \* Sensitive read piped to exec/network
    "decode_exec",    \* Decode piped to exec (obfuscation)
    "sensitive_exec"  \* Sensitive read piped to exec sink
}

CompositionDecision(ct) ==
    CASE ct = "none"          -> Allow
      [] ct = "exfil"         -> Ask
      [] ct = "decode_exec"   -> Block
      [] ct = "sensitive_exec" -> Ask

(* ---------- Path-based decision ---------- *)

PathDecision(cat) ==
    CASE cat = "sensitive_block" -> Block
      [] cat = "sensitive_ask"   -> Ask
      [] cat = "hook"            -> Block
      [] cat = "normal"          -> Allow

(* ---------- Full decision computation ---------- *)

ComputeBashDecision(sp, execEnv, redir, rPath,
                     gp, gpCat, wrapper, innerD, comp) ==
    LET
        baseD     == sp
        envD      == IF execEnv THEN DefaultPolicy("lang_exec") ELSE Allow
        redirBase == IF redir THEN DefaultPolicy("filesystem_write") ELSE Allow
        redirPath == IF redir THEN PathDecision(rPath) ELSE Allow
        gitD      == IF gp THEN PathDecision(gpCat) ELSE Allow
        wrapD     == IF wrapper THEN innerD ELSE Allow
        compD     == CompositionDecision(comp)
    IN  StricterAll({baseD, envD, redirBase, redirPath, gitD, wrapD, compD})

(* ---------- State machine ---------- *)

Init ==
    /\ stageAction     \in ActionTypes
    /\ stagePolicy     = DefaultPolicy(stageAction)
    /\ hasExecEnv      \in BOOLEAN
    /\ hasRedirect     \in BOOLEAN
    /\ redirectPath    \in PathCategories
    /\ hasGitPath      \in BOOLEAN
    /\ gitPathCategory \in PathCategories
    /\ isShellWrapper  \in BOOLEAN
    /\ innerDecision   \in Decisions
    /\ compositionType \in CompositionTypes
    /\ finalDecision   = ComputeBashDecision(
            stagePolicy, hasExecEnv, hasRedirect, redirectPath,
            hasGitPath, gitPathCategory, isShellWrapper,
            innerDecision, compositionType)

Next == UNCHANGED <<stageAction, stagePolicy, hasExecEnv, hasRedirect,
                     redirectPath, hasGitPath, gitPathCategory,
                     isShellWrapper, innerDecision, compositionType,
                     finalDecision>>

(* ---------- SAFETY INVARIANTS ---------- *)

TypeOK ==
    /\ stageAction \in ActionTypes
    /\ stagePolicy \in Decisions
    /\ finalDecision \in Decisions

(* INV-1: Obfuscated/decode→exec always Block *)
ObfuscatedAlwaysBlocked ==
    (stageAction = "obfuscated" \/ compositionType = "decode_exec")
    => finalDecision = Block

(* INV-2: Destructive ops never Allow *)
DestructiveNeverAllow ==
    stageAction \in {"disk_destructive", "container_destructive",
                      "filesystem_delete"}
    => Strictness[finalDecision] >= Strictness[Context]

(* INV-3: Exec env always escalates to >= Ask *)
ExecEnvEscalation ==
    hasExecEnv => Strictness[finalDecision] >= Strictness[Ask]

(* INV-4: Redirect to sensitive-block path → Block *)
RedirectToSensitiveBlocked ==
    (hasRedirect /\ redirectPath = "sensitive_block")
    => finalDecision = Block

(* INV-5: Redirect to hook path → Block *)
RedirectToHookBlocked ==
    (hasRedirect /\ redirectPath = "hook")
    => finalDecision = Block

(* INV-6: Git -C to sensitive-block → Block *)
GitPathSensitiveEscalated ==
    (hasGitPath /\ gitPathCategory = "sensitive_block")
    => finalDecision = Block

(* INV-7: Shell wrapper never downgrades inner decision *)
ShellWrapperNoDowngrade ==
    isShellWrapper
    => Strictness[finalDecision] >= Strictness[innerDecision]

(* INV-8: Composition exfil/sensitive_exec → >= Ask *)
CompositionEscalation ==
    compositionType \in {"exfil", "sensitive_exec"}
    => Strictness[finalDecision] >= Strictness[Ask]

(* INV-9: Final never weaker than base policy *)
NoDowngradeFromBase ==
    Strictness[finalDecision] >= Strictness[stagePolicy]

(* INV-10: Unknown → >= Ask *)
UnknownDefaultsToAsk ==
    stageAction = "unknown"
    => Strictness[finalDecision] >= Strictness[Ask]

(* INV-11: lang_exec → >= Ask *)
LangExecAlwaysAsk ==
    stageAction = "lang_exec"
    => Strictness[finalDecision] >= Strictness[Ask]

(* INV-12: network_write → >= Ask *)
NetworkWriteAlwaysAsk ==
    stageAction = "network_write"
    => Strictness[finalDecision] >= Strictness[Ask]

(* Combined *)
SafetyInvariant ==
    /\ TypeOK
    /\ ObfuscatedAlwaysBlocked
    /\ DestructiveNeverAllow
    /\ ExecEnvEscalation
    /\ RedirectToSensitiveBlocked
    /\ RedirectToHookBlocked
    /\ GitPathSensitiveEscalated
    /\ ShellWrapperNoDowngrade
    /\ CompositionEscalation
    /\ NoDowngradeFromBase
    /\ UnknownDefaultsToAsk
    /\ LangExecAlwaysAsk
    /\ NetworkWriteAlwaysAsk

=========================================================================
