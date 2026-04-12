--------------------------- MODULE BashGuard ---------------------------
(* TLA+ model of shush's Bash command classification pipeline.

   Models the multi-stage decision pipeline:
     1. Per-stage classification (flag rules -> classifiers -> trie -> fallback)
     2. Env var escalation (PAGER, EDITOR, GIT_SSH_COMMAND, etc. -> lang_exec)
     3. Redirect escalation (> file -> filesystem_write + path check)
     4. Safe redirect exemption: two distinct mechanisms:
        a. Device files (/dev/null etc.) exempt from BOTH write-policy AND path check
        b. Config allowRedirects exempt from write-policy BUT NOT path check
     5. Git path validation (-C, --git-dir, --work-tree)
     6. Git dangerous -c config detection
     7. Composition detection (5 rules, with inline-code-flag suppression)
     8. Shell -c unwrapping (recursive, depth-limited to 3)
     9. Docker exec/run inner command extraction
    10. Process substitution >(cmd) and command substitution $(cmd)
    11. Final: stricter() across all stages + subs

   State space is constrained: when a boolean flag is FALSE, its associated
   path/decision variable is fixed to "normal"/"allow" to avoid exploring
   irrelevant combinations. *)

EXTENDS Naturals, FiniteSets, Sequences, ShushTypes

VARIABLES
    stageAction,       \* Action type from trie/classifier
    stagePolicy,       \* Base policy for that action
    hasExecEnv,        \* Stage has PAGER/EDITOR/GIT_SSH_COMMAND env assignment
    hasRedirect,       \* Stage redirects to a file
    redirectIsDevice,  \* Target is /dev/null, /dev/stdout, etc.
    redirectConfigAllowed, \* Target matched by config.allowRedirects
    redirectPath,      \* Category of redirect target path
    hasGitPath,        \* git command with -C/--git-dir/--work-tree
    gitPathCategory,   \* Category of git dir path
    hasDangerousGitConfig, \* git -c with dangerous key (LD_PRELOAD etc.)
    isShellWrapper,    \* bash -c / sh -c wrapper
    innerDecision,     \* Decision from recursive inner classification
    isDockerExec,      \* docker exec/run with inner command
    dockerInnerDecision, \* Decision from docker inner command
    hasProcSub,        \* Process substitution >(cmd) or <(cmd) present
    procSubDecision,   \* Decision from process sub inner command
    hasCmdSub,         \* Command substitution $(cmd) present
    cmdSubDecision,    \* Decision from command sub inner command
    compositionType,   \* Multi-stage composition pattern detected
    execIgnoresStdin,  \* Exec sink has inline code flag (-e, --eval)
    finalDecision      \* Computed final decision

(* ---------- Action types and default policies ---------- *)

(* All 22 action types from data/policies.json *)
ActionTypes == {
    "filesystem_read",    "filesystem_write",   "filesystem_delete",
    "git_safe",           "git_write",          "git_discard",
    "git_history_rewrite",
    "network_outbound",   "network_write",      "network_diagnostic",
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
      [] at = "network_diagnostic"   -> Allow
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
    "none",
    "sensitive_read_network",  \* sensitive read | ... | network -> block
    "network_exec",            \* network | ... | exec -> block
    "decode_exec",             \* decode | ... | exec -> block
    "any_read_exec"            \* any read | ... | exec -> ask
}

(* Composition decision with inline-code-flag suppression.
   network|exec and decode|exec suppressed when exec has -e/--eval. *)
CompositionDecisionFn(ct, ignoresStdin) ==
    CASE ct = "none"                   -> Allow
      [] ct = "sensitive_read_network" -> Block
      [] ct = "network_exec"           -> IF ignoresStdin THEN Allow ELSE Block
      [] ct = "decode_exec"            -> IF ignoresStdin THEN Allow ELSE Block
      [] ct = "any_read_exec"          -> IF ignoresStdin THEN Allow ELSE Ask

(* ---------- Path-based decision ---------- *)

PathDecision(cat) ==
    CASE cat = "sensitive_block" -> Block
      [] cat = "sensitive_ask"   -> Ask
      [] cat = "hook"            -> Block
      [] cat = "normal"          -> Allow

(* ---------- Full decision computation ---------- *)

(* Redirect logic mirrors bash-guard.ts lines 384-406 exactly:
   - redirectAllowed = redirectIsDevice OR redirectConfigAllowed
   - Write-policy escalation: only when NOT redirectAllowed (line 388)
   - Path-sensitivity check: only when NOT redirectIsDevice (line 400)
     Config-allowed redirects still get path-checked! *)
ComputeBashDecision(sp, execEnv,
                     redir, rDevice, rConfigOk, rPath,
                     gp, gpCat, dangerousGit,
                     wrapper, innerD,
                     dockerExec, dockerD,
                     pSub, pSubD, cSub, cSubD,
                     comp, ignoresStdin) ==
    LET
        baseD     == sp
        envD      == IF execEnv THEN DefaultPolicy("lang_exec") ELSE Allow

        \* Redirect write-policy: exempt when device OR config-allowed
        redirectAllowed == rDevice \/ rConfigOk
        redirBase == IF redir /\ ~redirectAllowed
                     THEN DefaultPolicy("filesystem_write")
                     ELSE Allow

        \* Redirect path check: exempt ONLY for device files
        \* Config-allowed redirects still get path-checked (line 400)
        redirPath == IF redir /\ ~rDevice THEN PathDecision(rPath) ELSE Allow

        gitD      == IF gp THEN PathDecision(gpCat) ELSE Allow
        gitCfgD   == IF dangerousGit THEN DefaultPolicy("lang_exec") ELSE Allow
        wrapD     == IF wrapper THEN innerD ELSE Allow
        dockerExecD == IF dockerExec THEN dockerD ELSE Allow
        procSubD  == IF pSub THEN pSubD ELSE Allow
        cmdSubD   == IF cSub THEN cSubD ELSE Allow
        compD     == CompositionDecisionFn(comp, ignoresStdin)

    IN  StricterAll({baseD, envD, redirBase, redirPath, gitD, gitCfgD,
                     wrapD, dockerExecD, procSubD, cmdSubD, compD})

(* ---------- State machine ---------- *)

Init ==
    /\ stageAction          \in ActionTypes
    /\ stagePolicy          = DefaultPolicy(stageAction)
    /\ hasExecEnv           \in BOOLEAN
    /\ hasRedirect          \in BOOLEAN
    /\ redirectIsDevice     \in IF hasRedirect THEN BOOLEAN ELSE {FALSE}
    /\ redirectConfigAllowed \in IF hasRedirect THEN BOOLEAN ELSE {FALSE}
    /\ redirectPath         \in IF hasRedirect /\ ~redirectIsDevice THEN PathCategories ELSE {"normal"}
    /\ hasGitPath           \in BOOLEAN
    /\ gitPathCategory      \in IF hasGitPath THEN PathCategories ELSE {"normal"}
    /\ hasDangerousGitConfig \in BOOLEAN
    /\ isShellWrapper       \in BOOLEAN
    /\ innerDecision        \in IF isShellWrapper THEN Decisions ELSE {Allow}
    /\ isDockerExec         \in BOOLEAN
    /\ dockerInnerDecision  \in IF isDockerExec THEN Decisions ELSE {Allow}
    /\ hasProcSub           \in BOOLEAN
    /\ procSubDecision      \in IF hasProcSub THEN Decisions ELSE {Allow}
    /\ hasCmdSub            \in BOOLEAN
    /\ cmdSubDecision       \in IF hasCmdSub THEN Decisions ELSE {Allow}
    /\ compositionType      \in CompositionTypes
    /\ execIgnoresStdin     \in BOOLEAN
    /\ finalDecision        = ComputeBashDecision(
            stagePolicy, hasExecEnv,
            hasRedirect, redirectIsDevice, redirectConfigAllowed, redirectPath,
            hasGitPath, gitPathCategory, hasDangerousGitConfig,
            isShellWrapper, innerDecision,
            isDockerExec, dockerInnerDecision,
            hasProcSub, procSubDecision,
            hasCmdSub, cmdSubDecision,
            compositionType, execIgnoresStdin)

Next == UNCHANGED <<stageAction, stagePolicy, hasExecEnv, hasRedirect,
                     redirectIsDevice, redirectConfigAllowed, redirectPath,
                     hasGitPath, gitPathCategory,
                     hasDangerousGitConfig, isShellWrapper, innerDecision,
                     isDockerExec, dockerInnerDecision,
                     hasProcSub, procSubDecision, hasCmdSub, cmdSubDecision,
                     compositionType, execIgnoresStdin, finalDecision>>

(* ---------- SAFETY INVARIANTS ---------- *)

TypeOK ==
    /\ stageAction \in ActionTypes
    /\ stagePolicy \in Decisions
    /\ finalDecision \in Decisions

(* INV-1: Obfuscated commands always Block *)
ObfuscatedAlwaysBlocked ==
    stageAction = "obfuscated" => finalDecision = Block

(* INV-2: decode|exec always Block (unless exec ignores stdin) *)
DecodeExecBlocked ==
    (compositionType = "decode_exec" /\ ~execIgnoresStdin)
    => finalDecision = Block

(* INV-3: sensitive_read|network always Block (exfiltration) *)
ExfilAlwaysBlocked ==
    compositionType = "sensitive_read_network"
    => finalDecision = Block

(* INV-4: network|exec always Block (unless inline code flag) *)
NetworkExecBlocked ==
    (compositionType = "network_exec" /\ ~execIgnoresStdin)
    => finalDecision = Block

(* INV-5: any_read|exec at least Ask (unless exec ignores stdin) *)
ReadExecEscalated ==
    (compositionType = "any_read_exec" /\ ~execIgnoresStdin)
    => Strictness[finalDecision] >= Strictness[Ask]

(* INV-6: Destructive ops never Allow *)
DestructiveNeverAllow ==
    stageAction \in {"disk_destructive", "container_destructive",
                      "filesystem_delete"}
    => Strictness[finalDecision] >= Strictness[Context]

(* INV-7: Exec env always escalates to >= Ask *)
ExecEnvEscalation ==
    hasExecEnv => Strictness[finalDecision] >= Strictness[Ask]

(* INV-8: Redirect to sensitive-block path -> Block
   (device files are never sensitive, so this only fires for real paths) *)
RedirectToSensitiveBlocked ==
    (hasRedirect /\ ~redirectIsDevice /\ redirectPath = "sensitive_block")
    => finalDecision = Block

(* INV-9: Redirect to hook path -> Block *)
RedirectToHookBlocked ==
    (hasRedirect /\ ~redirectIsDevice /\ redirectPath = "hook")
    => finalDecision = Block

(* INV-10: Git -C to sensitive-block -> Block *)
GitPathSensitiveEscalated ==
    (hasGitPath /\ gitPathCategory = "sensitive_block")
    => finalDecision = Block

(* INV-11: Git dangerous config -> >= Ask *)
GitDangerousConfigEscalated ==
    hasDangerousGitConfig
    => Strictness[finalDecision] >= Strictness[Ask]

(* INV-12: Shell wrapper never downgrades inner decision *)
ShellWrapperNoDowngrade ==
    isShellWrapper
    => Strictness[finalDecision] >= Strictness[innerDecision]

(* INV-13: Docker exec/run never downgrades inner decision *)
DockerExecNoDowngrade ==
    isDockerExec
    => Strictness[finalDecision] >= Strictness[dockerInnerDecision]

(* INV-14: Process substitution never downgrades inner decision *)
ProcSubNoDowngrade ==
    hasProcSub
    => Strictness[finalDecision] >= Strictness[procSubDecision]

(* INV-15: Command substitution never downgrades inner decision *)
CmdSubNoDowngrade ==
    hasCmdSub
    => Strictness[finalDecision] >= Strictness[cmdSubDecision]

(* INV-16: Final never weaker than base policy *)
NoDowngradeFromBase ==
    Strictness[finalDecision] >= Strictness[stagePolicy]

(* INV-17: Unknown -> >= Ask *)
UnknownDefaultsToAsk ==
    stageAction = "unknown"
    => Strictness[finalDecision] >= Strictness[Ask]

(* INV-18: lang_exec -> >= Ask *)
LangExecAlwaysAsk ==
    stageAction = "lang_exec"
    => Strictness[finalDecision] >= Strictness[Ask]

(* INV-19: network_write -> >= Ask *)
NetworkWriteAlwaysAsk ==
    stageAction = "network_write"
    => Strictness[finalDecision] >= Strictness[Ask]

(* INV-20: Config-allowed redirect does NOT bypass sensitive path check.
   Even with config exemption, non-device sensitive targets still block. *)
ConfigAllowedRedirectNoPathBypass ==
    (hasRedirect /\ redirectConfigAllowed /\ ~redirectIsDevice
     /\ redirectPath = "sensitive_block")
    => finalDecision = Block

(* INV-21 removed: device redirect constraint now enforced in Init *)

(* INV-22: Inline code flag suppression doesn't bypass base classification *)
InlineFlagNoBaseBypass ==
    (stageAction = "obfuscated" /\ execIgnoresStdin)
    => finalDecision = Block

(* Combined *)
SafetyInvariant ==
    /\ TypeOK
    /\ ObfuscatedAlwaysBlocked
    /\ DecodeExecBlocked
    /\ ExfilAlwaysBlocked
    /\ NetworkExecBlocked
    /\ ReadExecEscalated
    /\ DestructiveNeverAllow
    /\ ExecEnvEscalation
    /\ RedirectToSensitiveBlocked
    /\ RedirectToHookBlocked
    /\ GitPathSensitiveEscalated
    /\ GitDangerousConfigEscalated
    /\ ShellWrapperNoDowngrade
    /\ DockerExecNoDowngrade
    /\ ProcSubNoDowngrade
    /\ CmdSubNoDowngrade
    /\ NoDowngradeFromBase
    /\ UnknownDefaultsToAsk
    /\ LangExecAlwaysAsk
    /\ NetworkWriteAlwaysAsk
    /\ ConfigAllowedRedirectNoPathBypass
    /\ InlineFlagNoBaseBypass

=========================================================================
