------------------------ MODULE BypassCheckBash ------------------------
(* Adversarial bypass analysis for BashGuard.

   Searches for states where dangerous Bash commands get Allow.
   Each bypass property is a claim that should hold. If TLC finds
   a counterexample, it's a potential bypass vector. *)

EXTENDS Naturals, FiniteSets, Sequences, ShushTypes

VARIABLES
    stageAction, stagePolicy,
    hasExecEnv, hasRedirect, redirectIsDevice, redirectConfigAllowed,
    redirectPath, hasGitPath, gitPathCategory, hasDangerousGitConfig,
    isShellWrapper, innerDecision,
    isDockerExec, dockerInnerDecision,
    hasProcSub, procSubDecision, hasCmdSub, cmdSubDecision,
    compositionType, execIgnoresStdin, finalDecision

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

PathCategories == {"hook", "sensitive_block", "sensitive_ask", "normal"}

CompositionTypes == {
    "none", "sensitive_read_network", "network_exec",
    "decode_exec", "any_read_exec"
}

CompositionDecisionFn(ct, ignoresStdin) ==
    CASE ct = "none"                   -> Allow
      [] ct = "sensitive_read_network" -> Block
      [] ct = "network_exec"           -> IF ignoresStdin THEN Allow ELSE Block
      [] ct = "decode_exec"            -> IF ignoresStdin THEN Allow ELSE Block
      [] ct = "any_read_exec"          -> IF ignoresStdin THEN Allow ELSE Ask

PathDecision(cat) ==
    CASE cat = "sensitive_block" -> Block
      [] cat = "sensitive_ask"   -> Ask
      [] cat = "hook"            -> Block
      [] cat = "normal"          -> Allow

ComputeBashDecision(sp, execEnv,
                     redir, rDevice, rConfigOk, rPath,
                     gp, gpCat, dangerousGit,
                     wrapper, innerD,
                     dockerExec, dockerD,
                     pSub, pSubD, cSub, cSubD,
                     comp, ignoresStdin) ==
    LET baseD     == sp
        envD      == IF execEnv THEN DefaultPolicy("lang_exec") ELSE Allow
        redirectAllowed == rDevice \/ rConfigOk
        redirBase == IF redir /\ ~redirectAllowed
                     THEN DefaultPolicy("filesystem_write")
                     ELSE Allow
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

(* ======================================================================
   BYPASS PROPERTIES
   ====================================================================== *)

(* BYPASS-B1: Can dangerous composition get Allow WITHOUT inline flag?
   network|exec or decode|exec without -e/-c should NEVER be Allow. *)
B_CompositionNoBypass ==
    (compositionType \in {"network_exec", "decode_exec", "sensitive_read_network"}
     /\ ~execIgnoresStdin)
    => finalDecision /= Allow

(* BYPASS-B2: Can inline code flag suppress exfil (sensitive_read|network)?
   Exfil should ALWAYS block, even with inline flag. *)
B_ExfilNoInlineSuppression ==
    compositionType = "sensitive_read_network"
    => finalDecision = Block

(* BYPASS-B3: Can a redirect to a sensitive path get Allow?
   Even with config allowRedirects, sensitive paths must not be Allow. *)
B_RedirectSensitiveNoAllow ==
    (hasRedirect /\ redirectPath \in {"sensitive_block", "hook"})
    => finalDecision /= Allow

(* BYPASS-B4: Can a shell wrapper hide a Block-worthy inner command?
   If inner classified as Block, wrapper must also be Block. *)
B_WrapperNoBlockDowngrade ==
    (isShellWrapper /\ innerDecision = Block)
    => finalDecision = Block

(* BYPASS-B5: Can docker exec hide a Block-worthy inner command? *)
B_DockerNoBlockDowngrade ==
    (isDockerExec /\ dockerInnerDecision = Block)
    => finalDecision = Block

(* BYPASS-B6: Can process/command substitution with Block be downgraded? *)
B_SubstitutionNoBlockDowngrade ==
    ((hasProcSub /\ procSubDecision = Block) \/
     (hasCmdSub /\ cmdSubDecision = Block))
    => finalDecision = Block

(* BYPASS-B7: Can a dangerous git config (-c) ever get Allow? *)
B_GitConfigNoAllow ==
    hasDangerousGitConfig => finalDecision /= Allow

(* BYPASS-B8: Can exec-env-var escalation (PAGER/EDITOR) get Allow? *)
B_ExecEnvNoAllow ==
    hasExecEnv => finalDecision /= Allow

(* BYPASS-B9: Can config allowRedirects + safe-exempt combine to
   make a non-device redirect to sensitive path get Allow?
   This is the key redirect bypass vector. *)
B_ConfigAllowRedirectSensitiveNoAllow ==
    (hasRedirect /\ redirectConfigAllowed /\ ~redirectIsDevice
     /\ redirectPath = "sensitive_block")
    => finalDecision /= Allow

(* BYPASS-B10: Can a filesystem_write action + redirect to hook path
   ever be Allow? This tests if redirecting output to hooks is caught. *)
B_RedirectToHookNoAllow ==
    (hasRedirect /\ ~redirectIsDevice /\ redirectPath = "hook")
    => finalDecision /= Allow

(* BYPASS-B11: Can an "allow" base policy action combined with a
   dangerous inner substitution still produce Allow?
   e.g., `ls $(rm -rf /)` - base is filesystem_read (allow) but
   sub should escalate. *)
B_SafeBaseWithDangerousSubNoAllow ==
    (stageAction = "filesystem_read" /\ hasCmdSub /\ cmdSubDecision = Block)
    => finalDecision = Block

(* BYPASS-B12: Can inline code flag suppression accidentally allow
   an otherwise-blocked BASE command? Inline flag should only suppress
   composition rules, not the base classification. *)
B_InlineFlagNoBaseBypass ==
    (stageAction = "obfuscated" /\ execIgnoresStdin)
    => finalDecision = Block

(* BYPASS-B13: Multiple escalation layers that individually are < Block
   but should combine to Block via stricter().
   git -C ~/.ssh + dangerous config + exec env = should be Block *)
B_MultiLayerEscalation ==
    (hasGitPath /\ gitPathCategory = "sensitive_block"
     /\ hasDangerousGitConfig /\ hasExecEnv)
    => finalDecision = Block

(* Combined *)
BypassInvariant ==
    /\ B_CompositionNoBypass
    /\ B_ExfilNoInlineSuppression
    /\ B_RedirectSensitiveNoAllow
    /\ B_WrapperNoBlockDowngrade
    /\ B_DockerNoBlockDowngrade
    /\ B_SubstitutionNoBlockDowngrade
    /\ B_GitConfigNoAllow
    /\ B_ExecEnvNoAllow
    /\ B_ConfigAllowRedirectSensitiveNoAllow
    /\ B_RedirectToHookNoAllow
    /\ B_SafeBaseWithDangerousSubNoAllow
    /\ B_InlineFlagNoBaseBypass
    /\ B_MultiLayerEscalation

=========================================================================
