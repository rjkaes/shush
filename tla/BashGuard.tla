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
    hasFileArgs,        \* Stage has file path arguments (cat, head, etc.)
    fileArgCategory,    \* Sensitivity category of file argument path
    finalDecision      \* Computed final decision

(* ---------- Action types and default policies ---------- *)

(* Symmetry reduction: 22 action types share only 4 distinct policies.
   One representative per policy group is sufficient for model checking
   since the decision logic only depends on the policy value, not the
   action type name (except for specific invariants that name types).

   allow:   filesystem_read (+ 6 others)
   context: filesystem_write (+ 3 others)
   ask:     unknown (+ 9 others, including lang_exec, disk_destructive)
   block:   obfuscated (only one)

   We keep filesystem_read and filesystem_write because the file-arg
   path check branches on policy=Allow to distinguish read vs write. *)
ActionTypes == {
    "filesystem_read",    \* representative: allow policy
    "filesystem_write",   \* representative: context policy
    "unknown",            \* representative: ask policy
    "obfuscated"          \* representative: block policy
}

DefaultPolicy(at) ==
    CASE at = "filesystem_read"      -> Allow
      [] at = "filesystem_write"     -> Context
      [] at = "unknown"              -> Ask
      [] at = "obfuscated"           -> Block

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

(* Path decision for Bash tool redirect/git-dir targets.
   checkPath("Bash", ...) is called. "Bash" is not in HOOK_BLOCK_TOOLS
   (Write/Edit/MultiEdit/NotebookEdit) or HOOK_READONLY_TOOLS (Read/Glob/Grep),
   so hook paths get Ask (the else branch), not Block. *)
(* Path decisions differ by context because checkPath uses different
   tool names for different checks:
   - Redirects use "Write" -> hooks get Block
   - Git paths use "Bash" -> hooks get Ask
   - File args use "Read" or "Write" depending on actionType *)
RedirectPathDecision(cat) ==
    CASE cat = "sensitive_block" -> Block
      [] cat = "sensitive_ask"   -> Ask
      [] cat = "hook"            -> Block  \* checkPath("Write", ...) -> HOOK_BLOCK_TOOLS
      [] cat = "normal"          -> Allow

GitPathDecision(cat) ==
    CASE cat = "sensitive_block" -> Block
      [] cat = "sensitive_ask"   -> Ask
      [] cat = "hook"            -> Ask    \* checkPath("Bash", ...) -> else branch
      [] cat = "normal"          -> Allow

(* File arg path check: Read for reads (hooks allowed), Write for writes *)
FileArgReadPathDecision(cat) ==
    CASE cat = "sensitive_block" -> Block
      [] cat = "sensitive_ask"   -> Ask
      [] cat = "hook"            -> Allow  \* checkPath("Read", ...) -> HOOK_READONLY_TOOLS
      [] cat = "normal"          -> Allow

FileArgWritePathDecision(cat) ==
    CASE cat = "sensitive_block" -> Block
      [] cat = "sensitive_ask"   -> Ask
      [] cat = "hook"            -> Block  \* checkPath("Write", ...) -> HOOK_BLOCK_TOOLS
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
                     comp, ignoresStdin,
                     fileArgs, fileArgCat) ==
    LET
        baseD     == sp
        envD      == IF execEnv THEN Ask ELSE Allow  \* lang_exec policy = Ask

        \* Redirect write-policy: exempt when device OR config-allowed
        redirectAllowed == rDevice \/ rConfigOk
        redirBase == IF redir /\ ~redirectAllowed
                     THEN DefaultPolicy("filesystem_write")
                     ELSE Allow

        \* Redirect path check: exempt ONLY for device files
        redirPath == IF redir /\ ~rDevice THEN RedirectPathDecision(rPath) ELSE Allow

        gitD      == IF gp THEN GitPathDecision(gpCat) ELSE Allow
        gitCfgD   == IF dangerousGit THEN Ask ELSE Allow  \* lang_exec policy = Ask
        wrapD     == IF wrapper THEN innerD ELSE Allow
        dockerExecD == IF dockerExec THEN dockerD ELSE Allow
        procSubD  == IF pSub THEN pSubD ELSE Allow
        cmdSubD   == IF cSub THEN cSubD ELSE Allow
        compD     == CompositionDecisionFn(comp, ignoresStdin)

        \* File argument path check: filesystem_read/write commands
        \* check positional args against sensitive paths.
        \* File args: Read for reads (hooks allowed), Write for writes (hooks blocked)
        fileArgD  == IF fileArgs
                     THEN IF sp = Allow \* filesystem_read -> allow policy
                          THEN FileArgReadPathDecision(fileArgCat)
                          ELSE FileArgWritePathDecision(fileArgCat)
                     ELSE Allow

    IN  StricterAll({baseD, envD, redirBase, redirPath, gitD, gitCfgD,
                     wrapD, dockerExecD, procSubD, cmdSubD, compD, fileArgD})

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
    /\ hasFileArgs          \in BOOLEAN
    /\ fileArgCategory      \in IF hasFileArgs THEN PathCategories ELSE {"normal"}
    /\ finalDecision        = ComputeBashDecision(
            stagePolicy, hasExecEnv,
            hasRedirect, redirectIsDevice, redirectConfigAllowed, redirectPath,
            hasGitPath, gitPathCategory, hasDangerousGitConfig,
            isShellWrapper, innerDecision,
            isDockerExec, dockerInnerDecision,
            hasProcSub, procSubDecision,
            hasCmdSub, cmdSubDecision,
            compositionType, execIgnoresStdin,
            hasFileArgs, fileArgCategory)

Next == UNCHANGED <<stageAction, stagePolicy, hasExecEnv, hasRedirect,
                     redirectIsDevice, redirectConfigAllowed, redirectPath,
                     hasGitPath, gitPathCategory,
                     hasDangerousGitConfig, isShellWrapper, innerDecision,
                     isDockerExec, dockerInnerDecision,
                     hasProcSub, procSubDecision, hasCmdSub, cmdSubDecision,
                     compositionType, execIgnoresStdin,
                     hasFileArgs, fileArgCategory, finalDecision>>

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

(* INV-6: Non-allow policy types never get Allow.
   Covers disk_destructive, container_destructive, filesystem_delete,
   etc. via their representative: filesystem_write (context) and
   unknown (ask). *)
NonAllowPolicyNeverAllow ==
    stagePolicy /= Allow
    => finalDecision /= Allow

(* INV-7: Exec env always escalates to >= Ask *)
ExecEnvEscalation ==
    hasExecEnv => Strictness[finalDecision] >= Strictness[Ask]

(* INV-8: Redirect to sensitive-block path -> Block
   (device files are never sensitive, so this only fires for real paths) *)
RedirectToSensitiveBlocked ==
    (hasRedirect /\ ~redirectIsDevice /\ redirectPath = "sensitive_block")
    => finalDecision = Block

(* INV-9: Redirect to hook path -> Block.
   Redirects now use checkPath("Write", ...) so hooks get Block. *)
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

(* INV-18: ask-policy types -> >= Ask.
   Covers lang_exec, network_write, unknown, disk_destructive, etc. *)
AskPolicyAlwaysAsk ==
    stagePolicy = Ask
    => Strictness[finalDecision] >= Strictness[Ask]

(* INV-19: removed - subsumed by AskPolicyAlwaysAsk *)

(* INV-20: File args targeting sensitive-block paths -> Block *)
FileArgSensitiveBlocked ==
    (hasFileArgs /\ fileArgCategory = "sensitive_block")
    => finalDecision = Block

(* INV-21: File args targeting sensitive-ask paths -> >= Ask *)
FileArgSensitiveAsk ==
    (hasFileArgs /\ fileArgCategory = "sensitive_ask")
    => Strictness[finalDecision] >= Strictness[Ask]

(* INV-22: File args targeting hook paths:
   - filesystem_write -> Block (checkPath("Write", ...) -> HOOK_BLOCK_TOOLS)
   - filesystem_read -> Allow (checkPath("Read", ...) -> HOOK_READONLY_TOOLS)
   We can only express the write case since read legitimately allows hooks. *)
FileArgHookWriteBlocked ==
    (hasFileArgs /\ fileArgCategory = "hook" /\ stagePolicy /= Allow)
    => finalDecision = Block

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
    /\ NonAllowPolicyNeverAllow
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
    /\ AskPolicyAlwaysAsk
    /\ ConfigAllowedRedirectNoPathBypass
    /\ FileArgSensitiveBlocked
    /\ FileArgSensitiveAsk
    /\ FileArgHookWriteBlocked
    /\ InlineFlagNoBaseBypass

=========================================================================
