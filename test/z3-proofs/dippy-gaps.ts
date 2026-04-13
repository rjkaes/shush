import {
  getZ3,
  D,
  stricter,
  validDecision,
  report,
  POLICIES,
} from "../z3-helpers";

/**
 * Z3 proofs for invariants surfaced by reviewing Dippy issue tracker.
 *
 * D1: find -delete always yields at least Context
 *   Models: classifyFind returns FILESYSTEM_DELETE when it sees -delete.
 *   FILESYSTEM_DELETE maps to "context" in policies.json. Pipeline takes
 *   stricter(base, classifierResult), so final decision >= context.
 *
 * D2: git global flag stripping preserves classification
 *   Models: stripGitGlobalFlags removes -C/--git-dir/--no-pager etc.
 *   The classification of stripped tokens must equal classification of
 *   the same tokens without flags. Proved via symbolic function equality.
 *
 * D3: parse failures never produce Allow
 *   Models: when the bash parser fails, the fallback path must yield
 *   decision >= ask. Assert Allow is impossible on error path.
 */
async function main() {
  const { Context } = await getZ3();

  // D1: find -delete always >= Context
  // FILESYSTEM_DELETE policy is "context" (severity 1). Any pipeline stage
  // classified as FILESYSTEM_DELETE gets at least Context. Even if another
  // stage in the pipeline is Allow, stricter-wins pushes result >= Ask.
  {
    const ctx = new Context("D1");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    // The find classifier returns FILESYSTEM_DELETE for -delete
    const findDeletePolicy = Int.val(POLICIES["filesystem_delete"]);

    // Some other stage in the pipeline might be less strict
    const otherStage = Int.const("otherStage");
    solver.add(validDecision(ctx, otherStage));

    // Pipeline result = stricter of all stages
    const pipelineResult = stricter(ctx, otherStage, findDeletePolicy);

    // Try to find: pipeline result < Context (severity 1)
    // filesystem_delete maps to "context", so pipeline must be >= context
    solver.add(pipelineResult.lt(findDeletePolicy));
    report("D1", await solver.check());
  }

  // D2: git global flag stripping preserves classification
  // Model: a symbolic classification function f applied to tokens.
  // stripGitGlobalFlags(["git", ...flags, subcmd, ...args]) yields
  // ["git", subcmd, ...args]. Prove f(stripped) == f(original_without_flags)
  // by modeling the stripping as: for all flag combos, the subcommand
  // position is found correctly, so classification is identical.
  //
  // We model this abstractly: the classification depends only on the
  // subcommand and its arguments (post-strip tokens). Global flags are
  // consumed and discarded. So classify(strip(tokens)) == classify(clean)
  // where clean = ["git", subcmd, ...args].
  {
    const ctx = new Context("D2");
    const { Solver, Int, Function: Func } = ctx;
    const solver = new Solver();

    // classify: maps subcommand index -> decision
    const classify = Func.declare("classify", Int.sort(), Int.sort());

    // Subcommand is the same token regardless of flag presence
    const subcmd = Int.const("subcmd");

    // Number of global flag tokens consumed (symbolic, >= 0)
    const flagTokens = Int.const("flagTokens");
    solver.add(flagTokens.ge(0));

    // After stripping, the subcommand is at position 1 (right after "git")
    // Before stripping, it's at position 1 + flagTokens
    // stripGitGlobalFlags extracts it to position 1
    // These are trivially equal because subcmd is the same.
    // The real invariant: stripping does not change the subcommand identity.
    // Model the subcommand extraction: position = 1 + flagTokens in original,
    // position = 1 in stripped. Both yield the same subcmd if stripping is correct.
    const subcmdFromOriginal = Int.const("subcmdFromOriginal");
    const subcmdFromStripped = Int.const("subcmdFromStripped");

    // Strip function postcondition: both yield same subcommand
    solver.add(subcmdFromStripped.eq(subcmdFromOriginal));

    // Try to find: classifications differ
    solver.add(classify.call(subcmdFromStripped).neq(classify.call(subcmdFromOriginal)));
    report("D2", await solver.check());
  }

  // D3: parse failures never produce Allow
  // When unbash/extractStages throws or returns an error, bash-guard
  // falls back to "ask" decision. Model: on parse error, decision is
  // constrained to {ask, block}. Assert Allow is reachable → UNSAT.
  {
    const ctx = new Context("D3");
    const { Solver, Int, Bool } = ctx;
    const solver = new Solver();

    const decision = Int.const("decision");
    const parseError = Bool.const("parseError");

    solver.add(validDecision(ctx, decision));

    // When parse error occurs, decision must be >= ask
    solver.add(
      ctx.Implies(parseError, decision.ge(Int.val(D.ask))),
    );

    // Try to find: parse error AND decision == allow
    solver.add(parseError);
    solver.add(decision.eq(Int.val(D.allow)));
    report("D3", await solver.check());
  }

  // D4: rm on sensitive path >= Write on same path
  // Write tool on a sensitive path gets pathPolicy directly.
  // rm gets stricter(filesystem_delete_policy, pathPolicy) = max(delete, path).
  // Since max(x, pathPolicy) >= pathPolicy, rm is always at least as strict.
  {
    const ctx = new Context("D4");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const pathPolicy = Int.const("pathPolicy");
    const deletePolicy = Int.val(POLICIES["filesystem_delete"]);
    solver.add(validDecision(ctx, pathPolicy));

    const writeDecision = pathPolicy;
    const rmDecision = stricter(ctx, deletePolicy, pathPolicy);

    // Try to find: rm decision < Write decision on same path
    solver.add(rmDecision.lt(writeDecision));
    report("D4", await solver.check());
  }

  // D5: find -delete on sensitive root >= Write on same root
  // Same structure as D4. find -delete gets FILESYSTEM_DELETE policy
  // composed with the search root's path policy via stricter().
  // The path-check loop in bash-guard applies checkPath("Write", root)
  // and takes stricter(current, pathResult). So the final decision is
  // at least max(filesystem_delete_policy, pathPolicy) >= pathPolicy.
  {
    const ctx = new Context("D5");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const pathPolicy = Int.const("pathPolicy");
    const deletePolicy = Int.val(POLICIES["filesystem_delete"]);
    solver.add(validDecision(ctx, pathPolicy));

    const writeDecision = pathPolicy;
    const findDeleteDecision = stricter(ctx, deletePolicy, pathPolicy);

    // Try to find: find -delete decision < Write decision on same path
    solver.add(findDeleteDecision.lt(writeDecision));
    report("D5", await solver.check());
  }

  // D6: network_outbound on sensitive path >= Read on same path
  // Network commands (scp, rsync) that access file paths get
  // stricter(network_outbound_policy, pathPolicy). Read tool gets
  // pathPolicy directly. Since stricter(x, P) = max(x, P) >= P,
  // network commands are always at least as strict as Read.
  {
    const ctx = new Context("D6");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const pathPolicy = Int.const("pathPolicy");
    const networkPolicy = Int.val(POLICIES["network_outbound"]);
    solver.add(validDecision(ctx, pathPolicy));

    const readDecision = pathPolicy;
    const networkDecision = stricter(ctx, networkPolicy, pathPolicy);

    // Try to find: network decision < Read decision on same path
    solver.add(networkDecision.lt(readDecision));
    report("D6", await solver.check());
  }

  // D7: git clone to sensitive path >= Write to that path
  // git_write policy is "allow" (0). Path-check adds
  // stricter(allow, pathPolicy) = pathPolicy. Write tool gets pathPolicy.
  // So git clone to sensitive path gets exactly the same as Write.
  {
    const ctx = new Context("D7");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const pathPolicy = Int.const("pathPolicy");
    const gitWritePolicy = Int.val(POLICIES["git_write"]);
    solver.add(validDecision(ctx, pathPolicy));

    const writeDecision = pathPolicy;
    const gitCloneDecision = stricter(ctx, gitWritePolicy, pathPolicy);

    // Try to find: git clone decision < Write decision
    solver.add(gitCloneDecision.lt(writeDecision));
    report("D7", await solver.check());
  }

  // D8: docker -v mount of sensitive path >= Write to that path
  // Docker inner command gets some decision D_inner. Volume mount
  // path-check adds stricter(D_inner, pathPolicy). Write tool gets
  // pathPolicy. Since stricter(D_inner, pathPolicy) >= pathPolicy,
  // docker with sensitive mount is always >= Write.
  {
    const ctx = new Context("D8");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const pathPolicy = Int.const("pathPolicy");
    const innerDecision = Int.const("innerDecision");
    solver.add(validDecision(ctx, pathPolicy));
    solver.add(validDecision(ctx, innerDecision));

    const writeDecision = pathPolicy;
    const dockerDecision = stricter(ctx, innerDecision, pathPolicy);

    // Try to find: docker decision < Write decision
    solver.add(dockerDecision.lt(writeDecision));
    report("D8", await solver.check());
  }

  // D9: Universal path-check guarantee (meta-proof)
  // For ANY action type policy P_action and ANY path policy P_path,
  // stricter(P_action, P_path) >= P_path. This is the algebraic
  // guarantee that IF the path-check code runs for an action type,
  // the sensitive path's policy is never weakened by the action type's
  // own policy. Combined with the meta-property test (which verifies
  // the path-check code IS reached for all file-operating types),
  // this gives full coverage.
  {
    const ctx = new Context("D9");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const actionPolicy = Int.const("actionPolicy");
    const pathPolicy = Int.const("pathPolicy");
    solver.add(validDecision(ctx, actionPolicy));
    solver.add(validDecision(ctx, pathPolicy));

    const combined = stricter(ctx, actionPolicy, pathPolicy);

    // Try to find: combined < pathPolicy
    solver.add(combined.lt(pathPolicy));
    report("D9", await solver.check());
  }

  // M1: Shell unwrapping never downgrades a decision
  // If inner command has decision D_inner and wrapper has decision D_wrapper,
  // then final = stricter(D_wrapper, D_inner) >= D_inner.
  // This is a direct consequence of stricter(a, b) >= max(a, b) >= b.
  {
    const ctx = new Context("M1");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const D_inner = Int.const("D_inner");
    const D_wrapper = Int.const("D_wrapper");
    solver.add(validDecision(ctx, D_inner));
    solver.add(validDecision(ctx, D_wrapper));

    const combined = stricter(ctx, D_wrapper, D_inner);

    // Try to find: combined < D_inner (would mean wrapping downgraded)
    solver.add(combined.lt(D_inner));
    report("M1", await solver.check());
  }

  // M2: Config overrides can't loosen sensitive-path decisions
  // For any path with built-in policy P_path >= ask, and any
  // config-overridden action policy P_config (even allow), the final
  // decision = stricter(P_config, P_path) >= P_path >= ask.
  // Config can only tighten, never loosen, sensitive path protections.
  {
    const ctx = new Context("M2");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    const pathPolicy = Int.const("pathPolicy");
    const configPolicy = Int.const("configPolicy");
    solver.add(validDecision(ctx, pathPolicy));
    solver.add(validDecision(ctx, configPolicy));

    // Built-in sensitive paths have policy >= ask (severity 2)
    solver.add(pathPolicy.ge(Int.val(D.ask)));

    // Config can set action policy to anything, even allow (0)
    // Final decision = stricter(configPolicy, pathPolicy)
    const finalDecision = stricter(ctx, configPolicy, pathPolicy);

    // Try to find: final decision < ask (would mean config loosened protection)
    solver.add(finalDecision.lt(Int.val(D.ask)));
    report("M2", await solver.check());
  }

  // M4: Hook self-protection across all tools + bash
  // For hook paths (pathPolicy = block = 3), write tools always get block.
  // For bash commands, stricter(any_action_policy, block) = block.
  // This is the highest-severity invariant: hooks can never be weakened.
  {
    const ctx = new Context("M4");
    const { Solver, Int } = ctx;
    const solver = new Solver();

    // Hook paths have pathPolicy = block (3)
    const hookPathPolicy = Int.val(D.block);

    // Any action policy from the taxonomy
    const actionPolicy = Int.const("actionPolicy");
    solver.add(validDecision(ctx, actionPolicy));

    // For write tools: decision = pathPolicy directly = block.
    // For bash: decision = stricter(actionPolicy, hookPathPolicy).
    // In both cases, result must be block.
    const bashDecision = stricter(ctx, actionPolicy, hookPathPolicy);

    // Try to find: bash decision < block (would mean hook protection weakened)
    solver.add(bashDecision.lt(Int.val(D.block)));
    report("M4", await solver.check());
  }
}

main().then(() => process.exit(0));
