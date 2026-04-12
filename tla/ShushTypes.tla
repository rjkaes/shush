--------------------------- MODULE ShushTypes ---------------------------
(* Shared type definitions for shush security model verification.

   Models the four-level decision lattice and strictness ordering
   that underpins all security decisions in shush. *)

EXTENDS Naturals, TLC

CONSTANT Allow, Context, Ask, Block

(* Decision strictness ordering: allow < context < ask < block *)
Strictness == Allow :> 0 @@ Context :> 1 @@ Ask :> 2 @@ Block :> 3

Decisions == {Allow, Context, Ask, Block}

(* Core operator: returns the stricter of two decisions.
   This mirrors src/types.ts stricter() exactly. *)
Stricter(a, b) == IF Strictness[a] >= Strictness[b] THEN a ELSE b

(* Fold stricter across a set of decisions *)
RECURSIVE StricterAll(_)
StricterAll(S) ==
    IF S = {} THEN Allow
    ELSE LET x == CHOOSE x \in S : TRUE
         IN  Stricter(x, StricterAll(S \ {x}))

=========================================================================
