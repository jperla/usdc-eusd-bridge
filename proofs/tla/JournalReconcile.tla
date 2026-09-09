----------------------- MODULE JournalReconcile -----------------------
(* Bounded independent recovery model. Histories abstract collision-free *)
(* journal digests; fsync/read-back and anchor durability are premises.   *)
EXTENDS Integers, Sequences, FiniteSets
CONSTANTS GuardPredecessor, GuardSequence, GuardPoison
Histories == UNION { [1..n -> {"a", "b"}] : n \in 0..3 }
VARIABLES journal, original, anchor, poisoned, recovered
vars == <<journal, original, anchor, poisoned, recovered>>
Init == /\ journal \in Histories /\ original \in Histories
        /\ anchor = original /\ poisoned \in BOOLEAN /\ recovered = FALSE
Recover ==
    /\ ~recovered
    /\ GuardPoison => ~poisoned
    /\ Len(journal) > 0
    /\ GuardSequence => Len(journal) = Len(anchor) + 1
    /\ GuardPredecessor => SubSeq(journal, 1, Len(journal)-1) = anchor
    /\ anchor' = journal /\ recovered' = TRUE
    /\ UNCHANGED <<journal, original, poisoned>>
Next == Recover
Spec == Init /\ [][Next]_vars
TypeOK == /\ journal \in Histories /\ original \in Histories /\ anchor \in Histories
          /\ poisoned \in BOOLEAN /\ recovered \in BOOLEAN
INV_ExactContinuation == recovered =>
    /\ Len(anchor) = Len(original) + 1
    /\ SubSeq(anchor, 1, Len(original)) = original
INV_NoPoisonRecovery == recovered => ~poisoned
COV_CanRecover == ~recovered
=======================================================================
