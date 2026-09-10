---------------------- MODULE DurablePublication ----------------------
(* One fixed session/seat; up to four writes and two public commitments. *)
(* R/B stand for fresh-slot reserve and bind-to-this-context. Histories    *)
(* represent collision-free journal heads. Writes are already durable;    *)
(* torn writes, hash collisions and dishonest anchors are outside scope.  *)
EXTENDS Integers, Sequences, FiniteSets
CONSTANTS GuardDuplicate, GuardAnchor, GuardBeforePublish
Histories == UNION {[1..n -> {"R", "B"}] : n \in 0..4}
VARIABLES journal, anchor, pc, published, premature, recovered, lostAck
vars == <<journal, anchor, pc, published, premature, recovered, lostAck>>
PCs == {"idle", "reserveAck", "bind", "bindAck", "ready", "done", "halted"}
Prefix(a, b) == Len(a) <= Len(b) /\ a = SubSeq(b, 1, Len(a))
ContainsBind(h) == \E i \in 1..Len(h) : h[i] = "B"
Init == /\ journal = <<>> /\ anchor = <<>> /\ pc = "idle"
        /\ published = 0 /\ premature = FALSE /\ recovered = FALSE /\ lostAck = FALSE
Start ==
    /\ pc = "idle" /\ Len(journal) < 4
    /\ GuardAnchor => journal = anchor
    /\ GuardDuplicate => ~ContainsBind(journal)
    /\ journal' = Append(journal, "R") /\ pc' = "reserveAck"
    /\ UNCHANGED <<anchor, published, premature, recovered, lostAck>>
Bind ==
    /\ pc = "bind" /\ Len(journal) < 4
    /\ journal' = Append(journal, "B") /\ pc' = "bindAck"
    /\ UNCHANGED <<anchor, published, premature, recovered, lostAck>>
Acknowledge ==
    /\ pc \in {"reserveAck", "bindAck"}
    /\ GuardAnchor => (Len(journal) = Len(anchor)+1 /\ Prefix(anchor, journal))
    /\ anchor' = journal
    /\ pc' = IF pc = "reserveAck" THEN "bind" ELSE "ready"
    /\ UNCHANGED <<journal, published, premature, recovered, lostAck>>
(* An acknowledgement may be lost either before or after the anchor writes. *)
LoseAck(commit) ==
    /\ pc \in {"reserveAck", "bindAck"}
    /\ Len(journal) = Len(anchor)+1 /\ Prefix(anchor, journal)
    /\ anchor' = IF commit THEN journal ELSE anchor
    /\ pc' = "halted" /\ lostAck' = (lostAck \/ published = 0)
    /\ UNCHANGED <<journal, published, premature, recovered>>
Crash == /\ pc # "idle" /\ pc' = "idle"
         /\ UNCHANGED <<journal, anchor, published, premature, recovered, lostAck>>
Recover ==
    /\ pc = "idle" /\ Len(journal) = Len(anchor)+1 /\ Prefix(anchor, journal)
    /\ anchor' = journal /\ recovered' = (recovered \/ published = 0)
    /\ UNCHANGED <<journal, pc, published, premature, lostAck>>
Rollback(n) ==
    /\ n \in 0..(Len(journal)-1)
    /\ journal' = SubSeq(journal, 1, n) /\ pc' = "idle"
    /\ UNCHANGED <<anchor, published, premature, recovered, lostAck>>
Publish ==
    /\ IF GuardBeforePublish THEN pc = "ready" ELSE pc \in {"ready", "bindAck"}
    /\ published < 2
    /\ published' = published + 1 /\ pc' = "done"
    /\ premature' = (premature \/ ~(journal = anchor /\ ContainsBind(anchor)))
    /\ UNCHANGED <<journal, anchor, recovered, lostAck>>
Next == Start \/ Bind \/ Acknowledge \/ Crash \/ Recover \/ Publish
        \/ (\E c \in BOOLEAN : LoseAck(c)) \/ (\E n \in 0..4 : Rollback(n))
Spec == Init /\ [][Next]_vars
TypeOK == /\ journal \in Histories /\ anchor \in Histories /\ pc \in PCs
          /\ published \in 0..2 /\ premature \in BOOLEAN
          /\ recovered \in BOOLEAN /\ lostAck \in BOOLEAN
INV_OnePublication == published <= 1
INV_AnchoredBeforePublication == ~premature
COV_Publish == published = 0
COV_RecoverThenPublish == ~(recovered /\ published = 1)
COV_LostAckThenPublish == ~(lostAck /\ published = 1)
=======================================================================
