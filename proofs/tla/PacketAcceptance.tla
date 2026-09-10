----------------------- MODULE PacketAcceptance -----------------------
(* Finite abstraction of mlsag::wire::decode. Signature validity and      *)
(* collision-free session/transcript contexts are premises. A caller     *)
(* supplies the trust root and expected seat/phase/context independently. *)
EXTENDS Integers
CONSTANTS GuardIdentity, GuardSignature, GuardSeat, GuardPhase,
          GuardSession, GuardTranscript, GuardDomain, GuardCanonical, GuardLength
VARIABLES packet, expectedPhase, accepted
vars == <<packet, expectedPhase, accepted>>
Packets == [key : {"trusted", "stranger"}, signature : BOOLEAN,
            seat : {"expected", "other"}, phase : 1..2,
            session : {"current", "other"}, transcript : {"current", "other"},
            domain : {"v2", "other"}, canonical : BOOLEAN, exactLength : BOOLEAN]
Init == /\ packet \in Packets /\ expectedPhase \in 1..2 /\ accepted = FALSE
Accept ==
    /\ ~accepted
    /\ GuardIdentity => packet.key = "trusted"
    /\ GuardSignature => packet.signature
    /\ GuardSeat => packet.seat = "expected"
    /\ GuardPhase => packet.phase = expectedPhase
    /\ GuardSession => packet.session = "current"
    /\ GuardTranscript => (expectedPhase = 2 => packet.transcript = "current")
    /\ GuardDomain => packet.domain = "v2"
    /\ GuardCanonical => packet.canonical
    /\ GuardLength => packet.exactLength
    /\ accepted' = TRUE /\ UNCHANGED <<packet, expectedPhase>>
Next == Accept
Spec == Init /\ [][Next]_vars
TypeOK == /\ packet \in Packets /\ expectedPhase \in 1..2 /\ accepted \in BOOLEAN
INV_Identity == accepted => packet.key = "trusted"
INV_Signature == accepted => packet.signature
INV_Seat == accepted => packet.seat = "expected"
INV_Phase == accepted => packet.phase = expectedPhase
INV_Session == accepted => packet.session = "current"
INV_Transcript == (accepted /\ expectedPhase = 2) => packet.transcript = "current"
INV_Domain == accepted => packet.domain = "v2"
INV_Canonical == accepted => packet.canonical
INV_Length == accepted => packet.exactLength
COV_RoundOne == ~(accepted /\ expectedPhase = 1)
COV_RoundTwo == ~(accepted /\ expectedPhase = 2)
(* Round-one contexts have no round-two transcript to bind yet. *)
COV_RoundOneIgnoresTranscript == ~(accepted /\ expectedPhase = 1 /\ packet.transcript = "other")
=======================================================================
