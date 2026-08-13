------------------------------ MODULE BridgeEscrowV2 ------------------------------
(***************************************************************************
(* Bridge escrow core, stage 1.                                            *)
(*                                                                         *)
(* This bounded machine covers the normal-operation authorization, source  *)
(* truth/accountability, evidence, verdict, penalty, and typed-nullifier    *)
(* interface described in BRIDGE_V2_TEST_PLAN.md. Capacity arithmetic and  *)
(* generation lifecycle are a separate NOT-YET-RUN stage.                  *)
(*                                                                         *)
(* The central discipline is deliberate: objectiveSource is ghost history. *)
(* Except for the allowlisted TRUTH_IN_RELEASE_GUARD adequacy mutation, no  *)
(* request, artifact, submission, or release action may read it. Only the   *)
(* environment records or publishes truth in the baseline.                 *)
***************************************************************************)

EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS ProtocolVersion, Bug, ArtifactPublicationMode,
          EnabledDirections, EnabledReleaseSlots, EnabledSourceFactVariants,
          EnabledVariants, EnabledClaimIds

Versions == {"V1", "V2"}
Directions == {"ETH_TO_MOB", "MOB_TO_ETH"}
Events == {"ETH_DEPOSIT", "MOB_RETURN"}
ReleaseIds == {"F1", "F2", "R1", "R2"}
ClaimIds == {"C1", "C2"}
Epochs == 0..1
ReleaseSlots == 1..2

Unknown == "UNKNOWN"
Absent == "ABSENT"
Final == "FINAL"
ObjectiveStates == {Unknown, Absent, Final}

NoActor == "NO_ACTOR"
NoEpoch == -1
NoDigest == <<"NO_DIGEST">>
BadDigest == <<"BAD_DIGEST">>
NoManifest == <<"ROSTER_MANIFEST", "NONE", NoEpoch>>
BadManifest == <<"ROSTER_MANIFEST", "BAD", NoEpoch>>
NoBond == <<"BOND_MANIFEST", NoEpoch>>
BadBond == <<"BOND_MANIFEST", 99>>
NoKey == <<"NO_KEY", NoEpoch>>
NoEvidence == "NO_EVIDENCE"
NoRelease == "NO_RELEASE"
NoClaim == "NO_CLAIM"
NoProof == <<"NO_PROOF">>
NoVerdict == "NO_VERDICT"
NoVerdictId == <<"NO_VERDICT_ID">>
NoReason == "NO_REASON"
NoVariant == "NO_VARIANT"

OwnerSigners == {"o1", "o2"}
GateSigners == {"shared1", "g2", "g3"}
EthSigners == {"h1", "h2", "h3"}
WardenSigners == {"shared1", "w2", "w3", "w4"}
AccountSigners == {"shared1", "a2", "a3", "a5", "unbonded_account"}
Challengers == {"c1", "c2"}

Principals == OwnerSigners \cup GateSigners \cup EthSigners
              \cup WardenSigners \cup AccountSigners \cup Challengers

K_OWN == 2
K_FROST == 2
K_ETH == 2
K_WARDEN == 2
K_ACCOUNT == 2

OwnerRoster(e) == OwnerSigners
GateRoster(e) == IF e = 0 THEN {"shared1", "g2"} ELSE {"g2", "g3"}
EthRoster(e) == IF e = 0 THEN {"h1", "h2"} ELSE {"h2", "h3"}
WardenRoster(e) == IF e = 0 THEN {"shared1", "w2"} ELSE {"w3", "w4"}
AccountRoster(e) == IF e = 0 THEN {"shared1", "a2", "unbonded_account"}
                    ELSE {"a3", "a5", "unbonded_account"}
BondedAccountRoster(e) == IF e = 0 THEN {"shared1", "a2"} ELSE {"a3", "a5"}
BondedWardenRoster(e) == WardenRoster(e)

RoleNames == {"MLSAG", "FROST", "ETH_MULTI", "WARDEN", "ACCOUNT"}
SigTags == {"GOOD_SIG", "BAD_SIG", "NO_SIG"}
ArtifactKinds == RoleNames \cup {"NONE"}

ReleaseStatuses == {"EMPTY", "ASSERTED", "ASSEMBLED", "SUBMITTED",
                     "REJECTED", "LIABILITY_ADMITTED",
                     "AUTHORIZED_PENDING", "CAPACITY_APPROVED", "CANCELLED",
                     "FINALIZED"}
ClaimStatuses == {"EMPTY", "SUBMITTED", "ADMITTED", "REJECTED",
                   "VERDICTED", "APPLIED"}
ProofKinds == {"FALSE_SOURCE", "EQUIVOCATION"}
VerdictKinds == {NoVerdict, "OPERATOR", "CHALLENGER"}
RejectionReasons == {NoReason, "REJECT_MALFORMED",
                     "REJECT_UNAUTHENTICATED", "REJECT_EXPIRED",
                     "REJECT_UNBONDED_CHALLENGE", "REJECT_UNSUPPORTED",
                     "REJECT_INVALID_PROOF", "REJECT_DUPLICATE"}
EvidenceVariants == {"GOOD_EVIDENCE", "MALFORMED_EVIDENCE",
                     "UNAUTHENTICATED_EVIDENCE", "WRONG_EVIDENCE_DIGEST",
                     "EXPIRED_EVIDENCE", "UNBONDED_CHALLENGE",
                     "UNSUPPORTED_EVIDENCE"}

SourceFactVariants == {"MATCH", "ABSENT", "WRONG_AMOUNT",
                       "WRONG_RECIPIENT", "WRONG_CHAIN", "WRONG_POLICY",
                       "WRONG_ASSET", "WRONG_CHECKPOINT", "WRONG_EVENT",
                       "WRONG_DESTINATION_ASSET",
                       "WRONG_DESTINATION_AMOUNT"}

ArtifactVariants == {
    "GOOD",
    "FALSE_RELEASE_WITHOUT_ACCOUNTABILITY",
    "OMIT_MLSAG", "INVALID_MLSAG", "UNDER_THRESHOLD_OWNER",
    "OMIT_FROST", "INVALID_FROST", "UNDER_THRESHOLD_FROST",
    "OMIT_ETH_MULTISIG", "INVALID_ETH_MULTISIG", "UNDER_THRESHOLD_ETH",
    "OMIT_WARDEN_CERT", "UNDER_THRESHOLD_WARDEN",
    "OMIT_ACCOUNTABILITY_CERT", "UNDER_THRESHOLD_ACCOUNT",
    "WRONG_ROLE_SIGNER",
    "DUPLICATE_OWNER_SLOTS", "DUPLICATE_FROST_SLOTS",
    "DUPLICATE_ETH_SLOTS", "DUPLICATE_WARDEN_SLOTS",
    "DUPLICATE_ACCOUNT_SLOTS",
    "STALE_FROST_EPOCH", "STALE_ETH_EPOCH", "STALE_WARDEN_EPOCH",
    "STALE_ACCOUNT_EPOCH",
    "MLSAG_DIGEST_MISMATCH", "FROST_DIGEST_MISMATCH",
    "ETH_MULTISIG_DIGEST_MISMATCH", "WARDEN_DIGEST_MISMATCH",
    "ACCOUNT_DIGEST_MISMATCH", "WRONG_BOND_MANIFEST",
    "UNBONDED_ACCOUNT_SIGNER"
}

ArtifactPublicationModes == {"DEFER_TO_DESTINATION", "VALIDATE_ON_PUBLICATION"}
AdequacyBugs == {"TRUTH_IN_RELEASE_GUARD"}
ProofBugs == {"MISSING_AUTOPROOF_ETH", "MISSING_AUTOPROOF_MOB_V2"}
NullifierBugs == {"OMIT_NULLIFIER_CONSUMPTION", "POISON_NULLIFIER",
                  "REUSE_SOURCE_EVENT", "VERSIONED_NULLIFIER",
                  "RELEASE_WITHOUT_RESERVE"}
ClaimBugs == {"ARBITRARY_OPERATOR_VERDICT", "INNOCENT_CULPRIT",
              "SLASH_WITHOUT_VERDICT", "DOUBLE_APPLY_PROOF",
              "REJECTED_CLAIM_EFFECT", "UNSUPPORTED_AUTO_SLASH",
              "FALSE_CHALLENGE_PAUSES", "WRONG_CHALLENGER_SLASH"}
BugKinds == {"NONE"} \cup (ArtifactVariants \ {"GOOD"})
            \cup AdequacyBugs \cup ProofBugs \cup NullifierBugs
            \cup ClaimBugs

ASSUME
    /\ ProtocolVersion \in Versions
    /\ Bug \in BugKinds
    /\ ArtifactPublicationMode \in ArtifactPublicationModes
    /\ EnabledDirections \subseteq Directions
    /\ EnabledReleaseSlots \subseteq ReleaseSlots
    /\ EnabledSourceFactVariants \subseteq SourceFactVariants
    /\ EnabledVariants \subseteq ArtifactVariants
    /\ EnabledClaimIds \subseteq ClaimIds

VARIABLES
    currentEpoch,
    objectiveSource,
    publicCheckpoint,
    releaseStatus,
    requests,
    bundleVariant,
    bundleEpoch,
    bundles,
    acceptedAtEpoch,
    valueState,
    reservationOwner,
    nullifierLog,
    claims,
    claimSubmissionLog,
    proofReservations,
    proofConsumptionLog,
    slashEvents,
    consequenceEvents,
    freshGateDkgEvents,
    slashApplyCount,
    operatorBondState,
    capacityEventLog,
    paused,
    pauseCauses

DirectionOfRelease(r) == IF r \in {"F1", "F2"}
                         THEN "ETH_TO_MOB" ELSE "MOB_TO_ETH"
EventOfRelease(r) == IF DirectionOfRelease(r) = "ETH_TO_MOB"
                     THEN "ETH_DEPOSIT" ELSE "MOB_RETURN"
DirectionOfEvent(ev) == IF ev = "ETH_DEPOSIT"
                        THEN "ETH_TO_MOB" ELSE "MOB_TO_ETH"
ReleaseSlotOf(r) == IF r \in {"F1", "R1"} THEN 1 ELSE 2
EnabledReleases ==
    {r \in ReleaseIds :
       /\ DirectionOfRelease(r) \in EnabledDirections
       /\ ReleaseSlotOf(r) \in EnabledReleaseSlots}

SourceChain(ev) == IF ev = "ETH_DEPOSIT" THEN "ETHEREUM" ELSE "MOBILECOIN"
SourcePolicy(ev) == IF ev = "ETH_DEPOSIT" THEN "USDC_ESCROW"
                    ELSE "EUSD_RETURN_POLICY"
CheckpointOf(ev) == IF ev = "ETH_DEPOSIT" THEN "ETH_CHECKPOINT"
                    ELSE "MOB_CHECKPOINT"
SourceAsset(ev) == IF ev = "ETH_DEPOSIT" THEN "USDC" ELSE "EUSD"
DestinationAsset(r) == IF DirectionOfRelease(r) = "ETH_TO_MOB"
                       THEN "EUSD" ELSE "USDC"
RecipientOf(r) == <<"RECIPIENT", r>>
DestinationTxOf(r) == <<"DESTINATION_TX", r>>
ExpiryEpoch(e) == e
TombstoneOf(r, e) == <<"TOMBSTONE", r, e>>
ValuePositions == {"EUSD_POSITION_F1", "EUSD_POSITION_F2",
                    "USDC_POSITION_R1", "USDC_POSITION_R2"}
ValuePositionOf(r) ==
    CASE r = "F1" -> "EUSD_POSITION_F1"
      [] r = "F2" -> "EUSD_POSITION_F2"
      [] r = "R1" -> "USDC_POSITION_R1"
      [] OTHER -> "USDC_POSITION_R2"

(* Deliberately excludes version, epoch, attempt, destination, and release id. *)
StableSourceKey(r) ==
    <<"BRIDGE_SOURCE_EVENT_V1", "BRIDGE_1", DirectionOfRelease(r),
      SourceChain(EventOfRelease(r)), SourcePolicy(EventOfRelease(r)),
      EventOfRelease(r)>>

ImplementationSourceKey(r) ==
    IF Bug = "VERSIONED_NULLIFIER"
    THEN <<StableSourceKey(r), ProtocolVersion>>
    ELSE StableSourceKey(r)

OwnerKey == <<"OWNER_KEY", 0>>
GateKey(e) == <<"GATE_KEY", e>>
EthEscrowContract == <<"ETH_ESCROW_CONTRACT", 0>>
PolicyId == "BRIDGE_POLICY_1"
GenerationId == "GENERATION_0"

RosterManifest(role, e) == <<"ROSTER_MANIFEST", role, e>>
BondManifest(e) == <<"BOND_MANIFEST", e>>
OperatorPrincipals == WardenSigners \cup AccountSigners
BondedOperatorPrincipals == WardenSigners \cup BondedAccountRoster(0)
                            \cup BondedAccountRoster(1)
OperatorBondIds ==
    {<<"OPERATOR_BOND", a, e>> : a \in OperatorPrincipals, e \in Epochs}
OperatorBondId(a, e) == <<"OPERATOR_BOND", a, e>>
ChallengeBondId(c) == <<"CHALLENGE_BOND", c>>

ExpectedDigest(r, e) ==
    <<"BRIDGE_DIGEST_V2", "SCHEMA_1", "BRIDGE_1", ProtocolVersion,
      DirectionOfRelease(r), SourceChain(EventOfRelease(r)),
      SourcePolicy(EventOfRelease(r)), EventOfRelease(r),
      CheckpointOf(EventOfRelease(r)), Final,
      SourceAsset(EventOfRelease(r)), 1, DestinationAsset(r), 1,
      RecipientOf(r), StableSourceKey(r), r, DestinationTxOf(r),
      ExpiryEpoch(e), TombstoneOf(r, e),
      PolicyId, e, OwnerKey, GateKey(e), EthEscrowContract,
      RosterManifest("MLSAG", e), RosterManifest("FROST", e),
      RosterManifest("ETH_MULTI", e), RosterManifest("WARDEN", e),
      RosterManifest("ACCOUNT", e), BondManifest(e)>>

CanonicalRequest(r, e) ==
    [ bridgeId |-> "BRIDGE_1",
      direction |-> DirectionOfRelease(r),
      sourceChain |-> SourceChain(EventOfRelease(r)),
      sourcePolicy |-> SourcePolicy(EventOfRelease(r)),
      sourceEvent |-> EventOfRelease(r),
      sourceCheckpoint |-> CheckpointOf(EventOfRelease(r)),
      claimedState |-> Final,
      sourceAsset |-> SourceAsset(EventOfRelease(r)),
      sourceAmount |-> 1,
      destinationAsset |-> DestinationAsset(r),
      destinationAmount |-> 1,
      recipient |-> RecipientOf(r),
      version |-> ProtocolVersion,
      policyId |-> PolicyId,
      policyEpoch |-> e,
      destinationTx |-> DestinationTxOf(r),
      expiryEpoch |-> ExpiryEpoch(e),
      tombstone |-> TombstoneOf(r, e),
      sourceKey |-> ImplementationSourceKey(r),
      digest |-> ExpectedDigest(r, e) ]

CanonicalRequestWithStableKey(r, e) ==
    [CanonicalRequest(r, e) EXCEPT !.sourceKey = StableSourceKey(r)]

NoRequest ==
    [ bridgeId |-> "NO_BRIDGE",
      direction |-> "NO_DIRECTION",
      sourceChain |-> "NO_CHAIN",
      sourcePolicy |-> "NO_POLICY",
      sourceEvent |-> "NO_EVENT",
      sourceCheckpoint |-> "NO_CHECKPOINT",
      claimedState |-> Unknown,
      sourceAsset |-> "NO_ASSET",
      sourceAmount |-> 0,
      destinationAsset |-> "NO_ASSET",
      destinationAmount |-> 0,
      recipient |-> <<"NO_RECIPIENT">>,
      version |-> "NO_VERSION",
      policyId |-> "NO_POLICY",
      policyEpoch |-> NoEpoch,
      destinationTx |-> <<"NO_DESTINATION_TX">>,
      expiryEpoch |-> NoEpoch,
      tombstone |-> <<"NO_TOMBSTONE">>,
      sourceKey |-> <<"NO_SOURCE_KEY">>,
      digest |-> NoDigest ]

RequestTypeOK(q) ==
    \/ q = NoRequest
    \/ /\ q.bridgeId = "BRIDGE_1"
       /\ q.direction \in Directions
       /\ q.sourceChain \in {"ETHEREUM", "MOBILECOIN"}
       /\ q.sourcePolicy \in {"USDC_ESCROW", "EUSD_RETURN_POLICY"}
       /\ q.sourceEvent \in Events
       /\ q.sourceCheckpoint \in {"ETH_CHECKPOINT", "MOB_CHECKPOINT"}
       /\ q.claimedState = Final
       /\ q.sourceAsset \in {"USDC", "EUSD"}
       /\ q.sourceAmount = 1
       /\ q.destinationAsset \in {"USDC", "EUSD"}
       /\ q.destinationAmount = 1
       /\ q.recipient \in {RecipientOf(r) : r \in ReleaseIds}
       /\ q.version \in Versions
       /\ q.policyId = PolicyId
       /\ q.policyEpoch \in Epochs
       /\ q.destinationTx \in {DestinationTxOf(r) : r \in ReleaseIds}
       /\ q.expiryEpoch \in Epochs
       /\ q.tombstone \in {TombstoneOf(r, e) : r \in ReleaseIds, e \in Epochs}
       /\ q.sourceKey \in
            {StableSourceKey(r) : r \in ReleaseIds}
            \cup {<<StableSourceKey(r), v>> : r \in ReleaseIds, v \in Versions}
       /\ q.digest \in {ExpectedDigest(r, e) : r \in ReleaseIds, e \in Epochs}

CanonicalReleaseForEvent(ev) == IF ev = "ETH_DEPOSIT" THEN "F1" ELSE "R1"

SourceFact(presentVariant, exists, finality, chain, policy, eventLocator,
           checkpoint, sourceAsset, sourceAmount, destinationAsset,
           destinationAmount, recipient) ==
    [variant |-> presentVariant, exists |-> exists, finality |-> finality,
     sourceChain |-> chain, sourcePolicy |-> policy,
     sourceEvent |-> eventLocator, sourceCheckpoint |-> checkpoint,
     sourceAsset |-> sourceAsset, sourceAmount |-> sourceAmount,
     destinationAsset |-> destinationAsset,
     destinationAmount |-> destinationAmount, recipient |-> recipient]

UnknownSourceFact ==
    SourceFact("UNKNOWN_FACT", FALSE, Unknown, "NO_CHAIN", "NO_POLICY",
               "NO_EVENT", "NO_CHECKPOINT", "NO_ASSET", 0, "NO_ASSET", 0,
               <<"NO_RECIPIENT">>)

CanonicalObjectiveFact(ev) ==
    LET r == CanonicalReleaseForEvent(ev) IN
      SourceFact("MATCH", TRUE, Final, SourceChain(ev), SourcePolicy(ev), ev,
                 CheckpointOf(ev), SourceAsset(ev), 1, DestinationAsset(r), 1,
                 RecipientOf(r))

ObjectiveFactFor(ev, variant) ==
    LET base == CanonicalObjectiveFact(ev) IN
      CASE variant = "MATCH" -> base
        [] variant = "ABSENT"
             -> [base EXCEPT !.variant = variant, !.exists = FALSE,
                              !.finality = Absent]
        [] variant = "WRONG_AMOUNT"
             -> [base EXCEPT !.variant = variant, !.sourceAmount = 2]
        [] variant = "WRONG_RECIPIENT"
             -> [base EXCEPT !.variant = variant,
                              !.recipient = <<"WRONG_RECIPIENT", ev>>]
        [] variant = "WRONG_CHAIN"
             -> [base EXCEPT !.variant = variant,
                              !.sourceChain = "WRONG_CHAIN"]
        [] variant = "WRONG_POLICY"
             -> [base EXCEPT !.variant = variant,
                              !.sourcePolicy = "WRONG_POLICY"]
        [] variant = "WRONG_ASSET"
             -> [base EXCEPT !.variant = variant,
                              !.sourceAsset = "WRONG_ASSET"]
        [] variant = "WRONG_CHECKPOINT"
             -> [base EXCEPT !.variant = variant,
                              !.sourceCheckpoint = "WRONG_CHECKPOINT"]
        [] variant = "WRONG_EVENT"
             -> [base EXCEPT !.variant = variant,
                              !.sourceEvent =
                                  IF ev = "ETH_DEPOSIT" THEN "MOB_RETURN"
                                  ELSE "ETH_DEPOSIT"]
        [] variant = "WRONG_DESTINATION_ASSET"
             -> [base EXCEPT !.variant = variant,
                              !.destinationAsset = "WRONG_ASSET"]
        [] OTHER
             -> [base EXCEPT !.variant = variant,
                              !.destinationAmount = 2]

SourceFactPayload(f) ==
    [exists |-> f.exists, finality |-> f.finality,
     sourceChain |-> f.sourceChain, sourcePolicy |-> f.sourcePolicy,
     sourceEvent |-> f.sourceEvent, sourceCheckpoint |-> f.sourceCheckpoint,
     sourceAsset |-> f.sourceAsset, sourceAmount |-> f.sourceAmount,
     destinationAsset |-> f.destinationAsset,
     destinationAmount |-> f.destinationAmount, recipient |-> f.recipient]

ClaimedSourceFacts(r) ==
    [exists |-> TRUE, finality |-> requests[r].claimedState,
     sourceChain |-> requests[r].sourceChain,
     sourcePolicy |-> requests[r].sourcePolicy,
     sourceEvent |-> requests[r].sourceEvent,
     sourceCheckpoint |-> requests[r].sourceCheckpoint,
     sourceAsset |-> requests[r].sourceAsset,
     sourceAmount |-> requests[r].sourceAmount,
     destinationAsset |-> requests[r].destinationAsset,
     destinationAmount |-> requests[r].destinationAmount,
     recipient |-> requests[r].recipient]

SourceFactTypeOK(f) ==
    /\ f.variant \in SourceFactVariants \cup {"UNKNOWN_FACT"}
    /\ f.exists \in BOOLEAN
    /\ f.finality \in ObjectiveStates
    /\ f.sourceChain \in {"ETHEREUM", "MOBILECOIN", "WRONG_CHAIN", "NO_CHAIN"}
    /\ f.sourcePolicy \in {"USDC_ESCROW", "EUSD_RETURN_POLICY",
                            "WRONG_POLICY", "NO_POLICY"}
    /\ f.sourceEvent \in Events \cup {"NO_EVENT"}
    /\ f.sourceCheckpoint \in {"ETH_CHECKPOINT", "MOB_CHECKPOINT",
                                "WRONG_CHECKPOINT", "NO_CHECKPOINT"}
    /\ f.sourceAsset \in {"USDC", "EUSD", "WRONG_ASSET", "NO_ASSET"}
    /\ f.sourceAmount \in 0..2
    /\ f.destinationAsset \in {"USDC", "EUSD", "WRONG_ASSET", "NO_ASSET"}
    /\ f.destinationAmount \in 0..2
    /\ f.recipient \in {RecipientOf(r) : r \in ReleaseIds}
                       \cup {<<"WRONG_RECIPIENT", ev>> : ev \in Events}
                       \cup {<<"NO_RECIPIENT">>}

NoCheckpoint ==
    [present |-> FALSE, auth |-> "NO_SIG", direction |-> "NO_DIRECTION",
     sourceEvent |-> "NO_EVENT", checkpointId |-> "NO_CHECKPOINT",
     proofKind |-> "NO_CHECKPOINT_PROOF", fact |-> UnknownSourceFact]

AuthenticatedCheckpoint(ev, fact) ==
    [present |-> TRUE, auth |-> "GOOD_SIG",
     direction |-> DirectionOfEvent(ev), sourceEvent |-> ev,
     checkpointId |-> CheckpointOf(ev),
     proofKind |-> IF fact.exists THEN "AUTHENTICATED_INCLUSION"
                   ELSE "AUTHENTICATED_MAP_NON_INCLUSION",
     fact |-> fact]

CheckpointTypeOK(cp) ==
    /\ cp.present \in BOOLEAN
    /\ cp.auth \in SigTags
    /\ cp.direction \in Directions \cup {"NO_DIRECTION"}
    /\ cp.sourceEvent \in Events \cup {"NO_EVENT"}
    /\ cp.checkpointId \in {"ETH_CHECKPOINT", "MOB_CHECKPOINT", "NO_CHECKPOINT"}
    /\ cp.proofKind \in {"NO_CHECKPOINT_PROOF", "AUTHENTICATED_INCLUSION",
                          "AUTHENTICATED_MAP_NON_INCLUSION"}
    /\ SourceFactTypeOK(cp.fact)

OtherEpoch(e) == IF e = 0 THEN 1 ELSE 0

GoodSlots(role, e) ==
    CASE role = "MLSAG"    -> <<"o1", "o2">>
      [] role = "FROST"    -> IF e = 0 THEN <<"shared1", "g2">> ELSE <<"g2", "g3">>
      [] role = "ETH_MULTI"-> IF e = 0 THEN <<"h1", "h2">> ELSE <<"h2", "h3">>
      [] role = "WARDEN"   -> IF e = 0 THEN <<"shared1", "w2">> ELSE <<"w3", "w4">>
      [] role = "ACCOUNT"  -> IF e = 0 THEN <<"shared1", "a2">> ELSE <<"a3", "a5">>

RoleRoster(role, e) ==
    CASE role = "MLSAG"     -> OwnerRoster(e)
      [] role = "FROST"     -> GateRoster(e)
      [] role = "ETH_MULTI" -> EthRoster(e)
      [] role = "WARDEN"    -> WardenRoster(e)
      [] role = "ACCOUNT"   -> AccountRoster(e)

RoleThreshold(role) ==
    CASE role = "MLSAG"     -> K_OWN
      [] role = "FROST"     -> K_FROST
      [] role = "ETH_MULTI" -> K_ETH
      [] role = "WARDEN"    -> K_WARDEN
      [] role = "ACCOUNT"   -> K_ACCOUNT

RoleKey(role, e) ==
    CASE role = "MLSAG"     -> OwnerKey
      [] role = "FROST"     -> GateKey(e)
      [] role = "ETH_MULTI" -> EthEscrowContract
      [] OTHER               -> NoKey

RoleBond(role, e) ==
    IF role \in {"WARDEN", "ACCOUNT"} THEN BondManifest(e) ELSE NoBond

Artifact(role, sig, e, digest, manifest, bond, key, slots) ==
    [ present |-> TRUE, kind |-> role, sig |-> sig, epoch |-> e,
      digest |-> digest, rosterManifest |-> manifest,
      bondManifest |-> bond, keyRef |-> key, slots |-> slots ]

NoArtifact ==
    [ present |-> FALSE, kind |-> "NONE", sig |-> "NO_SIG",
      epoch |-> NoEpoch, digest |-> NoDigest,
      rosterManifest |-> NoManifest, bondManifest |-> NoBond,
      keyRef |-> NoKey, slots |-> <<NoActor, NoActor>> ]

NoBundle ==
    [mlsag |-> NoArtifact, frost |-> NoArtifact, ethMulti |-> NoArtifact,
     warden |-> NoArtifact, account |-> NoArtifact]

GoodArtifact(role, r, e) ==
    Artifact(role, "GOOD_SIG", e, ExpectedDigest(r, e),
             RosterManifest(role, e), RoleBond(role, e),
             RoleKey(role, e), GoodSlots(role, e))

BadSignatureArtifact(role, r, e) ==
    Artifact(role, "BAD_SIG", e, ExpectedDigest(r, e),
             RosterManifest(role, e), RoleBond(role, e),
             RoleKey(role, e), GoodSlots(role, e))

UnderThresholdArtifact(role, r, e) ==
    Artifact(role, "GOOD_SIG", e, ExpectedDigest(r, e),
             RosterManifest(role, e), RoleBond(role, e),
             RoleKey(role, e), <<GoodSlots(role, e)[1], NoActor>>)

DuplicateArtifact(role, r, e) ==
    Artifact(role, "GOOD_SIG", e, ExpectedDigest(r, e),
             RosterManifest(role, e), RoleBond(role, e),
             RoleKey(role, e), <<GoodSlots(role, e)[1], GoodSlots(role, e)[1]>>)

StaleArtifact(role, r, e) ==
    LET old == OtherEpoch(e) IN
      Artifact(role, "GOOD_SIG", old, ExpectedDigest(r, e),
               RosterManifest(role, old), RoleBond(role, old),
               RoleKey(role, old), GoodSlots(role, old))

BadDigestArtifact(role, r, e) ==
    Artifact(role, "GOOD_SIG", e, BadDigest,
             RosterManifest(role, e), RoleBond(role, e),
             RoleKey(role, e), GoodSlots(role, e))

WrongRoleArtifact(role, r, e) ==
    Artifact(role, "GOOD_SIG", e, ExpectedDigest(r, e),
             RosterManifest(role, e), RoleBond(role, e),
             RoleKey(role, e), GoodSlots("WARDEN", e))

WrongBondArtifact(r, e) ==
    Artifact("ACCOUNT", "GOOD_SIG", e, ExpectedDigest(r, e),
             RosterManifest("ACCOUNT", e), BadBond, NoKey,
             GoodSlots("ACCOUNT", e))

UnbondedAccountArtifact(r, e) ==
    Artifact("ACCOUNT", "GOOD_SIG", e, ExpectedDigest(r, e),
             RosterManifest("ACCOUNT", e), BondManifest(e), NoKey,
             <<GoodSlots("ACCOUNT", e)[1], "unbonded_account">>)

GoodBundle(r, e) ==
    IF DirectionOfRelease(r) = "ETH_TO_MOB"
    THEN [mlsag |-> GoodArtifact("MLSAG", r, e),
          frost |-> GoodArtifact("FROST", r, e),
          ethMulti |-> NoArtifact,
          warden |-> GoodArtifact("WARDEN", r, e),
          account |-> GoodArtifact("ACCOUNT", r, e)]
    ELSE [mlsag |-> NoArtifact,
          frost |-> NoArtifact,
          ethMulti |-> GoodArtifact("ETH_MULTI", r, e),
          warden |-> GoodArtifact("WARDEN", r, e),
          account |-> GoodArtifact("ACCOUNT", r, e)]

BundleFor(r, e, variant) ==
    CASE variant = "GOOD" -> GoodBundle(r, e)
      [] variant \in {"FALSE_RELEASE_WITHOUT_ACCOUNTABILITY",
                       "OMIT_ACCOUNTABILITY_CERT"}
           -> [GoodBundle(r, e) EXCEPT !.account = NoArtifact]
      [] variant = "OMIT_MLSAG"
           -> [GoodBundle(r, e) EXCEPT !.mlsag = NoArtifact]
      [] variant = "INVALID_MLSAG"
           -> [GoodBundle(r, e) EXCEPT !.mlsag = BadSignatureArtifact("MLSAG", r, e)]
      [] variant = "UNDER_THRESHOLD_OWNER"
           -> [GoodBundle(r, e) EXCEPT !.mlsag = UnderThresholdArtifact("MLSAG", r, e)]
      [] variant = "OMIT_FROST"
           -> [GoodBundle(r, e) EXCEPT !.frost = NoArtifact]
      [] variant = "INVALID_FROST"
           -> [GoodBundle(r, e) EXCEPT !.frost = BadSignatureArtifact("FROST", r, e)]
      [] variant = "UNDER_THRESHOLD_FROST"
           -> [GoodBundle(r, e) EXCEPT !.frost = UnderThresholdArtifact("FROST", r, e)]
      [] variant = "OMIT_ETH_MULTISIG"
           -> [GoodBundle(r, e) EXCEPT !.ethMulti = NoArtifact]
      [] variant = "INVALID_ETH_MULTISIG"
           -> [GoodBundle(r, e) EXCEPT !.ethMulti = BadSignatureArtifact("ETH_MULTI", r, e)]
      [] variant = "UNDER_THRESHOLD_ETH"
           -> [GoodBundle(r, e) EXCEPT !.ethMulti = UnderThresholdArtifact("ETH_MULTI", r, e)]
      [] variant = "OMIT_WARDEN_CERT"
           -> [GoodBundle(r, e) EXCEPT !.warden = NoArtifact]
      [] variant = "UNDER_THRESHOLD_WARDEN"
           -> [GoodBundle(r, e) EXCEPT !.warden = UnderThresholdArtifact("WARDEN", r, e)]
      [] variant = "UNDER_THRESHOLD_ACCOUNT"
           -> [GoodBundle(r, e) EXCEPT !.account = UnderThresholdArtifact("ACCOUNT", r, e)]
      [] variant = "WRONG_ROLE_SIGNER"
           -> [GoodBundle(r, e) EXCEPT !.account = WrongRoleArtifact("ACCOUNT", r, e)]
      [] variant = "DUPLICATE_OWNER_SLOTS"
           -> [GoodBundle(r, e) EXCEPT !.mlsag = DuplicateArtifact("MLSAG", r, e)]
      [] variant = "DUPLICATE_FROST_SLOTS"
           -> [GoodBundle(r, e) EXCEPT !.frost = DuplicateArtifact("FROST", r, e)]
      [] variant = "DUPLICATE_ETH_SLOTS"
           -> [GoodBundle(r, e) EXCEPT !.ethMulti = DuplicateArtifact("ETH_MULTI", r, e)]
      [] variant = "DUPLICATE_WARDEN_SLOTS"
           -> [GoodBundle(r, e) EXCEPT !.warden = DuplicateArtifact("WARDEN", r, e)]
      [] variant = "DUPLICATE_ACCOUNT_SLOTS"
           -> [GoodBundle(r, e) EXCEPT !.account = DuplicateArtifact("ACCOUNT", r, e)]
      [] variant = "STALE_FROST_EPOCH"
           -> [GoodBundle(r, e) EXCEPT !.frost = StaleArtifact("FROST", r, e)]
      [] variant = "STALE_ETH_EPOCH"
           -> [GoodBundle(r, e) EXCEPT !.ethMulti = StaleArtifact("ETH_MULTI", r, e)]
      [] variant = "STALE_WARDEN_EPOCH"
           -> [GoodBundle(r, e) EXCEPT !.warden = StaleArtifact("WARDEN", r, e)]
      [] variant = "STALE_ACCOUNT_EPOCH"
           -> [GoodBundle(r, e) EXCEPT !.account = StaleArtifact("ACCOUNT", r, e)]
      [] variant = "MLSAG_DIGEST_MISMATCH"
           -> [GoodBundle(r, e) EXCEPT !.mlsag = BadDigestArtifact("MLSAG", r, e)]
      [] variant = "FROST_DIGEST_MISMATCH"
           -> [GoodBundle(r, e) EXCEPT !.frost = BadDigestArtifact("FROST", r, e)]
      [] variant = "ETH_MULTISIG_DIGEST_MISMATCH"
           -> [GoodBundle(r, e) EXCEPT !.ethMulti = BadDigestArtifact("ETH_MULTI", r, e)]
      [] variant = "WARDEN_DIGEST_MISMATCH"
           -> [GoodBundle(r, e) EXCEPT !.warden = BadDigestArtifact("WARDEN", r, e)]
      [] variant = "ACCOUNT_DIGEST_MISMATCH"
           -> [GoodBundle(r, e) EXCEPT !.account = BadDigestArtifact("ACCOUNT", r, e)]
      [] variant = "WRONG_BOND_MANIFEST"
           -> [GoodBundle(r, e) EXCEPT !.account = WrongBondArtifact(r, e)]
      [] variant = "UNBONDED_ACCOUNT_SIGNER"
           -> [GoodBundle(r, e) EXCEPT !.account = UnbondedAccountArtifact(r, e)]
      [] OTHER -> GoodBundle(r, e)

ArtifactTypeOK(a) ==
    /\ a.present \in BOOLEAN
    /\ a.kind \in ArtifactKinds
    /\ a.sig \in SigTags
    /\ (a.epoch = NoEpoch \/ a.epoch \in Epochs)
    /\ a.digest \in {NoDigest, BadDigest}
                    \cup {ExpectedDigest(r, e) : r \in ReleaseIds, e \in Epochs}
    /\ a.rosterManifest \in {NoManifest, BadManifest}
                            \cup {RosterManifest(role, e) :
                                   role \in RoleNames, e \in Epochs}
    /\ a.bondManifest \in {NoBond, BadBond}
                          \cup {BondManifest(e) : e \in Epochs}
    /\ a.keyRef \in {NoKey, OwnerKey, EthEscrowContract}
                     \cup {GateKey(e) : e \in Epochs}
    /\ a.slots \in [1..2 -> Principals \cup {NoActor}]

SlotSet(a) == {a.slots[i] : i \in 1..2}

ValidSlots(a, role, e) ==
    /\ NoActor \notin SlotSet(a)
    /\ SlotSet(a) \subseteq RoleRoster(role, e)
    /\ Cardinality(SlotSet(a)) >= RoleThreshold(role)

ValidArtifact(a, role, r, e) ==
    /\ a.present
    /\ a.kind = role
    /\ a.sig = "GOOD_SIG"
    /\ a.epoch = e
    /\ a.digest = ExpectedDigest(r, e)
    /\ a.rosterManifest = RosterManifest(role, e)
    /\ a.bondManifest = RoleBond(role, e)
    /\ a.keyRef = RoleKey(role, e)
    /\ ValidSlots(a, role, e)
    /\ (role # "WARDEN" \/ SlotSet(a) \subseteq BondedWardenRoster(e))
    /\ (role # "ACCOUNT" \/ SlotSet(a) \subseteq BondedAccountRoster(e))

ExpelledActors ==
    {a \in Principals :
       \E consequence \in consequenceEvents :
         /\ consequence.verdict = "OPERATOR"
         /\ a \in consequence.expelled}

AdmissionValidArtifact(a, role, r, e) ==
    /\ ValidArtifact(a, role, r, e)
    /\ SlotSet(a) \cap ExpelledActors = {}
    /\ IF role \in {"WARDEN", "ACCOUNT"}
          THEN \A signer \in SlotSet(a) :
                 operatorBondState[OperatorBondId(signer, e)] = "LOCKED"
          ELSE TRUE

IsAbsentArtifact(a) == a = NoArtifact

CorrectDirectionBundle(r, b, e) ==
    IF DirectionOfRelease(r) = "ETH_TO_MOB"
    THEN /\ ValidArtifact(b.mlsag, "MLSAG", r, e)
         /\ ValidArtifact(b.frost, "FROST", r, e)
         /\ IsAbsentArtifact(b.ethMulti)
         /\ ValidArtifact(b.warden, "WARDEN", r, e)
         /\ ValidArtifact(b.account, "ACCOUNT", r, e)
    ELSE /\ IsAbsentArtifact(b.mlsag)
         /\ IsAbsentArtifact(b.frost)
         /\ ValidArtifact(b.ethMulti, "ETH_MULTI", r, e)
         /\ ValidArtifact(b.warden, "WARDEN", r, e)
         /\ ValidArtifact(b.account, "ACCOUNT", r, e)

AdmissionDirectionBundle(r, b, e) ==
    IF DirectionOfRelease(r) = "ETH_TO_MOB"
    THEN /\ AdmissionValidArtifact(b.mlsag, "MLSAG", r, e)
         /\ AdmissionValidArtifact(b.frost, "FROST", r, e)
         /\ IsAbsentArtifact(b.ethMulti)
         /\ AdmissionValidArtifact(b.warden, "WARDEN", r, e)
         /\ AdmissionValidArtifact(b.account, "ACCOUNT", r, e)
    ELSE /\ IsAbsentArtifact(b.mlsag)
         /\ IsAbsentArtifact(b.frost)
         /\ AdmissionValidArtifact(b.ethMulti, "ETH_MULTI", r, e)
         /\ AdmissionValidArtifact(b.warden, "WARDEN", r, e)
         /\ AdmissionValidArtifact(b.account, "ACCOUNT", r, e)

ArtifactBugSelected(r) ==
    /\ Bug \in (ArtifactVariants \ {"GOOD"})
    /\ bundleVariant[r] = Bug

ImplementationBundleValid(r) ==
    AdmissionDirectionBundle(r, bundles[r], bundleEpoch[r])
    \/ ArtifactBugSelected(r)

RequiredArtifactsPresent(r) ==
    LET b == bundles[r] IN
      IF DirectionOfRelease(r) = "ETH_TO_MOB"
      THEN /\ b.mlsag.present /\ b.frost.present
           /\ b.warden.present /\ b.account.present
      ELSE /\ b.ethMulti.present /\ b.warden.present /\ b.account.present

RequiredArtifacts(r) ==
    IF DirectionOfRelease(r) = "ETH_TO_MOB"
    THEN {bundles[r].mlsag, bundles[r].frost,
          bundles[r].warden, bundles[r].account}
    ELSE {bundles[r].ethMulti, bundles[r].warden, bundles[r].account}

FinalizedReleaseIds == {r \in EnabledReleases : releaseStatus[r] = "FINALIZED"}

SourceKey(r) == requests[r].sourceKey
NullifierKeys == {n.key : n \in nullifierLog}
ExpectedNullifierLog ==
    {[release |-> r, key |-> StableSourceKey(r)] : r \in FinalizedReleaseIds}

WardenApprovers(r) == SlotSet(bundles[r].warden)
AccountabilityApprovers(r) == SlotSet(bundles[r].account)
LiableApprovalSigners(r) == WardenApprovers(r) \cup AccountabilityApprovers(r)
AccountableSigners(r) == LiableApprovalSigners(r)
EquivocationLiableSigners(r1, r2) ==
    (WardenApprovers(r1) \cap WardenApprovers(r2))
    \cup (AccountabilityApprovers(r1) \cap AccountabilityApprovers(r2))

ObjectiveKnown(r) ==
    objectiveSource[EventOfRelease(r)].variant # "UNKNOWN_FACT"
GroundTruthFault(r) ==
    /\ r \in FinalizedReleaseIds
    /\ ObjectiveKnown(r)
    /\ SourceFactPayload(objectiveSource[EventOfRelease(r)]) #
         ClaimedSourceFacts(r)

AutoVerifiable(version, direction, kind) ==
    \/ kind = "EQUIVOCATION"
    \/ /\ kind = "FALSE_SOURCE"
       /\ \/ direction = "ETH_TO_MOB"
          \/ /\ direction = "MOB_TO_ETH" /\ version = "V2"

CheckpointPublicationEnabled(ev) ==
    /\ AutoVerifiable(ProtocolVersion, DirectionOfEvent(ev), "FALSE_SOURCE")
    /\ ~(Bug = "MISSING_AUTOPROOF_ETH" /\ ev = "ETH_DEPOSIT")
    /\ ~(Bug = "MISSING_AUTOPROOF_MOB_V2" /\ ev = "MOB_RETURN")

ChallengerFor(c) == IF c = "C1" THEN "c1" ELSE "c2"
ProofId(kind, target, related) == <<"PROOF", kind, target, related>>
EvidenceDigest(c, challenger, target, kind, related, checkpoint, expiresAt,
               challengeBond) ==
    <<"EVIDENCE", c, challenger, target, kind, related, checkpoint, expiresAt,
      challengeBond,
      IF target \in ReleaseIds THEN requests[target].digest ELSE NoDigest>>

Evidence(present, auth, target, kind, related, checkpoint, digest, proofId,
         expiresAt, challengeBond, challengeBondLocked) ==
    [present |-> present, auth |-> auth, target |-> target, kind |-> kind,
     related |-> related, checkpoint |-> checkpoint, digest |-> digest,
     proofId |-> proofId, expiresAt |-> expiresAt,
     challengeBond |-> challengeBond,
     challengeBondLocked |-> challengeBondLocked]

EvidenceFor(c, target, kind, variant) ==
    LET challenger == ChallengerFor(c) IN
    LET related == IF kind = "EQUIVOCATION"
                   THEN IF target = "F1" THEN "F2"
                        ELSE IF target = "F2" THEN "F1"
                        ELSE IF target = "R1" THEN "R2" ELSE "R1"
                   ELSE NoRelease IN
    LET cp == publicCheckpoint[EventOfRelease(target)] IN
    LET pid == ProofId(kind, target, related) IN
    LET expiry == 1 IN
    LET bond == ChallengeBondId(c) IN
    CASE variant = "GOOD_EVIDENCE"
           -> Evidence(TRUE, "GOOD_SIG", target, kind, related, cp,
                       EvidenceDigest(c, challenger, target, kind, related,
                                      cp, expiry, bond), pid, expiry, bond, TRUE)
      [] variant = "UNAUTHENTICATED_EVIDENCE"
           -> Evidence(TRUE, "BAD_SIG", target, kind, related, cp,
                       EvidenceDigest(c, challenger, target, kind, related,
                                      cp, expiry, bond), pid, expiry, bond, TRUE)
      [] variant = "WRONG_EVIDENCE_DIGEST"
           -> Evidence(TRUE, "GOOD_SIG", target, kind, related, cp,
                       BadDigest, pid, expiry, bond, TRUE)
      [] variant = "EXPIRED_EVIDENCE"
           -> Evidence(TRUE, "GOOD_SIG", target, kind, related, cp,
                       EvidenceDigest(c, challenger, target, kind, related,
                                      cp, NoEpoch, bond), pid, NoEpoch, bond, TRUE)
      [] variant = "UNBONDED_CHALLENGE"
           -> Evidence(TRUE, "GOOD_SIG", target, kind, related, cp,
                       EvidenceDigest(c, challenger, target, kind, related,
                                      cp, expiry, bond), pid, expiry, bond, FALSE)
      [] variant = "UNSUPPORTED_EVIDENCE"
           -> Evidence(TRUE, "GOOD_SIG", target, "FALSE_SOURCE", related, cp,
                       EvidenceDigest(c, challenger, target, "FALSE_SOURCE",
                                      related, cp, expiry, bond),
                       ProofId("FALSE_SOURCE", target, related), expiry,
                       bond, TRUE)
      [] OTHER
           -> Evidence(FALSE, "NO_SIG", NoRelease, "FALSE_SOURCE", NoRelease,
                       NoCheckpoint, NoDigest, NoProof, NoEpoch,
                       <<"NO_CHALLENGE_BOND">>, FALSE)

NoEvidenceRecord ==
    Evidence(FALSE, "NO_SIG", NoRelease, "FALSE_SOURCE", NoRelease,
             NoCheckpoint, NoDigest, NoProof, NoEpoch,
             <<"NO_CHALLENGE_BOND">>, FALSE)

EvidenceTypeOK(ev) ==
    /\ ev.present \in BOOLEAN
    /\ ev.auth \in SigTags
    /\ ev.target \in ReleaseIds \cup {NoRelease}
    /\ ev.kind \in ProofKinds
    /\ ev.related \in ReleaseIds \cup {NoRelease}
    /\ CheckpointTypeOK(ev.checkpoint)
    /\ ev.digest \in {NoDigest, BadDigest}
                    \cup {EvidenceDigest(c, ch, target, kind, related, cp, exp,
                                          bond) :
                           c \in ClaimIds, ch \in Challengers,
                           target \in ReleaseIds, kind \in ProofKinds,
                           related \in ReleaseIds \cup {NoRelease},
                           cp \in {NoCheckpoint}
                                 \cup {publicCheckpoint[e] : e \in Events},
                           exp \in Epochs \cup {NoEpoch},
                           bond \in {ChallengeBondId(d) : d \in ClaimIds}}
    /\ ev.proofId \in {NoProof}
                     \cup {ProofId(k, t, rel) : k \in ProofKinds,
                            t \in ReleaseIds, rel \in ReleaseIds \cup {NoRelease}}
    /\ ev.expiresAt \in Epochs \cup {NoEpoch}
    /\ ev.challengeBond \in {<<"NO_CHALLENGE_BOND">>}
                            \cup {ChallengeBondId(c) : c \in ClaimIds}
    /\ ev.challengeBondLocked \in BOOLEAN

SignedIntent(r) ==
    /\ r \in EnabledReleases
    /\ releaseStatus[r] \in {"SUBMITTED", "AUTHORIZED_PENDING",
                              "LIABILITY_ADMITTED", "CAPACITY_APPROVED",
                              "CANCELLED", "FINALIZED"}
    /\ bundleEpoch[r] \in Epochs
    /\ CorrectDirectionBundle(r, bundles[r], bundleEpoch[r])

EquivocationFault(c) ==
    LET target == claims[c].target IN
    LET related == claims[c].evidence.related IN
      /\ SignedIntent(target)
      /\ SignedIntent(related)
      /\ target # related
      /\ StableSourceKey(target) = StableSourceKey(related)
      /\ requests[target].digest # requests[related].digest
      /\ EquivocationLiableSigners(target, related) # {}

ClaimGroundTruthFault(c) ==
    IF claims[c].kind = "FALSE_SOURCE"
    THEN GroundTruthFault(claims[c].target)
    ELSE EquivocationFault(c)

EmptyClaim ==
    [status |-> "EMPTY", target |-> NoRelease, kind |-> "FALSE_SOURCE",
     challenger |-> NoActor, evidence |-> NoEvidenceRecord,
     challengeBond |-> <<"NO_CHALLENGE_BOND">>,
     challengeBondStatus |-> "NO_BOND",
     rejection |-> NoReason, verdict |-> NoVerdict, culprits |-> {}]

ClaimSnapshot(c, cl) ==
    [claim |-> c, target |-> cl.target, kind |-> cl.kind,
     challenger |-> cl.challenger, challengeBond |-> cl.challengeBond,
     evidence |-> cl.evidence]

ProofReservedByOther(c, pid) ==
    \E d \in EnabledClaimIds :
      /\ d # c
      /\ claims[d].status \in {"ADMITTED", "VERDICTED", "APPLIED"}
      /\ claims[d].evidence.proofId = pid

EvidenceWellFormed(c) ==
    LET cl == claims[c] IN
    LET ev == cl.evidence IN
      /\ cl.target \in FinalizedReleaseIds
      /\ cl.challenger \in Challengers
      /\ ev.present
      /\ ev.auth = "GOOD_SIG"
      /\ ev.target = cl.target
      /\ ev.kind = cl.kind
      /\ ev.proofId = ProofId(ev.kind, ev.target, ev.related)
      /\ ev.expiresAt \in Epochs
      /\ currentEpoch <= ev.expiresAt
      /\ ev.challengeBond = cl.challengeBond
      /\ cl.challengeBond = ChallengeBondId(c)
      /\ cl.challengeBondStatus = "LOCKED"
      /\ ev.challengeBondLocked
      /\ ev.digest = EvidenceDigest(c, cl.challenger, ev.target, ev.kind,
                                    ev.related, ev.checkpoint, ev.expiresAt,
                                    ev.challengeBond)
      /\ AutoVerifiable(ProtocolVersion, DirectionOfRelease(cl.target), cl.kind)
      /\ IF cl.kind = "FALSE_SOURCE"
            THEN /\ publicCheckpoint[EventOfRelease(cl.target)].present
                 /\ publicCheckpoint[EventOfRelease(cl.target)].auth = "GOOD_SIG"
                 /\ ev.checkpoint = publicCheckpoint[EventOfRelease(cl.target)]
                 /\ ev.checkpoint.direction = requests[cl.target].direction
                 /\ ev.checkpoint.sourceEvent = requests[cl.target].sourceEvent
                 /\ ev.checkpoint.checkpointId =
                      requests[cl.target].sourceCheckpoint
                 /\ IF ev.checkpoint.fact.exists
                       THEN ev.checkpoint.proofKind = "AUTHENTICATED_INCLUSION"
                       ELSE ev.checkpoint.proofKind =
                              "AUTHENTICATED_MAP_NON_INCLUSION"
                 /\ ev.related = NoRelease
            ELSE /\ ev.related \in EnabledReleases
                 /\ releaseStatus[ev.related] \in
                      {"SUBMITTED", "LIABILITY_ADMITTED",
                       "AUTHORIZED_PENDING", "CAPACITY_APPROVED", "CANCELLED",
                       "FINALIZED"}
                 /\ ev.related # cl.target
                 /\ StableSourceKey(ev.related) = StableSourceKey(cl.target)
                 /\ requests[ev.related].digest # requests[cl.target].digest
                 /\ CorrectDirectionBundle(ev.related, bundles[ev.related],
                                            bundleEpoch[ev.related])

CorrectAdmissionDecision(c) ==
    LET cl == claims[c] IN
    LET ev == cl.evidence IN
    LET failure ==
      IF ~ev.present \/ ev.target # cl.target \/ ev.kind # cl.kind
      THEN "REJECT_MALFORMED"
      ELSE IF ev.auth # "GOOD_SIG" THEN "REJECT_UNAUTHENTICATED"
      ELSE IF ev.expiresAt \notin Epochs \/ currentEpoch > ev.expiresAt
           THEN "REJECT_EXPIRED"
      ELSE IF ev.challengeBond # cl.challengeBond
              \/ cl.challengeBond # ChallengeBondId(c)
              \/ cl.challengeBondStatus # "LOCKED"
              \/ ~ev.challengeBondLocked
           THEN "REJECT_UNBONDED_CHALLENGE"
      ELSE IF ~AutoVerifiable(ProtocolVersion,
                              DirectionOfRelease(cl.target), cl.kind)
           THEN "REJECT_UNSUPPORTED"
      ELSE IF ~EvidenceWellFormed(c) THEN "REJECT_INVALID_PROOF"
      ELSE NoReason
    IN IF failure # NoReason THEN failure
    ELSE IF ProofReservedByOther(c, claims[c].evidence.proofId)
         THEN "REJECT_DUPLICATE"
         ELSE "ADMIT"

ImplementationAdmissionDecision(c) ==
    IF Bug = "UNSUPPORTED_AUTO_SLASH"
       /\ ProtocolVersion = "V1"
       /\ DirectionOfRelease(claims[c].target) = "MOB_TO_ETH"
       /\ claims[c].kind = "FALSE_SOURCE"
    THEN "ADMIT"
    ELSE CorrectAdmissionDecision(c)

ObservableEvidenceSaysFault(c) ==
    IF claims[c].kind = "FALSE_SOURCE"
    THEN SourceFactPayload(claims[c].evidence.checkpoint.fact) #
           ClaimedSourceFacts(claims[c].target)
    ELSE TRUE

CorrectVerdict(c) ==
    IF ObservableEvidenceSaysFault(c)
    THEN [kind |-> "OPERATOR",
          culprits |->
            IF claims[c].kind = "EQUIVOCATION"
            THEN EquivocationLiableSigners(claims[c].target,
                                           claims[c].evidence.related)
            ELSE LiableApprovalSigners(claims[c].target)]
    ELSE [kind |-> "CHALLENGER", culprits |-> {claims[c].challenger}]

ImplementationVerdict(c) ==
    IF Bug = "ARBITRARY_OPERATOR_VERDICT"
       \/ Bug = "UNSUPPORTED_AUTO_SLASH"
    THEN [kind |-> "OPERATOR",
          culprits |-> LiableApprovalSigners(claims[c].target)]
    ELSE IF Bug = "INNOCENT_CULPRIT"
         THEN [kind |-> "OPERATOR", culprits |-> {"unbonded_account"}]
    ELSE IF Bug = "WRONG_CHALLENGER_SLASH"
         THEN [kind |-> "CHALLENGER", culprits |-> {"c2"}]
    ELSE CorrectVerdict(c)

SlashFor(c) ==
    {s.actor : s \in {x \in slashEvents : x.claim = c}}

ConsumedProofIds == {p.proofId : p \in proofConsumptionLog}
ProofConsumedBy(c) ==
    \E p \in proofConsumptionLog : p.claim = c

OperatorSlashEvent(c, a) ==
    [claim |-> c, proofId |-> claims[c].evidence.proofId, actor |-> a,
     role |-> "OPERATOR", bondId |-> OperatorBondId(a,
                                  acceptedAtEpoch[claims[c].target]),
     amount |-> 1]

ChallengerSlashEvent(c, a) ==
    [claim |-> c, proofId |-> claims[c].evidence.proofId, actor |-> a,
     role |-> "CHALLENGER", bondId |-> claims[c].challengeBond,
     amount |-> 1]

OperatorConsequence(c) ==
    [claim |-> c, proofId |-> claims[c].evidence.proofId,
     verdict |-> "OPERATOR", slashActors |-> claims[c].culprits,
     slashBondIds |-> {OperatorBondId(a, acceptedAtEpoch[claims[c].target]) :
                        a \in claims[c].culprits},
     restitutionActors |-> claims[c].culprits,
     bountyRecipient |-> claims[c].challenger, bountyAmount |-> 1,
     bountyAfterRestitution |-> TRUE,
     pausedEpoch |-> acceptedAtEpoch[claims[c].target],
     expelled |-> claims[c].culprits,
     rotationRequired |-> TRUE, freshGateDkgRequired |-> TRUE]

ChallengerConsequence(c) ==
    [claim |-> c, proofId |-> claims[c].evidence.proofId,
     verdict |-> "CHALLENGER", slashActors |-> claims[c].culprits,
     slashBondIds |-> {claims[c].challengeBond},
     restitutionActors |-> {}, bountyRecipient |-> NoActor,
     bountyAmount |-> 0, bountyAfterRestitution |-> TRUE,
     pausedEpoch |-> NoEpoch, expelled |-> {},
     rotationRequired |-> FALSE, freshGateDkgRequired |-> FALSE]

FreshGateDkgEvent(c) ==
    [claim |-> c, fromEpoch |-> acceptedAtEpoch[claims[c].target],
     toEpoch |-> 1, gateKey |-> GateKey(1),
     rosterManifest |-> RosterManifest("FROST", 1),
     expelled |-> claims[c].culprits]

(* Append-only core envelope only; capacity arithmetic remains NOT YET RUN. *)
CoreCapacityKinds == {"RECORD_SOURCE_ESCROW_INFLOW", "ADMIT_LIABILITY",
                      "AUTHORIZE_PENDING_RELEASE",
                      "ACCEPT_AND_RESERVE_RELEASE", "FINALIZE_RELEASE",
                      "PUBLISH_CANCEL_PROOF", "CANCEL_PENDING_RELEASE",
                      "APPLY_OPERATOR_FAULT"}

CapacityEvent(kind, r, e) ==
    [eventId |-> <<"CAPACITY_EVENT", kind, r>>,
     kind |-> kind, logicalTime |-> e,
     generation |-> GenerationId, direction |-> requests[r].direction,
     asset |-> requests[r].destinationAsset,
     amount |-> requests[r].destinationAmount,
     releaseId |-> r, sourceKey |-> requests[r].sourceKey,
     expiryEpoch |-> requests[r].expiryEpoch,
     tombstone |-> requests[r].tombstone,
     valuePositionIds |-> {ValuePositionOf(r)},
     capacityPositionIds |-> {<<"CAPACITY_POSITION", r>>},
     failureDomains |-> {"CORE_DOMAIN"},
     approvalQuorum |-> LiableApprovalSigners(r),
     ownerManifest |-> IF DirectionOfRelease(r) = "ETH_TO_MOB"
                       THEN RosterManifest("MLSAG", e) ELSE NoManifest,
     gateManifest |-> IF DirectionOfRelease(r) = "ETH_TO_MOB"
                      THEN RosterManifest("FROST", e) ELSE NoManifest,
     roleManifests |->
       IF DirectionOfRelease(r) = "ETH_TO_MOB"
       THEN {RosterManifest("WARDEN", e), RosterManifest("ACCOUNT", e)}
       ELSE {RosterManifest("ETH_MULTI", e), RosterManifest("WARDEN", e),
             RosterManifest("ACCOUNT", e)},
     bondManifest |-> BondManifest(e),
     capitalSourceKind |-> "NO_CAPITAL_EVENT",
     capitalSourceRef |-> "NO_CAPITAL_REF",
     phaseBefore |-> "NO_PHASE", phaseAfter |-> "NO_PHASE",
     proofId |-> NoProof, verdictId |-> NoVerdictId, culprits |-> {},
     bondPositionIds |-> {}, slashAmount |-> 0, restitutionAmount |-> 0,
     bountyAmount |-> 0, bountyRecipient |-> NoActor,
     affectedEpoch |-> NoEpoch, pauseRequired |-> FALSE, expelled |-> {},
     rotationRequired |-> FALSE, cancellationProofAuth |-> "NO_SIG"]

OperatorFaultCapacityEvent(c) ==
    [CapacityEvent("APPLY_OPERATOR_FAULT", claims[c].target,
                   acceptedAtEpoch[claims[c].target]) EXCEPT
       !.eventId = <<"CAPACITY_EVENT", "APPLY_OPERATOR_FAULT", c>>,
       !.approvalQuorum = claims[c].culprits,
       !.proofId = claims[c].evidence.proofId,
       !.verdictId = <<"VERDICT", c>>,
       !.culprits = claims[c].culprits,
       !.bondPositionIds =
          {OperatorBondId(a, acceptedAtEpoch[claims[c].target]) :
             a \in claims[c].culprits},
       !.slashAmount = Cardinality(claims[c].culprits),
       !.restitutionAmount = Cardinality(claims[c].culprits),
       !.bountyAmount = 1,
       !.bountyRecipient = claims[c].challenger,
       !.affectedEpoch = acceptedAtEpoch[claims[c].target],
       !.pauseRequired = TRUE,
       !.expelled = claims[c].culprits,
       !.rotationRequired = TRUE]

CancellationProofEvent(r) ==
    [CapacityEvent("PUBLISH_CANCEL_PROOF", r, acceptedAtEpoch[r]) EXCEPT
       !.proofId = <<"CANCEL_PROOF", r, requests[r].tombstone>>,
       !.cancellationProofAuth = "GOOD_SIG"]

FactRepresentsEscrowInflow(ev) ==
    LET fact == publicCheckpoint[ev].fact IN
      /\ publicCheckpoint[ev].present
      /\ publicCheckpoint[ev].auth = "GOOD_SIG"
      /\ fact.exists
      /\ fact.finality = Final
      /\ fact.sourceChain = SourceChain(ev)
      /\ fact.sourcePolicy = SourcePolicy(ev)
      /\ fact.sourceEvent = ev
      /\ fact.sourceCheckpoint = CheckpointOf(ev)
      /\ fact.sourceAsset = SourceAsset(ev)
      /\ fact.sourceAmount \in 1..2

SourceInflowCapacityEvent(ev) ==
    LET r == CanonicalReleaseForEvent(ev) IN
      [CapacityEvent("RECORD_SOURCE_ESCROW_INFLOW", r, 0) EXCEPT
         !.eventId = <<"CAPACITY_EVENT", "RECORD_SOURCE_ESCROW_INFLOW", ev>>,
         !.direction = DirectionOfEvent(ev),
         !.asset = SourceAsset(ev),
         !.amount = publicCheckpoint[ev].fact.sourceAmount,
         !.releaseId = NoRelease,
         !.sourceKey = StableSourceKey(r),
         !.expiryEpoch = NoEpoch,
         !.tombstone = <<"NO_TOMBSTONE">>,
         !.valuePositionIds = {<<"SOURCE_INFLOW_POSITION", ev>>},
         !.capacityPositionIds = {},
         !.approvalQuorum = {},
         !.ownerManifest = NoManifest,
         !.gateManifest = NoManifest,
         !.roleManifests = {},
         !.bondManifest = NoBond,
         !.capitalSourceKind = "CUSTOMER_ESCROW_INFLOW",
         !.capitalSourceRef = publicCheckpoint[ev].checkpointId]

CapacityEventUniverse ==
    {CapacityEvent(kind, r, e) :
       kind \in CoreCapacityKinds \
                 {"APPLY_OPERATOR_FAULT", "PUBLISH_CANCEL_PROOF",
                  "RECORD_SOURCE_ESCROW_INFLOW"},
       r \in ReleaseIds, e \in Epochs}
    \cup {OperatorFaultCapacityEvent(c) :
            c \in {d \in ClaimIds : claims[d].target \in ReleaseIds}}
    \cup {CancellationProofEvent(r) :
            r \in {x \in ReleaseIds : acceptedAtEpoch[x] \in Epochs}}
    \cup {SourceInflowCapacityEvent(ev) :
            ev \in {x \in Events : publicCheckpoint[x].present}}

CoreCapacityEventLog == capacityEventLog
CoreCapacityEvents ==
    {capacityEventLog[i] : i \in 1..Len(capacityEventLog)}

LiabilityAdmissionEvents ==
    {e \in CoreCapacityEvents : e.kind = "ADMIT_LIABILITY"}

AllocatedBackingPositions ==
    UNION {e.valuePositionIds : e \in LiabilityAdmissionEvents}

InventoryInflowEvents ==
    {e \in CoreCapacityEvents : e.kind = "RECORD_SOURCE_ESCROW_INFLOW"}

CapacityEventLogSound ==
    /\ \A i, j \in 1..Len(capacityEventLog) :
         capacityEventLog[i].eventId = capacityEventLog[j].eventId => i = j
    /\ \A i \in 1..Len(capacityEventLog) :
         capacityEventLog[i].kind \in CoreCapacityKinds

vars == <<currentEpoch, objectiveSource, publicCheckpoint, releaseStatus,
          requests, bundleVariant, bundleEpoch, bundles, acceptedAtEpoch,
          valueState, reservationOwner, nullifierLog, claims,
          claimSubmissionLog,
          proofReservations, proofConsumptionLog,
          slashEvents, consequenceEvents, freshGateDkgEvents,
          slashApplyCount, operatorBondState, capacityEventLog,
          paused, pauseCauses>>

Init ==
    /\ currentEpoch = 0
    /\ objectiveSource = [ev \in Events |-> UnknownSourceFact]
    /\ publicCheckpoint = [ev \in Events |-> NoCheckpoint]
    /\ releaseStatus = [r \in ReleaseIds |-> "EMPTY"]
    /\ requests = [r \in ReleaseIds |-> NoRequest]
    /\ bundleVariant = [r \in ReleaseIds |-> NoVariant]
    /\ bundleEpoch = [r \in ReleaseIds |-> NoEpoch]
    /\ bundles = [r \in ReleaseIds |-> NoBundle]
    /\ acceptedAtEpoch = [r \in ReleaseIds |-> NoEpoch]
    /\ valueState = [p \in ValuePositions |-> "AVAILABLE"]
    /\ reservationOwner = [p \in ValuePositions |-> NoRelease]
    /\ nullifierLog = {}
    /\ claims = [c \in ClaimIds |-> EmptyClaim]
    /\ claimSubmissionLog = {}
    /\ proofReservations = {}
    /\ proofConsumptionLog = {}
    /\ slashEvents = {}
    /\ consequenceEvents = {}
    /\ freshGateDkgEvents = {}
    /\ slashApplyCount = [c \in ClaimIds |-> 0]
    /\ operatorBondState =
         [bond \in OperatorBondIds |->
            IF bond[2] \in BondedOperatorPrincipals THEN "LOCKED"
            ELSE "UNBONDED"]
    /\ capacityEventLog = <<>>
    /\ paused = FALSE
    /\ pauseCauses = {}

(***************************************************************************)
(* Environment actions. Only these actions touch or read objectiveSource.   *)
(***************************************************************************)

RecordObjectiveSourceFact ==
    \E ev \in Events, variant \in EnabledSourceFactVariants :
      /\ objectiveSource[ev] = UnknownSourceFact
      /\ objectiveSource' =
           [objectiveSource EXCEPT ![ev] = ObjectiveFactFor(ev, variant)]
      /\ UNCHANGED <<currentEpoch, publicCheckpoint,
                      releaseStatus, requests,
                      bundleVariant, bundleEpoch, bundles, acceptedAtEpoch,
                      valueState, reservationOwner, nullifierLog, claims,
                      claimSubmissionLog,
                      proofReservations, proofConsumptionLog,
                      slashEvents, consequenceEvents, freshGateDkgEvents,
                      slashApplyCount, operatorBondState, capacityEventLog,
                      paused, pauseCauses>>

PublishVerifiableCheckpoint ==
    \E ev \in Events :
      /\ objectiveSource[ev] # UnknownSourceFact
      /\ publicCheckpoint[ev] = NoCheckpoint
      /\ CheckpointPublicationEnabled(ev)
      /\ publicCheckpoint' =
           [publicCheckpoint EXCEPT
              ![ev] = AuthenticatedCheckpoint(ev, objectiveSource[ev])]
      /\ UNCHANGED <<currentEpoch, objectiveSource,
                      releaseStatus, requests,
                      bundleVariant, bundleEpoch, bundles, acceptedAtEpoch,
                      valueState, reservationOwner, nullifierLog, claims,
                      claimSubmissionLog,
                      proofReservations, proofConsumptionLog,
                      slashEvents, consequenceEvents, freshGateDkgEvents,
                      slashApplyCount, operatorBondState, capacityEventLog,
                      paused, pauseCauses>>

RecordSourceEscrowInflow ==
    \E ev \in Events :
      /\ FactRepresentsEscrowInflow(ev)
      /\ SourceInflowCapacityEvent(ev) \notin CoreCapacityEvents
      /\ capacityEventLog' =
           Append(capacityEventLog, SourceInflowCapacityEvent(ev))
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint,
                      releaseStatus, requests, bundleVariant, bundleEpoch,
                      bundles, acceptedAtEpoch, valueState, reservationOwner,
                      nullifierLog, claims, claimSubmissionLog,
                      proofReservations, proofConsumptionLog, slashEvents,
                      consequenceEvents, freshGateDkgEvents, slashApplyCount,
                      operatorBondState, paused, pauseCauses>>

(***************************************************************************)
(* Release path. None of these actions may reference objectiveSource.       *)
(***************************************************************************)

ConstructSourceAssertion ==
    \E r \in EnabledReleases :
      /\ releaseStatus[r] = "EMPTY"
      /\ ~paused
      /\ releaseStatus' = [releaseStatus EXCEPT ![r] = "ASSERTED"]
      /\ requests' = [requests EXCEPT ![r] = CanonicalRequest(r, currentEpoch)]
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint,
                      bundleVariant, bundleEpoch, bundles, acceptedAtEpoch,
                      valueState, reservationOwner, nullifierLog, claims,
                      claimSubmissionLog, proofReservations,
                      proofConsumptionLog, slashEvents, consequenceEvents,
                      freshGateDkgEvents, slashApplyCount, operatorBondState,
                      capacityEventLog, paused, pauseCauses>>

AssembleDirectionArtifacts ==
    \E r \in EnabledReleases, variant \in EnabledVariants :
      LET candidate == BundleFor(r, currentEpoch, variant) IN
      /\ releaseStatus[r] = "ASSERTED"
      /\ ~paused
      /\ (ArtifactPublicationMode # "VALIDATE_ON_PUBLICATION"
          \/ AdmissionDirectionBundle(r, candidate, currentEpoch))
      /\ releaseStatus' = [releaseStatus EXCEPT ![r] = "ASSEMBLED"]
      /\ bundleVariant' = [bundleVariant EXCEPT ![r] = variant]
      /\ bundleEpoch' = [bundleEpoch EXCEPT ![r] = currentEpoch]
      /\ bundles' = [bundles EXCEPT ![r] = candidate]
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint, requests,
                      acceptedAtEpoch, valueState, reservationOwner,
                      nullifierLog, claims, claimSubmissionLog,
                      proofReservations, proofConsumptionLog, slashEvents,
                      consequenceEvents, freshGateDkgEvents, slashApplyCount,
                      operatorBondState, capacityEventLog, paused, pauseCauses>>

SubmitDestinationRelease ==
    \E r \in EnabledReleases :
      /\ releaseStatus[r] = "ASSEMBLED"
      /\ ~paused
      /\ releaseStatus' = [releaseStatus EXCEPT ![r] = "SUBMITTED"]
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint, requests,
                      bundleVariant, bundleEpoch, bundles, acceptedAtEpoch,
                      valueState, reservationOwner, nullifierLog, claims,
                      claimSubmissionLog, proofReservations,
                      proofConsumptionLog, slashEvents, consequenceEvents,
                      freshGateDkgEvents, slashApplyCount, operatorBondState,
                      capacityEventLog, paused, pauseCauses>>

CorrectReleaseAcceptable(r) ==
    /\ releaseStatus[r] = "SUBMITTED"
    /\ ~paused
    /\ requests[r] = CanonicalRequestWithStableKey(r, bundleEpoch[r])
    /\ bundleEpoch[r] = currentEpoch
    /\ AdmissionDirectionBundle(r, bundles[r], bundleEpoch[r])
    /\ StableSourceKey(r) \notin NullifierKeys
    /\ valueState[ValuePositionOf(r)] = "AVAILABLE"
    /\ ValuePositionOf(r) \notin AllocatedBackingPositions

ImplementationReleaseAcceptable(r) ==
    /\ releaseStatus[r] = "SUBMITTED"
    /\ ~paused
    /\ requests[r] = CanonicalRequest(r, bundleEpoch[r])
    /\ bundleEpoch[r] = currentEpoch
    /\ ImplementationBundleValid(r)
    /\ (StableSourceKey(r) \notin NullifierKeys \/ Bug = "REUSE_SOURCE_EVENT")
    /\ (valueState[ValuePositionOf(r)] = "AVAILABLE"
        \/ Bug = "RELEASE_WITHOUT_RESERVE")
    /\ ValuePositionOf(r) \notin AllocatedBackingPositions
    /\ (Bug # "TRUTH_IN_RELEASE_GUARD"
        \/ SourceFactPayload(objectiveSource[EventOfRelease(r)]) =
             ClaimedSourceFacts(r))

FinalizedNullifierRecord(r) ==
    [release |-> r,
     key |-> IF Bug = "VERSIONED_NULLIFIER"
             THEN requests[r].sourceKey ELSE StableSourceKey(r)]

AdmitDestinationLiability ==
    \E r \in EnabledReleases :
      /\ releaseStatus[r] = "SUBMITTED"
      /\ IF ImplementationReleaseAcceptable(r)
            THEN /\ releaseStatus' =
                        [releaseStatus EXCEPT ![r] = "LIABILITY_ADMITTED"]
                 /\ acceptedAtEpoch' = [acceptedAtEpoch EXCEPT ![r] = currentEpoch]
                 /\ capacityEventLog' =
                      Append(capacityEventLog,
                             CapacityEvent("ADMIT_LIABILITY", r,
                                           currentEpoch))
            ELSE /\ releaseStatus' = [releaseStatus EXCEPT ![r] = "REJECTED"]
                 /\ UNCHANGED <<acceptedAtEpoch, capacityEventLog>>
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint, requests,
                      bundleVariant, bundleEpoch, bundles, claims,
                      claimSubmissionLog, valueState, reservationOwner,
                      nullifierLog, proofReservations, proofConsumptionLog,
                      slashEvents, consequenceEvents, freshGateDkgEvents,
                      slashApplyCount, operatorBondState, paused, pauseCauses>>

ValidateDestinationRelease ==
    \E r \in EnabledReleases :
      /\ releaseStatus[r] = "LIABILITY_ADMITTED"
      /\ ~paused
      /\ acceptedAtEpoch[r] = currentEpoch
      /\ releaseStatus' = [releaseStatus EXCEPT ![r] = "AUTHORIZED_PENDING"]
      /\ capacityEventLog' =
           Append(capacityEventLog,
                  CapacityEvent("AUTHORIZE_PENDING_RELEASE", r,
                                acceptedAtEpoch[r]))
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint, requests,
                      bundleVariant, bundleEpoch, bundles, acceptedAtEpoch,
                      valueState, reservationOwner, nullifierLog, claims,
                      claimSubmissionLog, proofReservations,
                      proofConsumptionLog, slashEvents, consequenceEvents,
                      freshGateDkgEvents, slashApplyCount, operatorBondState,
                      paused, pauseCauses>>

(* Assume/guarantee handshake: this action records an approval returned by   *)
(* the not-yet-run capacity stage. It does not itself prove any cap.         *)
RecordCapacityApproval ==
    \E r \in EnabledReleases :
      /\ releaseStatus[r] = "AUTHORIZED_PENDING"
      /\ ~paused
      /\ acceptedAtEpoch[r] = currentEpoch
      /\ (valueState[ValuePositionOf(r)] = "AVAILABLE"
          \/ Bug = "RELEASE_WITHOUT_RESERVE")
      /\ releaseStatus' = [releaseStatus EXCEPT ![r] = "CAPACITY_APPROVED"]
      /\ IF Bug = "RELEASE_WITHOUT_RESERVE"
            THEN /\ UNCHANGED <<valueState, reservationOwner>>
            ELSE /\ valueState' =
                       [valueState EXCEPT ![ValuePositionOf(r)] = "RESERVED"]
                 /\ reservationOwner' =
                       [reservationOwner EXCEPT ![ValuePositionOf(r)] = r]
      /\ capacityEventLog' =
           Append(capacityEventLog,
                  CapacityEvent("ACCEPT_AND_RESERVE_RELEASE", r,
                                acceptedAtEpoch[r]))
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint, requests,
                      bundleVariant, bundleEpoch, bundles, acceptedAtEpoch,
                      nullifierLog, claims,
                      claimSubmissionLog, proofReservations,
                      proofConsumptionLog, slashEvents, consequenceEvents,
                      freshGateDkgEvents, slashApplyCount, operatorBondState,
                      paused, pauseCauses>>

FinalizeDestinationRelease ==
    \E r \in EnabledReleases :
      /\ releaseStatus[r] = "CAPACITY_APPROVED"
      /\ ~paused
      /\ acceptedAtEpoch[r] = currentEpoch
      /\ (StableSourceKey(r) \notin NullifierKeys \/ Bug = "REUSE_SOURCE_EVENT")
      /\ ( /\ valueState[ValuePositionOf(r)] = "RESERVED"
             /\ reservationOwner[ValuePositionOf(r)] = r
           \/ Bug = "RELEASE_WITHOUT_RESERVE")
      /\ releaseStatus' = [releaseStatus EXCEPT ![r] = "FINALIZED"]
      /\ nullifierLog' =
           IF Bug = "OMIT_NULLIFIER_CONSUMPTION"
           THEN nullifierLog
           ELSE nullifierLog \cup {FinalizedNullifierRecord(r)}
      /\ IF Bug = "RELEASE_WITHOUT_RESERVE"
            THEN /\ UNCHANGED <<valueState, reservationOwner>>
            ELSE /\ valueState' =
                       [valueState EXCEPT ![ValuePositionOf(r)] = "SPENT"]
                 /\ reservationOwner' =
                       [reservationOwner EXCEPT ![ValuePositionOf(r)] = r]
      /\ capacityEventLog' =
           Append(capacityEventLog,
                  CapacityEvent("FINALIZE_RELEASE", r, acceptedAtEpoch[r]))
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint, requests,
                      bundleVariant, bundleEpoch, bundles, acceptedAtEpoch,
                      claims, claimSubmissionLog, proofReservations,
                      proofConsumptionLog, slashEvents, consequenceEvents,
                      freshGateDkgEvents, slashApplyCount, operatorBondState,
                      paused, pauseCauses>>

PublishCancellationProof ==
    \E r \in EnabledReleases :
      /\ releaseStatus[r] \in {"AUTHORIZED_PENDING", "CAPACITY_APPROVED"}
      /\ currentEpoch > requests[r].expiryEpoch
      /\ CancellationProofEvent(r) \notin CoreCapacityEvents
      /\ capacityEventLog' = Append(capacityEventLog, CancellationProofEvent(r))
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint,
                      releaseStatus, requests, bundleVariant, bundleEpoch,
                      bundles, acceptedAtEpoch, valueState, reservationOwner,
                      nullifierLog, claims, claimSubmissionLog,
                      proofReservations, proofConsumptionLog, slashEvents,
                      consequenceEvents, freshGateDkgEvents, slashApplyCount,
                      operatorBondState, paused, pauseCauses>>

CancelPendingRelease ==
    \E r \in EnabledReleases :
      /\ releaseStatus[r] \in {"AUTHORIZED_PENDING", "CAPACITY_APPROVED"}
      /\ currentEpoch > requests[r].expiryEpoch
      /\ CancellationProofEvent(r) \in CoreCapacityEvents
      /\ releaseStatus' = [releaseStatus EXCEPT ![r] = "CANCELLED"]
      /\ IF reservationOwner[ValuePositionOf(r)] = r
            THEN /\ valueState' =
                       [valueState EXCEPT ![ValuePositionOf(r)] = "AVAILABLE"]
                 /\ reservationOwner' =
                       [reservationOwner EXCEPT ![ValuePositionOf(r)] = NoRelease]
            ELSE /\ UNCHANGED <<valueState, reservationOwner>>
      /\ capacityEventLog' =
           Append(capacityEventLog,
                  CapacityEvent("CANCEL_PENDING_RELEASE", r,
                                acceptedAtEpoch[r]))
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint, requests,
                      bundleVariant, bundleEpoch, bundles, acceptedAtEpoch,
                      nullifierLog, claims, claimSubmissionLog,
                      proofReservations, proofConsumptionLog, slashEvents,
                      consequenceEvents, freshGateDkgEvents, slashApplyCount,
                      operatorBondState, paused, pauseCauses>>

PoisonNullifier ==
    /\ Bug = "POISON_NULLIFIER"
    /\ \E r \in EnabledReleases :
         /\ releaseStatus[r] # "FINALIZED"
         /\ [release |-> r, key |-> StableSourceKey(r)] \notin nullifierLog
         /\ nullifierLog' = nullifierLog \cup
              {[release |-> r, key |-> StableSourceKey(r)]}
    /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint,
                    releaseStatus, requests, bundleVariant, bundleEpoch,
                    bundles, acceptedAtEpoch, valueState, reservationOwner,
                    claims, claimSubmissionLog, proofReservations,
                    proofConsumptionLog, slashEvents, consequenceEvents,
                    freshGateDkgEvents, slashApplyCount, operatorBondState,
                    capacityEventLog, paused, pauseCauses>>

AdvanceEpoch ==
    /\ currentEpoch = 0
    /\ ~paused
    /\ currentEpoch' = 1
    /\ UNCHANGED <<objectiveSource, publicCheckpoint, releaseStatus, requests,
                    bundleVariant, bundleEpoch, bundles, acceptedAtEpoch,
                    valueState, reservationOwner, nullifierLog, claims,
                    claimSubmissionLog, proofReservations,
                    proofConsumptionLog, slashEvents, consequenceEvents,
                    freshGateDkgEvents, slashApplyCount, operatorBondState,
                    capacityEventLog, paused, pauseCauses>>

(***************************************************************************)
(* Claim, evidence, verdict, and consequence path.                          *)
(***************************************************************************)

SubmitFraudClaim ==
    \E c \in EnabledClaimIds, r \in FinalizedReleaseIds,
       kind \in ProofKinds, variant \in EvidenceVariants :
      /\ claims[c].status = "EMPTY"
      /\ LET submitted ==
               [status |-> "SUBMITTED", target |-> r, kind |-> kind,
                challenger |-> ChallengerFor(c),
                challengeBond |-> ChallengeBondId(c),
                challengeBondStatus |->
                  IF variant = "UNBONDED_CHALLENGE" THEN "UNBONDED"
                  ELSE "LOCKED",
                evidence |-> EvidenceFor(c, r, kind, variant),
                rejection |-> NoReason, verdict |-> NoVerdict, culprits |-> {}]
         IN /\ claims' = [claims EXCEPT ![c] = submitted]
            /\ claimSubmissionLog' =
                 claimSubmissionLog \cup {ClaimSnapshot(c, submitted)}
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint,
                      releaseStatus, requests, bundleVariant, bundleEpoch,
                      bundles, acceptedAtEpoch, valueState, reservationOwner,
                      nullifierLog, proofReservations,
                      proofConsumptionLog, slashEvents, consequenceEvents,
                      freshGateDkgEvents, slashApplyCount, operatorBondState,
                      capacityEventLog, paused, pauseCauses>>

ClassifyClaim ==
    \E c \in EnabledClaimIds :
      LET decision == ImplementationAdmissionDecision(c) IN
      /\ claims[c].status = "SUBMITTED"
      /\ IF decision = "ADMIT"
            THEN /\ claims' = [claims EXCEPT
                     ![c].status = "ADMITTED",
                     ![c].rejection = NoReason]
                 /\ proofReservations' = proofReservations \cup
                      {[proofId |-> claims[c].evidence.proofId, claim |-> c]}
            ELSE /\ claims' = [claims EXCEPT
                     ![c].status = "REJECTED",
                     ![c].rejection = decision]
                 /\ UNCHANGED proofReservations
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint,
                      releaseStatus, requests, bundleVariant, bundleEpoch,
                      bundles, acceptedAtEpoch, valueState, reservationOwner,
                      nullifierLog, claimSubmissionLog, proofConsumptionLog,
                      slashEvents, consequenceEvents, freshGateDkgEvents,
                      slashApplyCount, operatorBondState, capacityEventLog,
                      paused, pauseCauses>>

RecordVerdict ==
    \E c \in EnabledClaimIds :
      LET v == ImplementationVerdict(c) IN
      /\ claims[c].status = "ADMITTED"
      /\ claims' = [claims EXCEPT
           ![c].status = "VERDICTED",
           ![c].verdict = v.kind,
           ![c].culprits = v.culprits]
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint,
                      releaseStatus, requests, bundleVariant, bundleEpoch,
                      bundles, acceptedAtEpoch, valueState, reservationOwner,
                      nullifierLog, claimSubmissionLog, proofReservations,
                      proofConsumptionLog, slashEvents, consequenceEvents,
                      freshGateDkgEvents, slashApplyCount, operatorBondState,
                      capacityEventLog, paused, pauseCauses>>

ApplyOperatorFault ==
    \E c \in EnabledClaimIds :
      /\ claims[c].status = "VERDICTED"
      /\ claims[c].verdict = "OPERATOR"
      /\ claims[c].evidence.proofId \notin ConsumedProofIds
      /\ claims' = [claims EXCEPT ![c].status = "APPLIED"]
      /\ proofConsumptionLog' = proofConsumptionLog \cup
           {[proofId |-> claims[c].evidence.proofId, claim |-> c]}
      /\ slashEvents' = slashEvents \cup
           {OperatorSlashEvent(c, a) : a \in claims[c].culprits}
      /\ consequenceEvents' = consequenceEvents \cup {OperatorConsequence(c)}
      /\ slashApplyCount' = [slashApplyCount EXCEPT ![c] = @ + 1]
      /\ operatorBondState' =
           [bond \in OperatorBondIds |->
              IF \E a \in claims[c].culprits :
                   bond = OperatorBondId(a,
                            acceptedAtEpoch[claims[c].target])
              THEN "SLASHED" ELSE operatorBondState[bond]]
      /\ paused' = TRUE
      /\ pauseCauses' = pauseCauses \cup {c}
      /\ capacityEventLog' =
           Append(capacityEventLog, OperatorFaultCapacityEvent(c))
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint,
                      releaseStatus, requests, bundleVariant, bundleEpoch,
                      bundles, acceptedAtEpoch, valueState, reservationOwner,
                      nullifierLog, claimSubmissionLog, proofReservations,
                      freshGateDkgEvents>>

ApplyChallengerFault ==
    \E c \in EnabledClaimIds :
      /\ claims[c].status = "VERDICTED"
      /\ claims[c].verdict = "CHALLENGER"
      /\ claims[c].evidence.proofId \notin ConsumedProofIds
      /\ claims' = [claims EXCEPT
           ![c].status = "APPLIED",
           ![c].challengeBondStatus = "SLASHED"]
      /\ proofConsumptionLog' = proofConsumptionLog \cup
           {[proofId |-> claims[c].evidence.proofId, claim |-> c]}
      /\ slashEvents' = slashEvents \cup
           {ChallengerSlashEvent(c, a) : a \in claims[c].culprits}
      /\ consequenceEvents' = consequenceEvents \cup {ChallengerConsequence(c)}
      /\ slashApplyCount' = [slashApplyCount EXCEPT ![c] = @ + 1]
      /\ IF Bug = "FALSE_CHALLENGE_PAUSES"
            THEN /\ paused' = TRUE
                 /\ pauseCauses' = pauseCauses \cup {c}
            ELSE /\ UNCHANGED <<paused, pauseCauses>>
      /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint,
                      releaseStatus, requests, bundleVariant, bundleEpoch,
                      bundles, acceptedAtEpoch, valueState, reservationOwner,
                      nullifierLog, claimSubmissionLog, proofReservations,
                      freshGateDkgEvents, operatorBondState, capacityEventLog>>

SlashWithoutVerdict ==
    /\ Bug = "SLASH_WITHOUT_VERDICT"
    /\ \E c \in EnabledClaimIds :
         /\ claims[c].status \in {"SUBMITTED", "REJECTED", "ADMITTED"}
         /\ slashEvents' = slashEvents \cup
              {OperatorSlashEvent(c, "unbonded_account")}
         /\ slashApplyCount' = [slashApplyCount EXCEPT ![c] = @ + 1]
    /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint,
                    releaseStatus, requests, bundleVariant, bundleEpoch,
                    bundles, acceptedAtEpoch, valueState, reservationOwner,
                    nullifierLog, claims, claimSubmissionLog,
                    proofReservations, proofConsumptionLog, consequenceEvents,
                    freshGateDkgEvents, operatorBondState, capacityEventLog,
                    paused, pauseCauses>>

DoubleApplyProof ==
    /\ Bug = "DOUBLE_APPLY_PROOF"
    /\ \E c \in EnabledClaimIds :
         /\ claims[c].status = "APPLIED"
         /\ slashApplyCount[c] = 1
         /\ slashApplyCount' = [slashApplyCount EXCEPT ![c] = 2]
    /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint,
                    releaseStatus, requests, bundleVariant, bundleEpoch,
                    bundles, acceptedAtEpoch, valueState, reservationOwner,
                    nullifierLog, claims, claimSubmissionLog,
                    proofReservations, proofConsumptionLog, slashEvents,
                    consequenceEvents, freshGateDkgEvents, operatorBondState,
                    capacityEventLog, paused, pauseCauses>>

RejectedClaimEffect ==
    /\ Bug = "REJECTED_CLAIM_EFFECT"
    /\ \E c \in EnabledClaimIds :
         /\ claims[c].status = "REJECTED"
         /\ slashEvents' = slashEvents \cup
              {OperatorSlashEvent(c, "unbonded_account")}
         /\ slashApplyCount' = [slashApplyCount EXCEPT ![c] = @ + 1]
         /\ proofConsumptionLog' = proofConsumptionLog \cup
              {[proofId |-> claims[c].evidence.proofId, claim |-> c]}
         /\ consequenceEvents' = consequenceEvents \cup {OperatorConsequence(c)}
         /\ paused' = TRUE
         /\ pauseCauses' = pauseCauses \cup {c}
    /\ UNCHANGED <<currentEpoch, objectiveSource, publicCheckpoint,
                    releaseStatus, requests, bundleVariant, bundleEpoch,
                    bundles, acceptedAtEpoch, valueState, reservationOwner,
                    nullifierLog, claims, claimSubmissionLog,
                    proofReservations, freshGateDkgEvents, operatorBondState,
                    capacityEventLog>>

CompleteFreshGateEpoch ==
    \E c \in EnabledClaimIds :
      /\ claims[c].status = "APPLIED"
      /\ claims[c].verdict = "OPERATOR"
      /\ acceptedAtEpoch[claims[c].target] = 0
      /\ FreshGateDkgEvent(c) \notin freshGateDkgEvents
      /\ currentEpoch' = 1
      /\ freshGateDkgEvents' = freshGateDkgEvents \cup {FreshGateDkgEvent(c)}
      /\ paused' = FALSE
      /\ UNCHANGED <<objectiveSource, publicCheckpoint,
                      releaseStatus, requests, bundleVariant, bundleEpoch,
                      bundles, acceptedAtEpoch, valueState, reservationOwner,
                      nullifierLog, claims, claimSubmissionLog,
                      proofReservations, proofConsumptionLog, slashEvents,
                      consequenceEvents, slashApplyCount, operatorBondState,
                      capacityEventLog, pauseCauses>>

Next ==
    \/ RecordObjectiveSourceFact
    \/ PublishVerifiableCheckpoint
    \/ RecordSourceEscrowInflow
    \/ ConstructSourceAssertion
    \/ AssembleDirectionArtifacts
    \/ SubmitDestinationRelease
    \/ AdmitDestinationLiability
    \/ ValidateDestinationRelease
    \/ RecordCapacityApproval
    \/ FinalizeDestinationRelease
    \/ PublishCancellationProof
    \/ CancelPendingRelease
    \/ PoisonNullifier
    \/ AdvanceEpoch
    \/ SubmitFraudClaim
    \/ ClassifyClaim
    \/ RecordVerdict
    \/ ApplyOperatorFault
    \/ ApplyChallengerFault
    \/ SlashWithoutVerdict
    \/ DoubleApplyProof
    \/ RejectedClaimEffect
    \/ CompleteFreshGateEpoch

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Type and state safety.                                                   *)
(***************************************************************************)

TypeOK ==
    /\ currentEpoch \in Epochs
    /\ \A ev \in Events : SourceFactTypeOK(objectiveSource[ev])
    /\ \A ev \in Events : CheckpointTypeOK(publicCheckpoint[ev])
    /\ releaseStatus \in [ReleaseIds -> ReleaseStatuses]
    /\ \A r \in ReleaseIds : RequestTypeOK(requests[r])
    /\ bundleVariant \in [ReleaseIds -> ArtifactVariants \cup {NoVariant}]
    /\ \A r \in ReleaseIds :
         (bundleEpoch[r] = NoEpoch \/ bundleEpoch[r] \in Epochs)
    /\ \A r \in ReleaseIds :
         (acceptedAtEpoch[r] = NoEpoch \/ acceptedAtEpoch[r] \in Epochs)
    /\ \A r \in ReleaseIds :
         \/ bundles[r] = NoBundle
         \/ /\ ArtifactTypeOK(bundles[r].mlsag)
            /\ ArtifactTypeOK(bundles[r].frost)
            /\ ArtifactTypeOK(bundles[r].ethMulti)
            /\ ArtifactTypeOK(bundles[r].warden)
            /\ ArtifactTypeOK(bundles[r].account)
    /\ valueState \in [ValuePositions -> {"AVAILABLE", "RESERVED", "SPENT"}]
    /\ reservationOwner \in [ValuePositions -> ReleaseIds \cup {NoRelease}]
    /\ nullifierLog \subseteq
         [release : ReleaseIds, key : {StableSourceKey(r) : r \in ReleaseIds}
                                       \cup {<<StableSourceKey(r), v>> :
                                             r \in ReleaseIds, v \in Versions}]
    /\ \A c \in ClaimIds :
         /\ claims[c].status \in ClaimStatuses
         /\ claims[c].target \in ReleaseIds \cup {NoRelease}
         /\ claims[c].kind \in ProofKinds
         /\ claims[c].challenger \in Challengers \cup {NoActor}
         /\ claims[c].challengeBond \in {<<"NO_CHALLENGE_BOND">>}
                                        \cup {ChallengeBondId(d) : d \in ClaimIds}
         /\ claims[c].challengeBondStatus \in
              {"NO_BOND", "LOCKED", "UNBONDED", "SLASHED"}
         /\ EvidenceTypeOK(claims[c].evidence)
         /\ claims[c].rejection \in RejectionReasons
         /\ claims[c].verdict \in VerdictKinds
         /\ claims[c].culprits \subseteq Principals
    /\ \A snap \in claimSubmissionLog :
         /\ snap.claim \in ClaimIds
         /\ snap.target \in ReleaseIds
         /\ snap.kind \in ProofKinds
         /\ snap.challenger \in Challengers
         /\ snap.challengeBond \in {ChallengeBondId(c) : c \in ClaimIds}
         /\ EvidenceTypeOK(snap.evidence)
    /\ \A p \in proofReservations :
         /\ p.claim \in ClaimIds
         /\ p.proofId = claims[p.claim].evidence.proofId
    /\ \A p \in proofConsumptionLog :
         /\ p.claim \in ClaimIds
         /\ p.proofId = claims[p.claim].evidence.proofId
    /\ \A s \in slashEvents :
         /\ s.claim \in ClaimIds
         /\ s.proofId = claims[s.claim].evidence.proofId
         /\ s.actor \in Principals
         /\ s.role \in {"OPERATOR", "CHALLENGER"}
         /\ s.bondId \in OperatorBondIds
                         \cup {ChallengeBondId(c) : c \in ClaimIds}
         /\ s.amount = 1
    /\ \A e \in consequenceEvents :
         /\ e.claim \in ClaimIds
         /\ e.proofId = claims[e.claim].evidence.proofId
         /\ e.verdict \in {"OPERATOR", "CHALLENGER"}
         /\ e.slashActors \subseteq Principals
         /\ e.slashBondIds \subseteq
              OperatorBondIds \cup {ChallengeBondId(c) : c \in ClaimIds}
         /\ e.restitutionActors \subseteq Principals
         /\ e.bountyRecipient \in Challengers \cup {NoActor}
         /\ e.bountyAmount \in 0..1
         /\ e.bountyAfterRestitution \in BOOLEAN
         /\ (e.pausedEpoch = NoEpoch \/ e.pausedEpoch \in Epochs)
         /\ e.expelled \subseteq Principals
         /\ e.rotationRequired \in BOOLEAN
         /\ e.freshGateDkgRequired \in BOOLEAN
    /\ \A dkg \in freshGateDkgEvents :
         /\ dkg.claim \in ClaimIds
         /\ dkg.fromEpoch = 0
         /\ dkg.toEpoch = 1
         /\ dkg.gateKey = GateKey(1)
         /\ dkg.rosterManifest = RosterManifest("FROST", 1)
         /\ dkg.expelled \subseteq Principals
    /\ slashApplyCount \in [ClaimIds -> 0..2]
    /\ operatorBondState \in
         [OperatorBondIds -> {"LOCKED", "SLASHED", "UNBONDED"}]
    /\ capacityEventLog \in Seq(CapacityEventUniverse)
    /\ paused \in BOOLEAN
    /\ pauseCauses \subseteq ClaimIds

ObjectiveHistoryIndependent ==
    [][objectiveSource # objectiveSource' => RecordObjectiveSourceFact]_vars

CheckpointSound ==
    \A ev \in Events :
      /\ (objectiveSource[ev] = UnknownSourceFact \/
            objectiveSource[ev] \in
              {ObjectiveFactFor(ev, v) : v \in EnabledSourceFactVariants})
      /\ (publicCheckpoint[ev] = NoCheckpoint \/
            /\ objectiveSource[ev] # UnknownSourceFact
            /\ publicCheckpoint[ev] =
                 AuthenticatedCheckpoint(ev, objectiveSource[ev]))

AcceptedReleaseBoundToClaim ==
    \A r \in FinalizedReleaseIds :
      /\ requests[r] = CanonicalRequestWithStableKey(r, acceptedAtEpoch[r])
      /\ requests[r].digest = ExpectedDigest(r, acceptedAtEpoch[r])

NoPolicyBypass ==
    \A r \in FinalizedReleaseIds : RequiredArtifactsPresent(r)

MlsagArtifactSound ==
    \A r \in FinalizedReleaseIds :
      DirectionOfRelease(r) = "ETH_TO_MOB" =>
        ValidArtifact(bundles[r].mlsag, "MLSAG", r, acceptedAtEpoch[r])

FrostArtifactSound ==
    \A r \in FinalizedReleaseIds :
      DirectionOfRelease(r) = "ETH_TO_MOB" =>
        ValidArtifact(bundles[r].frost, "FROST", r, acceptedAtEpoch[r])

EthereumMultisigArtifactSound ==
    \A r \in FinalizedReleaseIds :
      DirectionOfRelease(r) = "MOB_TO_ETH" =>
        ValidArtifact(bundles[r].ethMulti, "ETH_MULTI", r, acceptedAtEpoch[r])

WardenCertificateSound ==
    \A r \in FinalizedReleaseIds :
      ValidArtifact(bundles[r].warden, "WARDEN", r, acceptedAtEpoch[r])

AccountabilityCertificateSound ==
    \A r \in FinalizedReleaseIds :
      ValidArtifact(bundles[r].account, "ACCOUNT", r, acceptedAtEpoch[r])

SignerSlotsDistinct ==
    \A r \in FinalizedReleaseIds :
      \A a \in RequiredArtifacts(r) : Cardinality(SlotSet(a)) = 2

RoleThresholdsIndependent ==
    \A r \in FinalizedReleaseIds :
      CorrectDirectionBundle(r, bundles[r], acceptedAtEpoch[r])

ReleaseDigestBound ==
    \A r \in FinalizedReleaseIds :
      \A a \in RequiredArtifacts(r) : a.digest = requests[r].digest

ReleaseEpochSound ==
    \A r \in FinalizedReleaseIds :
      \A a \in RequiredArtifacts(r) :
        /\ bundleEpoch[r] = acceptedAtEpoch[r]
        /\ a.epoch = acceptedAtEpoch[r]
        /\ a.rosterManifest = RosterManifest(a.kind, acceptedAtEpoch[r])

HistoricalBondBinding ==
    \A r \in FinalizedReleaseIds :
      /\ bundles[r].warden.bondManifest = BondManifest(acceptedAtEpoch[r])
      /\ bundles[r].account.bondManifest = BondManifest(acceptedAtEpoch[r])
      /\ WardenApprovers(r) \subseteq BondedWardenRoster(acceptedAtEpoch[r])
      /\ AccountabilityApprovers(r) \subseteq
           BondedAccountRoster(acceptedAtEpoch[r])
      /\ \A a \in LiableApprovalSigners(r) :
           operatorBondState[OperatorBondId(a, acceptedAtEpoch[r])] \in
             {"LOCKED", "SLASHED"}

StableSourceNullifier ==
    \A r \in FinalizedReleaseIds : requests[r].sourceKey = StableSourceKey(r)

NullifierBijection ==
    /\ nullifierLog = ExpectedNullifierLog
    /\ \A n1, n2 \in nullifierLog : n1.key = n2.key => n1.release = n2.release

NoRejectedReleaseEffect ==
    \A r \in EnabledReleases :
      releaseStatus[r] = "REJECTED" =>
        /\ acceptedAtEpoch[r] = NoEpoch
        /\ ~\E n \in nullifierLog : n.release = r
        /\ ~\E e \in LiabilityAdmissionEvents : e.releaseId = r

EscrowOutputPartition ==
    \A p \in ValuePositions :
      \/ /\ valueState[p] = "AVAILABLE"
         /\ reservationOwner[p] = NoRelease
      \/ /\ valueState[p] = "RESERVED"
         /\ reservationOwner[p] \in EnabledReleases
         /\ releaseStatus[reservationOwner[p]] \in
              {"CAPACITY_APPROVED"}
      \/ /\ valueState[p] = "SPENT"
         /\ reservationOwner[p] \in FinalizedReleaseIds

ReleaseValueConserved ==
    \A r \in EnabledReleases :
      /\ (releaseStatus[r] = "CAPACITY_APPROVED" =>
            /\ valueState[ValuePositionOf(r)] = "RESERVED"
            /\ reservationOwner[ValuePositionOf(r)] = r)
      /\ (releaseStatus[r] = "FINALIZED" =>
            /\ valueState[ValuePositionOf(r)] = "SPENT"
            /\ reservationOwner[ValuePositionOf(r)] = r)

LiabilityBackingSound ==
    /\ \A e \in LiabilityAdmissionEvents :
         e.valuePositionIds = {ValuePositionOf(e.releaseId)}
    /\ \A e1, e2 \in LiabilityAdmissionEvents :
         e1.valuePositionIds \cap e2.valuePositionIds # {} =>
           e1.releaseId = e2.releaseId
    /\ \A r \in EnabledReleases :
         releaseStatus[r] \in {"LIABILITY_ADMITTED", "AUTHORIZED_PENDING",
                                "CAPACITY_APPROVED", "CANCELLED", "FINALIZED"}
         => \E e \in LiabilityAdmissionEvents : e.releaseId = r

InventoryInflowSound ==
    /\ \A e \in InventoryInflowEvents :
         /\ e.eventId[3] \in Events
         /\ FactRepresentsEscrowInflow(e.eventId[3])
         /\ e = SourceInflowCapacityEvent(e.eventId[3])
    /\ \A ev \in Events :
         Cardinality({e \in InventoryInflowEvents : e.eventId[3] = ev}) <= 1

UnmatchedReleaseHasAccountability ==
    \A r \in FinalizedReleaseIds :
      GroundTruthFault(r) =>
        /\ ValidArtifact(bundles[r].warden, "WARDEN", r, acceptedAtEpoch[r])
        /\ ValidArtifact(bundles[r].account, "ACCOUNT", r, acceptedAtEpoch[r])
        /\ WardenApprovers(r) \subseteq BondedWardenRoster(acceptedAtEpoch[r])
        /\ AccountabilityApprovers(r) \subseteq
             BondedAccountRoster(acceptedAtEpoch[r])
        /\ Cardinality(WardenApprovers(r)) >= K_WARDEN
        /\ Cardinality(AccountabilityApprovers(r)) >= K_ACCOUNT

ClaimEvidenceImmutable ==
    claimSubmissionLog =
      {ClaimSnapshot(c, claims[c]) :
         c \in {d \in EnabledClaimIds : claims[d].status # "EMPTY"}}

RejectionSound ==
    \A c \in EnabledClaimIds :
      claims[c].status = "REJECTED" =>
        /\ CorrectAdmissionDecision(c) # "ADMIT"
        /\ claims[c].verdict = NoVerdict

VerdictDeterministic ==
    \A c \in EnabledClaimIds :
      claims[c].status \in {"VERDICTED", "APPLIED"} =>
        /\ claims[c].verdict = CorrectVerdict(c).kind
        /\ claims[c].culprits = CorrectVerdict(c).culprits

VerdictSound ==
    \A c \in EnabledClaimIds :
      claims[c].status \in {"VERDICTED", "APPLIED"} =>
        \/ /\ claims[c].verdict = "OPERATOR"
           /\ ClaimGroundTruthFault(c)
           /\ claims[c].culprits = CorrectVerdict(c).culprits
        \/ /\ claims[c].verdict = "CHALLENGER"
           /\ ~ClaimGroundTruthFault(c)
           /\ claims[c].culprits = {claims[c].challenger}

CulpritSetExact ==
    \A c \in EnabledClaimIds :
      claims[c].status \in {"VERDICTED", "APPLIED"} =>
        claims[c].culprits = CorrectVerdict(c).culprits

SlashRequiresVerdict ==
    \A s \in slashEvents :
      /\ claims[s.claim].status = "APPLIED"
      /\ claims[s.claim].verdict \in {"OPERATOR", "CHALLENGER"}
      /\ s.actor \in claims[s.claim].culprits

SlashExactOnce ==
    /\ \A c \in EnabledClaimIds : slashApplyCount[c] <= 1
    /\ \A c \in EnabledClaimIds :
         claims[c].status = "APPLIED" =>
           /\ slashApplyCount[c] = 1
           /\ ProofConsumedBy(c)
           /\ SlashFor(c) = claims[c].culprits
           /\ IF claims[c].verdict = "OPERATOR"
                 THEN OperatorConsequence(c) \in consequenceEvents
                 ELSE ChallengerConsequence(c) \in consequenceEvents

NoRejectedClaimEffect ==
    \A c \in EnabledClaimIds :
      claims[c].status = "REJECTED" =>
        /\ SlashFor(c) = {}
        /\ slashApplyCount[c] = 0
        /\ ~ProofConsumedBy(c)
        /\ ~\E e \in consequenceEvents : e.claim = c
        /\ claims[c].challengeBondStatus # "SLASHED"
        /\ c \notin pauseCauses

NoUnsupportedAutomaticSlash ==
    \A c \in EnabledClaimIds :
      claims[c].status \in {"VERDICTED", "APPLIED"} =>
        AutoVerifiable(ProtocolVersion,
                       DirectionOfRelease(claims[c].target), claims[c].kind)

ChallengerFaultDoesNotPause ==
    \A c \in EnabledClaimIds :
      /\ claims[c].status = "APPLIED"
      /\ claims[c].verdict = "CHALLENGER"
      => /\ c \notin pauseCauses
         /\ claims[c].challengeBondStatus = "SLASHED"
         /\ ChallengerConsequence(c) \in consequenceEvents
         /\ \A s \in slashEvents : s.claim = c => s.role = "CHALLENGER"

OperatorFaultContainment ==
    \A c \in EnabledClaimIds :
      /\ claims[c].status = "APPLIED"
      /\ claims[c].verdict = "OPERATOR"
      => /\ c \in pauseCauses
         /\ (paused \/ FreshGateDkgEvent(c) \in freshGateDkgEvents)
         /\ SlashFor(c) = claims[c].culprits
         /\ OperatorConsequence(c) \in consequenceEvents
         /\ OperatorFaultCapacityEvent(c) \in
              {capacityEventLog[i] : i \in 1..Len(capacityEventLog)}

(***************************************************************************)
(* Liveness/reachability operators. They are not baseline safety invariants. *)
(***************************************************************************)

FalseEthToMobReleaseExists ==
    \E r \in FinalizedReleaseIds :
      DirectionOfRelease(r) = "ETH_TO_MOB" /\ GroundTruthFault(r)

FalseMobToEthReleaseExists ==
    \E r \in FinalizedReleaseIds :
      DirectionOfRelease(r) = "MOB_TO_ETH" /\ GroundTruthFault(r)

MalformedArtifactPublishedAndRejected ==
    \E r \in EnabledReleases :
      /\ releaseStatus[r] = "REJECTED"
      /\ bundleVariant[r] # "GOOD"

AutomaticProofMaterialAvailable(r) ==
    /\ r \in FinalizedReleaseIds
    /\ GroundTruthFault(r)
    /\ AutoVerifiable(ProtocolVersion, DirectionOfRelease(r), "FALSE_SOURCE")
    /\ publicCheckpoint[EventOfRelease(r)] =
         AuthenticatedCheckpoint(EventOfRelease(r),
                                 objectiveSource[EventOfRelease(r)])

UnmatchedReleaseHasAutomaticProof ==
    \A r \in EnabledReleases :
      /\ r \in FinalizedReleaseIds
      /\ GroundTruthFault(r)
      /\ AutoVerifiable(ProtocolVersion, DirectionOfRelease(r), "FALSE_SOURCE")
      ~> AutomaticProofMaterialAvailable(r)

=============================================================================
