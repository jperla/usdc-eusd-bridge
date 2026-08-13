--------------------------- MODULE M5SealedResponse ---------------------------
(*******************************************************************************
Bounded safety model for the M5 sealed-response handshake only.

The model has one nonce slot and exactly two distinct request digests.  It
tracks the vault, opaque receipt, operation-authority persistence/anchor,
release certificate, and raw-response observation as separate facts.  Exact
retries and crashes are explicit no-op/stutter actions.

Assumptions:
  * a receipt/certificate/request token represents already-canonical bytes;
  * an honest attestation verifier accepts only the modeled exact token;
  * durable Boolean transitions do not roll back inside this model; and
  * the operation authority has already authorized the complete sibling vector.

Non-claims:
  * no FROST/MLSAG equation, nonce entropy/secrecy, HSM, filesystem, replica,
    finality, liveness, archival, or MobileCoin consensus behavior is modeled;
  * the model does not prove the assumptions above; and
  * stuttering models a crash/lost acknowledgement only at an atomic boundary,
    not a torn write or unsafe recovery procedure.

Bug is a one-defect selector.  Each mutant must violate one named invariant.
*******************************************************************************)

EXTENDS FiniteSets, Integers, TLC

CONSTANT Bug

BugKinds == {"NONE", "CERT_WITHOUT_ANCHOR", "REBIND_CHANGED_REQUEST"}
ASSUME Bug \in BugKinds

RequestDigests == {"request-A", "request-B"}
NoRequest == "NO_REQUEST"
MaybeRequest == RequestDigests \cup {NoRequest}
ReceiptOf(request) == <<"sealed-receipt", request>>
ReceiptIds == {ReceiptOf(request) : request \in RequestDigests}
NoReceipt == <<"NO_RECEIPT">>
MaybeReceipt == ReceiptIds \cup {NoReceipt}

VaultStates == {"Absent", "Committed", "Bound", "Sealed", "Released"}

StateRank(state) ==
  CASE state = "Absent"    -> 0
    [] state = "Committed" -> 1
    [] state = "Bound"     -> 2
    [] state = "Sealed"    -> 3
    [] state = "Released"  -> 4

StatePrefix(state) == {candidate \in VaultStates :
                         StateRank(candidate) <= StateRank(state)}

VARIABLES
  vaultState,
  visitedStates,
  boundRequest,
  sealedRequest,
  receiptRequest,
  anchoredRequest,
  certificateRequest,
  rawRequest,
  sealedReceipt,
  persistedReceipt,
  anchoredReceipt,
  certificateReceipt,
  boundHistory,
  sealedHistory,
  receiptObservable,
  receiptPersisted,
  authorityAnchored,
  certificateIssued,
  rawObserved

vars ==
  <<vaultState, visitedStates, boundRequest, sealedRequest, receiptRequest,
    anchoredRequest, certificateRequest, rawRequest, sealedReceipt,
    persistedReceipt, anchoredReceipt, certificateReceipt, boundHistory,
    sealedHistory, receiptObservable, receiptPersisted, authorityAnchored,
    certificateIssued, rawObserved>>

Init ==
  /\ vaultState = "Absent"
  /\ visitedStates = {"Absent"}
  /\ boundRequest = NoRequest
  /\ sealedRequest = NoRequest
  /\ receiptRequest = NoRequest
  /\ anchoredRequest = NoRequest
  /\ certificateRequest = NoRequest
  /\ rawRequest = NoRequest
  /\ sealedReceipt = NoReceipt
  /\ persistedReceipt = NoReceipt
  /\ anchoredReceipt = NoReceipt
  /\ certificateReceipt = NoReceipt
  /\ boundHistory = {}
  /\ sealedHistory = {}
  /\ receiptObservable = FALSE
  /\ receiptPersisted = FALSE
  /\ authorityAnchored = FALSE
  /\ certificateIssued = FALSE
  /\ rawObserved = FALSE

CommitNonce ==
  /\ vaultState = "Absent"
  /\ vaultState' = "Committed"
  /\ visitedStates' = visitedStates \cup {"Committed"}
  /\ UNCHANGED <<boundRequest, sealedRequest, receiptRequest,
                 anchoredRequest, certificateRequest, rawRequest,
                 sealedReceipt, persistedReceipt, anchoredReceipt,
                 certificateReceipt,
                 boundHistory, sealedHistory, receiptObservable,
                 receiptPersisted, authorityAnchored, certificateIssued,
                 rawObserved>>

BindRequest(request) ==
  /\ request \in RequestDigests
  /\ vaultState = "Committed"
  /\ vaultState' = "Bound"
  /\ visitedStates' = visitedStates \cup {"Bound"}
  /\ boundRequest' = request
  /\ boundHistory' = boundHistory \cup {request}
  /\ UNCHANGED <<sealedRequest, receiptRequest, anchoredRequest,
                 certificateRequest, rawRequest, sealedReceipt,
                 persistedReceipt, anchoredReceipt, certificateReceipt, sealedHistory,
                 receiptObservable, receiptPersisted, authorityAnchored,
                 certificateIssued, rawObserved>>

(* Deliberate mutant: a changed digest replaces the durable binding in place. *)
RebindChangedRequest(request) ==
  /\ Bug = "REBIND_CHANGED_REQUEST"
  /\ request \in RequestDigests
  /\ vaultState = "Bound"
  /\ request # boundRequest
  /\ boundRequest' = request
  /\ boundHistory' = boundHistory \cup {request}
  /\ UNCHANGED <<vaultState, visitedStates, sealedRequest, receiptRequest,
                 anchoredRequest, certificateRequest, rawRequest, sealedReceipt,
                 persistedReceipt, anchoredReceipt, certificateReceipt,
                 sealedHistory, receiptObservable, receiptPersisted,
                 authorityAnchored, certificateIssued, rawObserved>>

SealResponse ==
  /\ vaultState = "Bound"
  /\ vaultState' = "Sealed"
  /\ visitedStates' = visitedStates \cup {"Sealed"}
  /\ sealedRequest' = boundRequest
  /\ receiptRequest' = boundRequest
  /\ sealedReceipt' = ReceiptOf(boundRequest)
  /\ sealedHistory' = sealedHistory \cup {boundRequest}
  /\ UNCHANGED <<boundRequest, anchoredRequest, certificateRequest,
                 rawRequest, persistedReceipt, anchoredReceipt,
                 certificateReceipt, boundHistory, receiptObservable,
                 receiptPersisted, authorityAnchored, certificateIssued,
                 rawObserved>>

ObserveOpaqueReceipt ==
  /\ vaultState = "Sealed"
  /\ receiptRequest = sealedRequest
  /\ sealedReceipt = ReceiptOf(sealedRequest)
  /\ receiptObservable' = TRUE
  /\ UNCHANGED <<vaultState, visitedStates, boundRequest, sealedRequest,
                 receiptRequest, anchoredRequest, certificateRequest,
                 rawRequest, sealedReceipt, persistedReceipt, anchoredReceipt,
                 certificateReceipt, boundHistory, sealedHistory, receiptPersisted,
                 authorityAnchored, certificateIssued, rawObserved>>

PersistExactReceipt ==
  /\ receiptObservable
  /\ receiptRequest = sealedRequest
  /\ receiptPersisted' = TRUE
  /\ persistedReceipt' = sealedReceipt
  /\ UNCHANGED <<vaultState, visitedStates, boundRequest, sealedRequest,
                 receiptRequest, anchoredRequest, certificateRequest,
                 rawRequest, sealedReceipt, anchoredReceipt, certificateReceipt,
                 boundHistory, sealedHistory, receiptObservable,
                 authorityAnchored, certificateIssued, rawObserved>>

AnchorExactReceipt ==
  /\ receiptPersisted
  /\ authorityAnchored' = TRUE
  /\ anchoredRequest' = receiptRequest
  /\ anchoredReceipt' = persistedReceipt
  /\ UNCHANGED <<vaultState, visitedStates, boundRequest, sealedRequest,
                 receiptRequest, certificateRequest, rawRequest, sealedReceipt,
                 persistedReceipt, certificateReceipt, boundHistory, sealedHistory,
                 receiptObservable, receiptPersisted,
                 certificateIssued, rawObserved>>

IssueReleaseCertificate ==
  /\ receiptPersisted
  /\ IF Bug = "CERT_WITHOUT_ANCHOR"
        THEN TRUE
        ELSE /\ authorityAnchored
             /\ anchoredRequest = receiptRequest
  /\ certificateIssued' = TRUE
  /\ certificateRequest' = receiptRequest
  /\ certificateReceipt' = persistedReceipt
  /\ UNCHANGED <<vaultState, visitedStates, boundRequest, sealedRequest,
                 receiptRequest, anchoredRequest, rawRequest, sealedReceipt,
                 persistedReceipt, anchoredReceipt, boundHistory, sealedHistory,
                 receiptObservable, receiptPersisted,
                 authorityAnchored, rawObserved>>

(* The vault durably records RELEASED before raw bytes cross its boundary. *)
MarkReleased ==
  /\ vaultState = "Sealed"
  /\ certificateIssued
  /\ certificateRequest = sealedRequest
  /\ vaultState' = "Released"
  /\ visitedStates' = visitedStates \cup {"Released"}
  /\ UNCHANGED <<boundRequest, sealedRequest, receiptRequest,
                 anchoredRequest, certificateRequest, rawRequest,
                 sealedReceipt, persistedReceipt, anchoredReceipt,
                 certificateReceipt, boundHistory, sealedHistory,
                 receiptObservable, receiptPersisted, authorityAnchored,
                 certificateIssued, rawObserved>>

(* A crash may stutter between MarkReleased and this observable effect. *)
ObserveRawResponse ==
  /\ vaultState = "Released"
  /\ certificateIssued
  /\ certificateRequest = sealedRequest
  /\ rawObserved' = TRUE
  /\ rawRequest' = sealedRequest
  /\ UNCHANGED <<vaultState, visitedStates, boundRequest, sealedRequest, receiptRequest,
                 anchoredRequest, certificateRequest, sealedReceipt,
                 persistedReceipt, anchoredReceipt, certificateReceipt, boundHistory,
                 sealedHistory, receiptObservable, receiptPersisted,
                 authorityAnchored, certificateIssued>>

(* Exact request retry is accepted only for the already-bound digest. *)
ExactRequestRetry(request) ==
  /\ request \in RequestDigests
  /\ boundRequest = request
  /\ StateRank(vaultState) >= StateRank("Bound")
  /\ UNCHANGED vars

(* A changed request is an explicit state-preserving conflict in the honest model. *)
RejectChangedRequest(request) ==
  /\ Bug # "REBIND_CHANGED_REQUEST"
  /\ request \in RequestDigests
  /\ StateRank(vaultState) >= StateRank("Bound")
  /\ request # boundRequest
  /\ UNCHANGED vars

(* Other exact retries/lost acknowledgements repeat durable facts only. *)
ExactRetry ==
  \/ /\ receiptObservable
     /\ UNCHANGED vars
  \/ /\ receiptPersisted
     /\ UNCHANGED vars
  \/ /\ authorityAnchored
     /\ UNCHANGED vars
  \/ /\ certificateIssued
     /\ UNCHANGED vars
  \/ /\ rawObserved
     /\ UNCHANGED vars

(* Crash, restart, timeout, or message loss at an already atomic boundary. *)
CrashOrStutter == UNCHANGED vars

Next ==
  \/ CommitNonce
  \/ \E request \in RequestDigests : BindRequest(request)
  \/ \E request \in RequestDigests : RebindChangedRequest(request)
  \/ \E request \in RequestDigests : ExactRequestRetry(request)
  \/ \E request \in RequestDigests : RejectChangedRequest(request)
  \/ SealResponse
  \/ ObserveOpaqueReceipt
  \/ PersistExactReceipt
  \/ AnchorExactReceipt
  \/ IssueReleaseCertificate
  \/ MarkReleased
  \/ ObserveRawResponse
  \/ ExactRetry
  \/ CrashOrStutter

Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------------
(* Required safety predicates. *)

TypeOK ==
  /\ vaultState \in VaultStates
  /\ visitedStates \subseteq VaultStates
  /\ boundRequest \in MaybeRequest
  /\ sealedRequest \in MaybeRequest
  /\ receiptRequest \in MaybeRequest
  /\ anchoredRequest \in MaybeRequest
  /\ certificateRequest \in MaybeRequest
  /\ rawRequest \in MaybeRequest
  /\ sealedReceipt \in MaybeReceipt
  /\ persistedReceipt \in MaybeReceipt
  /\ anchoredReceipt \in MaybeReceipt
  /\ certificateReceipt \in MaybeReceipt
  /\ boundHistory \subseteq RequestDigests
  /\ sealedHistory \subseteq RequestDigests
  /\ receiptObservable \in BOOLEAN
  /\ receiptPersisted \in BOOLEAN
  /\ authorityAnchored \in BOOLEAN
  /\ certificateIssued \in BOOLEAN
  /\ rawObserved \in BOOLEAN

ReceiptObservationSound ==
  receiptObservable =>
    /\ StateRank(vaultState) >= StateRank("Sealed")
    /\ receiptRequest = sealedRequest
    /\ sealedReceipt = ReceiptOf(sealedRequest)
    /\ sealedRequest \in RequestDigests

CertificateRequiresExactAnchor ==
  certificateIssued =>
    /\ receiptPersisted
    /\ authorityAnchored
    /\ certificateRequest = receiptRequest
    /\ anchoredRequest = receiptRequest
    /\ receiptRequest = sealedRequest
    /\ certificateReceipt = persistedReceipt
    /\ persistedReceipt = sealedReceipt
    /\ anchoredReceipt = sealedReceipt

RawObservationSound ==
  rawObserved =>
    /\ vaultState = "Released"
    /\ receiptPersisted
    /\ authorityAnchored
    /\ certificateIssued
    /\ rawRequest = sealedRequest
    /\ certificateRequest = sealedRequest
    /\ anchoredRequest = sealedRequest
    /\ receiptRequest = sealedRequest
    /\ sealedRequest \in RequestDigests
    /\ certificateReceipt = sealedReceipt
    /\ anchoredReceipt = sealedReceipt
    /\ persistedReceipt = sealedReceipt

SingleRequestBinding ==
  /\ Cardinality(boundHistory \cup sealedHistory) <= 1
  /\ sealedRequest \in RequestDigests => sealedRequest = boundRequest

StateMonotonic == visitedStates = StatePrefix(vaultState)

=============================================================================
