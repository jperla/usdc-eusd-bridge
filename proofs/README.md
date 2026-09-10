# Running the bounded proof checks

From the repository root, with Python 3, curl and a JVM installed:

```sh
./scripts/setup-proofs.sh
./scripts/proofs.sh
```

The setup step downloads the official [TLA+ Tools v1.7.4 release](https://github.com/tlaplus/tlaplus/releases/tag/v1.7.4), containing TLC 2.19, and requires SHA-256 `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`. This is the exact artifact used for the checked runs. Existing mismatching files are refused and preserved. The JAR is an external dependency and remains uncommitted; a clean clone needs the setup step or an independently provisioned matching JAR. Java 21 is a suitable runtime.

To select installed tools explicitly:

```sh
JAVA_BIN=/absolute/path/to/java TLA2TOOLS_JAR=/absolute/path/to/tla2tools.jar ./scripts/proofs.sh
```

`JAVA_HOME` is also supported. `TLC_WORKERS` defaults to one in the shared harness. Setup verifies the pinned artifact; the proof runner permits an explicit alternate JAR for toolchain experiments, so such runs must record their own version and hash. The checked model and mutation runs use isolated temporary working directories. Java may require permission to create its local management socket in a restricted sandbox.

`scripts/proofs.sh` executes the **18 `proofs/tla/run_*.py` runners**, including their coverage and mutation checks. It does **not** execute every historical `.tla`, `.cfg`, `check_*.py`, or other analysis file in this directory. Its success therefore applies to the configurations those runners select, not to every proof-like artifact in the repository.

These are finite-state model checks and counterexample witnesses. Authenticated output decoding, cryptographic primitives, implementation refinement and operational ceremony assumptions require separate evidence. Claim retry success is reachable, not guaranteed eventually. Attribution thresholds additionally depend on ownership and independent share material; the correlated-share scenario demonstrates why counting attribution slots does not establish that threshold.

## Authenticated deployment replay

`DeploymentReplay.tla` models chain/escrow/namespace destinations authenticated
inside v2 return memos, legacy rejection, and persistent replay state per
chain+escrow. The runner checks three invariants, successful-payment coverage,
six guard-removal matrices and a source mutation that substitutes relay metadata
for the authenticated domain. The baseline generates 3,328 states. Hash/memo
integrity and persistence of an existing escrow's replay mapping are assumptions;
this does not prove implementation refinement or live-chain finality.

## Authenticated signing packets

`PacketAcceptance.tla` models the acceptance boundary in
`crates/two-cohort/src/mlsag_wire.rs`: a caller supplies the trusted identity,
seat, phase, session and (in round two) transcript. The baseline generates
1,027 states over two values for each identity/seat/phase/session/transcript
class and valid/invalid signature, domain, encoding and length classes.

Nine invariants separately check identity, signature, seat, phase, session,
transcript, protocol domain, canonical encoding and exact length. Both rounds
must be reachable; round one deliberately has no round-two transcript yet.
Each guard removal must violate its named invariant. A source mutation makes
the packet select its own session context while leaving guards enabled; another
rejects every packet, showing that safety alone is vacuous and the positive-path
probes distinguish that model. This abstracts cryptographic verification and
assumes caller enrollment and collision-resistant contexts. It does not establish
signature security, network-service behavior, roster uniqueness, or Rust refinement.

## Durable commitment publication

`DurablePublication.tla` composes fresh-slot reservation, context binding,
independent anchor acknowledgement, crash, one-write reconciliation, rollback,
and publication. Its baseline generates 751 states for one fixed session/seat,
up to four durable writes and two attempted publications. It checks at most one
publication and that a durable context binding was anchored before publication.

Positive probes require ordinary publication, recovery before publication, and
publication after a lost acknowledgement. Loss can occur before or after the
anchor commits. Removing duplicate protection, rollback protection (both the
initial comparison and anchor continuation check), or publication ordering must
produce the named counterexample. A source mutation publishes after anchoring
only the reservation, before binding, and must also fail. Both source mutations
in these new runners alter the TLA+ model, not Rust source.

The anchor is honest and independent, histories abstract collision-free hashes,
and writes are already durable. Torn-write handling remains covered by the Rust
journal tests; hardware durability and multi-process service operation are not
proved. A crash after binding can permanently burn this session/seat without
publication: the model proves safety and bounded successful paths, not general
liveness or a production recovery service.
