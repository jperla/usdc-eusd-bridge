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

`scripts/proofs.sh` executes the **14 `proofs/tla/run_*.py` runners**, including their coverage and mutation checks. It does **not** execute every historical `.tla`, `.cfg`, `check_*.py`, or other analysis file in this directory. Its success therefore applies to the configurations those runners select, not to every proof-like artifact in the repository.

These are finite-state model checks and counterexample witnesses. Authenticated output decoding, cryptographic primitives, implementation refinement and operational ceremony assumptions require separate evidence. Claim retry success is reachable, not guaranteed eventually. Attribution thresholds additionally depend on ownership and independent share material; the correlated-share scenario demonstrates why counting attribution slots does not establish that threshold.
