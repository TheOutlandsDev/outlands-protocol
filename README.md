# OUTLANDS Protocol

OUTLANDS // BEYOND THE WALL

An account-based proof-of-work protocol research project with an original Rust reference implementation. This source showcase exposes actual implementation code for review: canonical bytes, strict cryptography integration, deterministic account transitions, block/chain validation, storage adapters, bounded P2P sessions, and local node orchestration.

**Status: research/development source; no deployed network or production wallet is claimed.** Mainnet parameters remain gated. The wallet/keystore work, private review packets, runtime state and standalone C/Python reference tools are excluded. This is an eight-crate selection from a larger development workspace. [Export scope](EXPORT-SCOPE.md) describes the selection and validation limits.

## What the implementation addresses

Consensus results must follow exact bytes and checked state transitions rather than a database engine, serializer or execution environment. The implementation separates canonical decoding, cryptographic verification, deterministic state changes and storage activation. Malformed input is rejected at explicit boundaries; operational failure is distinguished from consensus-invalid data.

```text
bounded canonical transaction/block bytes
    -> out-codec: exact layouts, tags, lengths and rejection
    -> out-crypto: domain-separated BLAKE3 and strict Ed25519 integration
    -> out-state / out-consensus: checked state, ancestry, work and block rules
    -> out-storage: validated commit, branch storage, activation and recovery
    -> out-node: bounded orchestration and local operator control

out-p2p: transport-independent framing, sessions and request correlation
```

The core tests exercise actual library code, not a mock blockchain. The higher-level source includes memory transports/harnesses, redb/RocksDB adapters and Unix-domain operator utilities. There is no TCP/UDP peer transport, public HTTP/RPC service, web frontend, cloud deployment or operational PostgreSQL/Redis implementation in this export.

## Component map and evidence

| Component | Implementation | Example review/test target | Fresh result |
| --- | --- | --- | --- |
| Typed bounds and arithmetic | [out-primitives](crates/out-primitives/src/lib.rs) | Nonce overflow, money cap, exact work and wide retarget arithmetic | 7 tests passed |
| Canonical byte format | [out-codec](crates/out-codec/src/lib.rs) | Exact transaction/header vectors; trailing data, count/order/length rejection | 12 tests passed |
| Cryptography integration | [out-crypto](crates/out-crypto/src/lib.rs) | Domain-separated hashing, strict point/scalar checks, changed-digest rejection | 7 tests passed |
| Account state | [out-state](crates/out-state/src/lib.rs) | Self-send, nonce maximum, state roots, transfer/reward checks | 6 tests passed |
| Block and chain logic | [out-consensus](crates/out-consensus/src/lib.rs), [block](crates/out-consensus/src/block.rs), [chain](crates/out-consensus/src/chain.rs) | Validation order, ancestry, replay, work, branch planning and block commits | 43 tests passed |
| P2P framing/session | [out-p2p](crates/out-p2p/src/lib.rs), [session](crates/out-p2p/src/session.rs) | Correlation, handshake bounds, checksums, timeout and malformed-frame behavior | 31 tests passed |
| Storage | [out-storage](crates/out-storage/src/lib.rs), [conformance](crates/out-storage/src/conformance.rs) | In-memory reference, redb/RocksDB adapters, prepare/publish recovery contracts | Source reviewed; not freshly built/tested in this export |
| Node/control backend | [out-node](crates/out-node/src/lib.rs), [dispatcher](crates/out-node/src/dispatcher.rs), [operator protocol](crates/out-node/OPERATOR-PROTOCOL.md) | Sync, bounded mempool/mining coordination, local authenticated Unix IPC, process test source | Source reviewed; process/native-backend acceptance not repeated |

## Reproduce the bounded checks

The project pins Rust **1.98.0** in [rust-toolchain.toml](rust-toolchain.toml). The review used `rustc 1.98.0 (88d9e12ae 2026-08-18)`, an already installed toolchain, cached registry dependencies and a build directory outside the export. No dependency was downloaded or installed. With that toolchain and the locked dependencies already available:

```sh
cargo test --offline --locked --lib \
  -p out-primitives -p out-codec -p out-crypto \
  -p out-state -p out-consensus -p out-p2p -j 2
cargo fmt --all -- --check
```

Measured on 2026-10-23: **106 tests passed, 0 failed, 0 ignored**, across the six pure-library suites above. All exported Rust files passed an explicit Rust 1.98.0 rustfmt check. [Validation details](VALIDATION.md) distinguish fresh execution from historical statements retained in design documents. An offline cache miss is a missing prerequisite; these commands do not authorize an installation step.

For a focused example:

```sh
cargo test --offline --locked -p out-state --lib self_send_loses_only_fee
cargo test --offline --locked -p out-codec --lib exact_decode_round_trips_and_rejects_trailing_byte
```

These exercise the original state-transition and codec routines with synthetic fixtures. The first asserts the self-send balance/nonce result; the second checks exact decode/reencode and rejects a trailing byte. The fixtures and testnet/devnet genesis bytes are fictional development material. Fixed test keys must never secure funds or services. No live account, balance, key or production state is included.

The full workspace is intentionally not covered by the 106-test claim. Building/testing `out-storage` and `out-node` also requires the native redb/RocksDB build closure and may create disposable database files or Unix sockets in their tests. Those operations were not performed for this export. Do not interpret retained process-test source or historical counts as fresh acceptance. No node, wallet, miner service or listener was started during this review.

## Engineering tradeoffs and known limits

- Language-neutral wire rules and explicit domain separation keep consensus independent of Rust layout, Serde/JSON and database serialization.
- Monetary/work calculations use checked fixed-width integers. The tests cover selected boundaries; they do not prove all economic or consensus properties.
- Storage accepts validated commits and separates stored branches from canonical activation. Native-backend crash/recovery behavior needs its own fresh acceptance run.
- P2P/runtime components use explicit caller-driven bounds and clocks. Memory transports provide deterministic integration fixtures; a production peer network is not implemented here.
- Cryptographic primitives come from upstream libraries. Local strictness wrappers and negative tests are not an independent cryptographic audit.
- There is no browser frontend in the original workspace. Backend, protocol, storage and testing experience can be reviewed directly without inventing a full-stack product or deployment history.

## Contribution and provenance

The project owner reports originating the ideas and using AI tools to accelerate coding, testing and debugging. Historical development records show this project was commissioned as an original OUT design and contain creation/update calls for every exported crate file. Implementation and documentation were developed with substantial AI assistance; this repository does not claim unaided or line-by-line human authorship.

The owner confirmed ownership of the original files before this export. The review examined the source inventory, development records, external references, existing license declarations and privacy-sensitive content. [Provenance and attribution](PROVENANCE.md), the [dependency inventory](DEPENDENCIES.md) and [source map](SOURCE-MAP.json) describe the evidence and its limits. Original Rust files are copied unchanged. The root workspace member list and lockfile exclude wallet work; unused locked packages were removed offline without upgrades. Export documentation is new or carries an explicit historical-status banner.

Existing package metadata (`MIT OR Apache-2.0`, `publish=false`) is preserved. This export assigns no new repository-wide license and bundles no upstream dependency source or compiled binaries. Upstream standards and library authors retain their attribution and terms. No audit, mainnet/testnet deployment, financial safety or production experience is asserted by publishing this source.
