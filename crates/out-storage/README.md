> Export scope: dated verification statements below are historical. See [current export scope](../../EXPORT-SCOPE.md) and root VALIDATION.md for fresh results and excluded tools.

# OUT consensus storage

`out-storage` defines the narrow boundary between pure consensus validation and durable storage. Storage engines do not define canonical encoding, state roots, transaction validity, work, or chain selection.

## Required backend behavior

Every persistent adapter MUST:

- accept only `ValidatedBlockCommit` values produced by `out-consensus`;
- atomically store the exact block bytes, validated metadata, branch state, account deltas, transaction IDs, and issued supply;
- keep a stored fork noncanonical until an explicit, verified reorganization is applied;
- atomically roll back the detach list and apply the attach list in the specified order;
- make canonical height, transaction, account, supply, and tip indices visible together;
- reject reads while recovery is required, so no mixed pre/post-transaction view is observable;
- recover a prepared-but-unpublished mutation to the old state;
- recover a published mutation to the new state;
- validate persisted records before exposing them as consensus inputs;
- sort by specified consensus bytes, never database iteration order; and
- produce identical observable results regardless of engine, filesystem order, process scheduling, or cache state.

PostgreSQL and Redis MUST NOT implement or substitute for this interface. They remain nonauthoritative operational services.

## Storage schema v0

Storage schema bytes are operational and MUST NOT enter any consensus hash. Switching databases or rebuilding every record from canonical blocks MUST preserve all consensus results.

All multibyte integers below are unsigned big-endian. Tags and widths are explicit; Rust layout, Serde, bincode, JSON, native endianness, `usize`, floats, and implicit enum discriminants are forbidden.

### Keys

| Tag | Key | Exact bytes | Value record kind |
|---:|---|---|---|
| `00` | manifest | `tag` | Manifest |
| `01` | recovery marker | `tag` | Recovery |
| `10` | visible block | `tag || block_id[32]` | BlockVisibility |
| `11` | block bytes | `tag || block_id[32]` | Block |
| `12` | block transaction | `tag || block_id[32] || index:u32` | TransactionId |
| `13` | branch account | `tag || block_id[32] || recipient[33]` | Account |
| `14` | account delta | `tag || block_id[32] || recipient[33]` | AccountDelta |
| `15` | content-addressed state node | `tag || node_hash[32]` | StateNode |
| `20` | generation seal | `tag || generation:u64` | GenerationSeal |
| `21` | canonical tip | `tag || generation:u64` | CanonicalTip |
| `22` | canonical height | `tag || generation:u64 || height:u64` | BlockId |
| `23` | canonical transaction | `tag || generation:u64 || transaction_id[32]` | BlockId |
| `24` | canonical account | `tag || generation:u64 || recipient[33]` | Account |

Key decoders MUST reject unknown tags, wrong lengths, trailing bytes, and unsupported recipient versions. Prefix iteration is only discovery: an adapter MUST decode every key and sort by the complete encoded key before computing a generation digest or rebuilding deterministic state.

### Record envelope

Every value has this exact envelope:

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `OUTS` |
| 4 | 2 | schema version | exactly `0` |
| 6 | 1 | record-kind tag | explicit tag from `StorageRecordKind` |
| 7 | 1 | flags | exactly zero in schema v0 |
| 8 | 4 | payload length | at most 2,097,382 bytes |
| 12 | variable | payload | exactly the declared length |
| 12+length | 32 | checksum | BLAKE3 `derive_key` result below |

The checksum preimage is every envelope byte from offset 0 through the final payload byte. The exact BLAKE3 context string is `OUT/storage-record-checksum/v0`. This operational checksum is not a consensus hash.

Decoders MUST check the total input bound, magic, schema, known kind, zero flags, and payload bound before interpreting or allocating for the payload. They MUST then reject truncation, trailing bytes, and checksum mismatch. Unknown schema versions fail closed; automatic interpretation as schema v0 is forbidden.

Typed payloads currently fixed by code are:

- Manifest: `chain_id[32] || network_id:u32 || genesis_commitment[32] || genesis_block_id[32] || active_generation:u64 || active_tip[32]` (140 bytes).
- Recovery: `state:u8 || mutation:u8 || reserved:u16 || base_generation:u64 || candidate_generation:u64 || subject_block_id[32] || expected_tip[32]` (84 bytes). Reserved is zero.
- GenerationSeal: `generation:u64 || tip[32] || state_root[32] || issued_supply:u128 || height_count:u64 || transaction_count:u64 || account_count:u64 || records_digest[32]` (144 bytes). Supply MUST NOT exceed `MAX_MONEY`.

Block payloads MUST be exact canonical OUT block bytes and MUST reproduce the block ID in their key. TransactionId and BlockId payloads are exactly 32 bytes. Account payloads are `balance:u64 || nonce:u64`; absent `(0,0)` accounts MUST NOT be stored. AccountDelta payloads are `before_balance:u64 || before_nonce:u64 || after_balance:u64 || after_nonce:u64`. CanonicalTip payloads are `block_id[32] || state_root[32] || issued_supply:u128`. StateNode payloads MUST carry a node-kind byte followed by the exact consensus leaf or internal-node preimage; the key hash MUST be recomputed with the corresponding state domain before acceptance.

### Generation seal

The generation digest excludes its own seal record. Input records MUST be strictly increasing by complete encoded key with no duplicates. For each record, hash:

```text
00 || key_length:u16 || key || value_length:u32 || value
```

After the last record, hash `ff || record_count:u64`. The exact BLAKE3 context is `OUT/storage-generation-digest/v0`. Keys are bounded to 80 bytes and values to the record payload cap before hashing. Counts in the seal MUST match the decoded canonical height, transaction, and nonabsent-account records. The adapter MUST additionally recompute the state root, issued supply, block ancestry, targets, PoW, and cumulative work; a matching operational digest alone is never sufficient.

### Prepare, publish, and recovery

Every mutation uses `candidate_generation = base_generation + 1`; overflow rejects the mutation. A store-block mutation uses the new block ID as `subject` and keeps `expected_tip` unchanged. A reorganization uses the winning tip as both `subject` and `expected_tip`.

```text
1. Read and validate the clean manifest, marker, active seal, and active state.
2. Atomically write Prepared(base, candidate, subject, expected_tip).
3. Build hidden candidate-generation records and immutable block/state records.
4. Decode and validate every candidate record; recompute counts, digest, roots, work, and indices.
5. Atomically publish the candidate manifest/tip, any block-visibility key, and Published marker.
6. Atomically replace Published with Clean(candidate, expected_tip).
7. Garbage-collect unreachable old/candidate records only after Clean is durable.
```

While the marker is Prepared or Published, every consensus read and mutation MUST return a local recovery-required error.

- Prepared recovery MUST verify that the manifest still names the base generation, discard the hidden candidate and unpublished subject records, and atomically restore Clean for the base generation.
- Published recovery MUST verify that the manifest names the candidate generation and expected tip, fully validate the candidate seal/state, and atomically finalize Clean for the candidate.
- Any marker/manifest mismatch, missing record, checksum failure, unknown schema, count mismatch, root mismatch, or work mismatch is local durable-state corruption. It MUST NOT be classified as a consensus-invalid block or repaired by guessing.

Engine-native transactions MAY realize each atomic step differently, but the visible states and recovery outcomes MUST match this protocol exactly.

## Reusable conformance suite

The optional `conformance` feature exposes:

- `assert_consensus_storage_conformance`, covering inert fork storage, duplicate rejection, bounded best-chain planning, branch-local snapshots, rollback, and forward application;
- `assert_recovery_conformance`, covering prepare/publish interruption during block storage and reorganization, fail-closed reads, and exact recovery outcomes; and
- `FaultInjectableConformanceStore`, the test-only fault boundary an adapter implements for crash simulation.

An adapter test supplies a factory that creates a fresh backend from the pinned devnet genesis passed by the suite. The factory MAY choose a unique temporary database path. Tests MUST NOT use production data directories.

```rust,ignore
assert_consensus_storage_conformance(|genesis, metadata| {
    AdapterUnderTest::create(unique_temporary_path(), genesis, metadata, &[], 0)
});
```

The in-memory, redb, and RocksDB reference backends run both suites in the normal workspace test gate.

## Persistent adapter status

The redb reference adapter is implemented with exact-pinned `redb` 4.2.0. It uses immediate-durability engine transactions for every prepare, publish, finalize, and recovery boundary. The RocksDB reference adapter is implemented with exact-pinned `rocksdb` 0.25.0, default compression features disabled, the WAL enabled, and synchronous write batches at the same boundaries. RocksDB opens with paranoid checks enabled. Neither adapter's native representation is exposed to consensus code.

Both adapters use the same canonical record builder, record-envelope validation, deterministic replay, generation verification, and marker/manifest rules. On open they validate every storage envelope, reconstruct every visible branch from canonical block bytes through `out-consensus`, restore the explicitly published canonical tip, recompute the active generation, and reject any mismatch rather than trusting cached metadata. redb additionally runs its engine integrity check; RocksDB performs its native open/recovery with paranoid checks before the shared validation begins.

Each adapter's test gate covers the shared core/recovery suites, normal close/reopen, prepared rollback after reopen, published finalization after reopen, published fork-reorganization recovery after reopen, and checksum-corruption rejection. Test databases use unique temporary paths and are removed afterward. Passing the same behavioral suite demonstrates storage-interface interchangeability; it does not make engine files mutually readable.

This is a correctness-first archival reference implementation. It currently retains old generations and rebuilds in-memory validated state from all visible canonical block bytes on open. Pruning, garbage collection, compaction policy, incremental startup acceleration, and production performance qualification remain future work and MUST NOT change observable consensus results.

RocksDB's Rust binding generates native bindings during compilation and therefore requires a compatible Clang/libclang build environment. This is a build-time requirement only and has no role in consensus or runtime storage results.
