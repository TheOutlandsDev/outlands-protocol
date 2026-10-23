> Export scope: dated verification statements below are historical. See [current export scope](../EXPORT-SCOPE.md) and root VALIDATION.md for fresh results and excluded tools.

# OUT Consensus v0 security invariants

Each invariant is normative. A release MUST include positive, negative, boundary, differential, and crash-recovery tests sufficient to demonstrate it. “Node” means every consensus implementation, not only Rust.

## 1. Canonical bytes and parsing

1. **Single accepted encoding:** An accepted transaction, header, block, state record, snapshot, and typed P2P payload has exactly one canonical byte encoding. Decode-then-encode MUST equal input.
2. **No alternate transaction representation:** No two accepted byte strings may represent the same canonical transaction fields/authorization. Fixed widths, strict auth decoding, and no trailing bytes enforce this.
3. **No language serializer authority:** Serde, bincode, JSON, Protobuf, ABI/struct layout, `usize`, native endian, implicit enum discriminants, and floating point MUST NOT produce/parse consensus bytes.
4. **No platform order:** Hash-map/set iteration, database iteration, filesystem directory order, locale/collation, thread completion order, or pointer/address order MUST NOT affect an encoded object, transaction order, state transition, tree root, chain work, or tie break.
5. **Complete consumption:** Unknown mandatory tags, duplicates in any future tagged form, wrong fixed lengths, noncanonical padding, reserved values, trailing bytes, and truncation are invalid.
6. **No parser panic:** Every byte string up to the transport hard bound—including empty, truncated, adversarial lengths/counts, and random bytes—returns a bounded error or a value; it MUST NOT panic, abort, read out of bounds, recurse without a bound, or allocate from an unchecked attacker length.

Required tests: round-trip/golden tests in four languages where available; mutation at every field boundary; append/truncate; maximum+1 lengths/counts; corpus fuzzing; allocation instrumentation; 32/64-bit and big-endian-emulated builds.

## 2. Cryptography and identity

1. **Every consensus hash is domain-separated:** The exact BLAKE3 `derive_key` context registry is exhaustive. An unlabeled or reused generic consensus hash is forbidden.
2. **Exact preimages:** All widths, field order, version/tag bytes, lengths, and byte order entering each hash are specified and tested. Text hex is never accidentally hashed.
3. **Cross-network replay fails:** Chain ID, network ID, and genesis commitment are inside transaction bodies, signing digests, block headers, handshakes, and snapshots. A transaction for one network MUST fail another network's identity check.
4. **Strict Ed25519 only:** Keys/R points are canonical valid nonidentity prime-subgroup points; `S<L`; exact uncofactored equation; no permissive legacy behavior, alternate variants, or batch verification.
5. **Address text is not consensus identity:** Only the 33-byte binary recipient enters consensus. Bech32m HRP/checksum/case decoding is strict, and an address for one HRP cannot be silently interpreted on another.
6. **CPU/CUDA equality:** For identical header bytes, all CPU and CUDA paths MUST return identical PoW digest bytes and target result bit-for-bit.

Required tests: official primitive vectors plus OUT vectors; all known noncanonical/low-order/mixed-order Ed25519 encodings; `S=L-1,L,L+1`; R/A identity; negative zero; wrong network tuple components one at a time; every PoW digest/limb ordering boundary.

## 3. Money and accounts

1. **No money overflow/underflow:** Stored money is `u64`; all intermediate/aggregate operations are checked unsigned `>=128`-bit. No wrap, saturation, signed cast, float, or build-mode difference.
2. **Maximum supply:** Every balance, aggregate, genesis allocation sum, subsidy issuance, reward total, and total supply is `<= P_MAX_MONEY <= u64::MAX`.
3. **Conservation:** Regular transfers plus fees conserve value. Fees are credited exactly once in the reward. Subsidy is the only candidate-v0 issuance and is credited exactly once.
4. **Exact nonce:** A new account expects 0; accepted nonce equals stored next nonce; success increments once; overflow invalid; failure changes nothing; zero-balance nonzero-nonce accounts remain.
5. **Deterministic order:** Regular transactions apply in block order; each debits/increments before credit; reward applies last. Self-send has the specified result.
6. **Atomic failure:** Insufficient funds, overflow, invalid nonce, bad reward, wrong root, or later transaction failure leaves the parent state unchanged.

Required tests: amount/fee/balance at 0, 1, `u64::MAX`, `P_MAX_MONEY` and ±1; `amount+fee` overflow; fee-sum overflow; credit overflow; nonce `u64::MAX`; nonexistent sender/recipient; self-send; same recipient from multiple senders; late-block failure rollback.

## 4. State commitment and storage

1. **Deterministic state root:** The fixed 256-bit sparse tree, MSB-first key path, exact occupied/empty leaves, height-bound internal hashes, normalized accounts, and raw-byte ordering produce one root for a semantic state.
2. **Insertion/backend independence:** Random insertion orders, batched updates, RocksDB, redb, and an in-memory model MUST produce identical roots and transitions.
3. **No database authority leakage:** Database serialization, comparator, compaction, cache, iterator order, or transaction API cannot change validity. Corruption/I/O is a local failure.
4. **Operational-store loss is harmless to consensus:** Total PostgreSQL/Redis loss, stale mirrors, duplicate queue delivery, or cache poisoning cannot change balances, nonces, roots, targets, work, or best tip.
5. **Snapshot verification:** A snapshot is not state until bounds, identity, commitment, sorted entries, money, root, anchor, header PoW/target chain, and cumulative work are verified.
6. **Crash-safe atomic block application:** After crash/recovery the node exposes exactly the pre-commit or post-commit branch state, never a mixed state. Tip, indices, state, root, supply, work, and undo linkage agree.

Required tests: permutation/property tests; cross-backend differential test; deliberately different database comparators; forced crashes/fault injection at every commit step; corrupt/missing node; snapshot duplicate/out-of-order/key mismatch; Redis/PostgreSQL unavailable during validation.

## 5. Proof of work and chain selection

1. **Exact U256 target:** Fixed 32-byte big-endian unsigned target, `1..=P_POW_LIMIT`, and exact expected value. Inclusive hash comparison.
2. **Exact work:** Integer formula and checked U256 cumulative sum; no float or approximate difficulty; overflow is invalid.
3. **Exact retarget:** Window inputs are identified by height on the candidate parent branch; endpoint span/clamps/multiply/divide/rounding are exact and checked.
4. **Deterministic best chain:** Higher cumulative work, then height, then lexicographically smaller raw tip ID. Arrival, peer, local selected tip, map/database/filesystem order, and thread scheduling never break ties.
5. **Probabilistic finality only:** Local deep-reorg policy may pause but cannot make higher-work valid history invalid.
6. **Clock containment:** Locale/time zone never matter. MTP is historical/deterministic. Future drift controls temporary local admission and is not permanently invalid-cached.

Required tests: U256 limb boundaries; target equality; work cross-language vectors; retarget lower/upper clamp equality and ±1; nonpositive raw span; cumulative overflow; equal-work fork permutations; local clock advance/retry.

## 6. Resource and network safety

1. **Bound before allocate:** Every attacker-controlled length/count has a documented maximum and is checked against remaining bytes with checked arithmetic before allocation, recursion, loop reservation, decompression, or hashing.
2. **Layered hard limits:** Transaction, memo/reward-extra, transaction count, block body/block, P2P payload/type payload, inventory/locator/headers, address, snapshot body/count, and diagnostic detail are bounded.
3. **No compression bomb in v0:** P2P v0 is uncompressed. Optional snapshot wrappers are decompressed into a hard bounded canonical byte count.
4. **Failure separation:** Malformed input is invalid; missing parent/state, disk/database faults, resource limits, and shutdown are local failures. A peer cannot cause local failure to be persisted as consensus invalidity.
5. **Unknown protocol behavior:** Unknown mandatory P2P types terminate; bounded unknown ignorable types are checksummed and discarded; neither enters consensus.

Required tests: adversarial length prefixes near every integer maximum; checked addition/multiplication overflow; slow/truncated frames; message semantic limit below global limit; snapshot decompression bound; fault classification assertions.

## 7. Release gates

A release MUST NOT claim consensus compatibility until:

- all implementation-blocking owner decisions are ratified and committed in final genesis descriptors;
- complete non-placeholder vectors are generated by one implementation and independently verified by another;
- CPU/CUDA differential PoW tests pass if CUDA is shipped;
- at least two independent codec/state/work implementations agree on all positive and negative vectors;
- fuzzing demonstrates bounded, panic-free decoding;
- cross-backend and crash-injection tests pass;
- a review confirms Python, Docker, PostgreSQL, Redis, wall-clock locale, and backend choice do not enter consensus decisions.
