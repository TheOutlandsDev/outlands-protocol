> Export scope: dated verification statements below are historical. See [current export scope](../EXPORT-SCOPE.md) and root VALIDATION.md for fresh results and excluded tools.

# OUT Consensus v0 implementation review checklist

Use this as a merge/release gate. Every checked item SHOULD link to code, a test, a vector, or a review record. “N/A” requires written justification.

## Owner ratification and source control

- [x] Chain ID, network IDs/names, P2P magic, and address HRPs are owner-approved in `OUT-ID-v0`.
- [ ] Complete mainnet genesis descriptor is owner-approved; testnet/devnet descriptors are frozen and independently verified.
- [x] Recipient v0 version, payload size, and meaning are approved in `OUT-ID-v0`.
- [x] Maximum money, no-allocation genesis, reward schedule, fee semantics/minimum, and display-unit status are approved in `OUT-ECON-v0`.
- [x] Transaction/block/P2P/genesis/snapshot maxima and timestamp bounds are approved in `OUT-LIMITS-v0`.
- [x] State-tree v0 and all empty-hash construction rules are approved in `OUT-TECH-v0`.
- [ ] Mainnet PoW limit/genesis target and launch timestamp are approved; spacing, retarget, test/dev targets, timestamps, and exceptions are approved.
- [x] Initial consensus/transaction versions and height activation schedule are approved in `OUT-TECH-v0`.
- [x] Reviewed documentation/genesis/vector set is content-hashed in `docs/spec-content-manifest-v0.txt`; testnet/devnet genesis bytes/IDs are independently verified.
- [x] `OUT-LAUNCH-GATE-v0` authorizes Rust testnet/devnet work while requiring mainnet fields to remain unset.
- [ ] Mainnet manifest and generated genesis bytes/IDs are content-hashed and independently verified.
- [ ] No application code was treated as the specification.

## Codec and object layouts

- [ ] Every field has fixed order, width, byte order, tag value, and semantic bound.
- [ ] Header encoder always emits exactly 223 bytes and offsets match the table.
- [ ] Transaction/body/auth/block envelopes consume exactly their declared slice.
- [ ] All lengths/counts are checked against semantic maximum and remaining input before allocation.
- [ ] Checked arithmetic is used for `offset+length`, `count*element_size`, next-power-of-two, and total size.
- [ ] Unknown/reserved/duplicate tags, truncation, noncanonical padding, and trailing bytes are rejected.
- [ ] No `usize`, floats, native endian, struct layout, Serde/bincode/JSON/Protobuf, implicit enum discriminants, or unordered iteration defines consensus bytes.
- [ ] Decode/re-encode equality is asserted for every accepted object.
- [ ] Malformed input and fuzz corpora cannot panic/abort or allocate beyond bounds.

## Hashes, signatures, and addresses

- [ ] BLAKE3 uses `derive_key` mode, exact ASCII contexts, exact 32-byte output, and no dynamic context.
- [ ] Each registry purpose has distinct positive and wrong-domain negative vectors.
- [ ] Every exact preimage includes specified version/tag/length bytes and endian order.
- [ ] Pure Ed25519 signs exactly the 32-byte OUT signing digest—not raw body, Ed25519ph, or Ed25519ctx.
- [ ] A/R canonical point decoding, nonidentity prime-subgroup checks, `S<L`, and exact uncofactored equation are enforced.
- [ ] Lax/legacy/cofactored verification and batch verification are disabled.
- [ ] Sender/public-key mapping is exact.
- [ ] Bech32m constant/alphabet/conversion/padding are correct; canonical text is lowercase; mixed/uppercase, wrong HRP, wrong checksum/size/version/key are rejected.
- [ ] Address text never enters consensus objects/state keys.
- [ ] Cross-network identity mutations fail signatures/validation as specified.

## Transactions, state, and money

- [ ] New account nonce is 0; exact nonce match/increment; `u64::MAX` overflow invalid.
- [ ] `amount+fee`, fee sum, credit, subsidy/reward, initial/scheduled/total supply use checked `u128` or wider arithmetic and narrow only after bounds.
- [ ] No float, signed cast, wrapping, saturation, or debug/release overflow difference exists.
- [ ] Insufficient funds checks amount plus fee before any committed mutation.
- [ ] Sender debit/nonce occurs before recipient credit; self-send test matches spec.
- [ ] Regular transactions apply in body order; reward validates/credits last.
- [ ] Failed block/transaction leaves parent state unchanged.
- [ ] `(0,0)` accounts are absent; zero-balance nonzero-nonce accounts remain.
- [ ] Reward fields equal exact schedule and fee total; over/underclaim fail.
- [ ] Duplicate IDs within block/ancestor branch are rejected; competing-branch behavior is correct.

## State commitment, snapshots, and storage

- [ ] Account key, record, leaf, empty leaf, every empty height, and internal-node preimages match vectors.
- [ ] Key path is MSB-first; internal height and left/right order are correct.
- [ ] Account-key collisions fail deterministically.
- [ ] Root is independent of insertion, update batching, unordered maps, database iteration/comparator, RocksDB/redb, and filesystem order.
- [ ] Header post-state root is compared only after complete pure transition.
- [ ] Snapshot bounds/count/order/key/record/money/commitment/root/anchor/header-work are all verified before atomic install.
- [ ] Unimplemented state proof format is not exposed as consensus-valid.
- [ ] Undo/persistent nodes can reproduce parent root across tested reorg horizon.
- [ ] Block/state/root/work/index/undo/tip persistence is crash atomic; recovery fault-injection passes.
- [ ] Storage faults are local failures, not cached invalid blocks.
- [ ] PostgreSQL/Redis loss or corruption cannot alter any consensus query/result.

## PoW, targets, time, and chain selection

- [ ] PoW hashes exact 223 header bytes with exact derive-key context; nonce is big-endian at offset 215.
- [ ] Digest-to-U256 and target use fixed big-endian unsigned interpretation; comparison is inclusive.
- [ ] Required target range/equality checks precede PoW acceptance.
- [ ] Work formula uses exact integer floor and 257-bit-capable intermediate; cumulative U256 addition is checked.
- [ ] Epoch heights/endpoints, expected/actual span, nonpositive span, rational clamp rounding, >=512-bit product, division floor, and pow-limit clamp match vectors.
- [ ] MTP collection/sort/upper-early-median and strict greater-than check match vectors.
- [ ] Future-drift failure is retriable and not permanently invalid-cached.
- [ ] Main/test/dev exception flags are descriptor-bound and mutually exclusive.
- [ ] Best tip comparison is cumulative work, height, then smaller raw block ID, independent of arrival/current tip/storage order.
- [ ] CPU and CUDA produce bit-identical digests/results over boundary/random differential corpus; disagreement fails closed.

## Validation, reorg, and failure classes

- [ ] Validation order follows `consensus-v0.md` or is proven observationally equivalent.
- [ ] Cheap bounds/canonical/identity/target/PoW/Merkle checks precede expensive state commit.
- [ ] Signatures are individually verified in transaction order before transition.
- [ ] Missing parent/history/state, I/O/resource/shutdown, and internal faults remain local/unclassified.
- [ ] Reorg validates winning branch, rolls back reverse order, applies forward order, and switches visible tip/state atomically.
- [ ] Local deep-reorg policy pauses rather than declaring a valid higher-work branch invalid.
- [ ] Mempool reinsertion fully revalidates and remains non-consensus.
- [ ] Pruned history unavailability triggers fetch/reconstruct/decline, never false invalidity.
- [ ] Documentation accurately states probabilistic finality and snapshot trust.

## Interoperability evidence

- [x] Every example satisfies `test-vectors/schema.json` constraints as checked by the dependency-free repository validator.
- [ ] No field marked `verified` contains a guessed or single-implementation-only cryptographic output.
- [x] Initial illustrative vectors have two independent implementations agreeing on canonical bytes, hashes, addresses, roots, target/work, transitions, and represented invalid reasons.
- [ ] Negative vectors cover every tag, bound, arithmetic failure, replay component, signature strictness rule, and trailing/truncated case.
- [ ] Cross-language (Rust/Python/C++) and CPU/CUDA reports include exact tool/library versions without making them consensus inputs.
