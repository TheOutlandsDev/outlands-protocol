> Export scope: dated verification statements below are historical. See [current export scope](../../EXPORT-SCOPE.md) and root VALIDATION.md for fresh results and excluded tools.

# Independently verified OUT genesis artifacts

`devnet-v0.json` and `testnet-v0.json` contain complete canonical descriptor/header bytes and derived commitments, roots, nonces, PoW hashes, and block IDs.

Verification performed on 2026-08-30:

- Independent dependency-free Python BLAKE3 and OUT encoder: `tools/python/out_ref.py`.
- Separate C OUT encoder using pinned official portable BLAKE3 1.8.7: `tools/c/out_ref.c`.
- Python passed all 35 official BLAKE3 hash/keyed/derive-key extended-output vectors.
- C passed selected official derive-key vectors at lengths 0, 1,024, and 102,400.
- Complete nonce-zero test/dev JSON content matched after canonical JSON key sorting.
- C mined devnet nonce 2,757 and testnet nonce 538,190.
- Python independently recomputed the complete mined artifacts and matched every field byte-for-byte.

Key results:

| Network | Commitment | Nonce | PoW hash | Block ID |
|---|---|---:|---|---|
| devnet | `baa26e3bdda0a7b3196e89367f32a9d05558ea5ea196875f30880f055e5226a7` | 2,757 | `00089b59cde9abecc6421d2cfd06f2abcba5c07dfcb9f3ab1c62e7c22b6b71c5` | `bd31ae362fa769dab143ef308f7706a7bea9ae671c8fe21793cd8200d73135c9` |
| testnet | `2a0cd6921865d4514f264cd96ed3f8fb05dba505747f7412e403560a72a7ebe6` | 538,190 | `00000dc9b459d2a3bd21cdcefe38e24665b6ca94a2075d3f8f0e4a529049c0b6` | `15a4d51b737a4e3887218b004389f5245d9a2423af17145aa4686862f050c5cb` |

Shared empty state root: `3d30a2588a2f688edd9b29af2bb3b522db2deb731709dbfb53fadefab69c2147`.

Shared empty-genesis transaction root: `da2fb959f81d652879472f8c56076e63a2fb3587dda94754f316328e7ec43140`.

Mainnet is intentionally absent until its launch timestamp and benchmark-derived targets are ratified.
