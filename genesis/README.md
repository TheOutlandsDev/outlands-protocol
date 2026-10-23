> Export scope: dated verification statements below are historical. See [current export scope](../EXPORT-SCOPE.md) and root VALIDATION.md for fresh results and excluded tools.

# OUT genesis parameter-source status

`parameter-source-v0.json` is a machine-readable assembly of ratified owner decisions. It is **not** the canonical binary genesis descriptor and contains no claimed cryptographic output.

Status:

- Testnet and devnet parameter inputs and mined genesis artifacts are independently verified in `generated/`.
- Mainnet `genesis_timestamp`, `pow_limit_hex`, and `genesis_target_hex` are deliberately `null` and listed as blockers.
- Mainnet commitment, roots/header, nonce, PoW hash, and block ID remain uncomputed/unverified.

Generation tooling expands the reward formula into the exact 30-entry schedule required by `consensus-v0.md`, preserves descriptor field order, encodes every integer big-endian at its specified width, and rejects values outside their width/bound. Test/dev outputs were promoted only after complete C/Python equality.

JSON is configuration/source data only. It never becomes a consensus encoding and MUST NOT be hashed directly.
