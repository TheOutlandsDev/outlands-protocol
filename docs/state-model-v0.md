> Export scope: dated verification statements below are historical. See [current export scope](../EXPORT-SCOPE.md) and root VALIDATION.md for fresh results and excluded tools.

# OUT account state and commitment v0

Status: normative and ratified as part of `OUT-TECH-v0`.

## 1. State domain

Consensus state is a finite mapping from supported binary `recipient[33]` values to accounts:

```text
Account {
  balance: u64 base units,
  nonce:   u64 next expected regular-transaction nonce
}
```

An account identifier is the binary recipient, not Bech32m text. Its authenticated tree key is:

```text
account_key[32] = OUT_HASH(ACCOUNT_KEY_CONTEXT, 0x00 || recipient[33])
```

The prefix is account-key format version 0. Keys are compared as unsigned 256-bit bit strings in raw-byte lexicographic order. Tree traversal consumes key bits most-significant-bit first: bit 0 is `account_key[0] & 0x80`; bit 255 is `account_key[31] & 0x01`.

If a state already contains the same account key with a different recipient, validation MUST fail with `ACCOUNT_KEY_COLLISION`; an implementation MUST NOT overwrite, choose an insertion order, or create a collision bucket. This is a cryptographically implausible but deterministic failure rule.

## 2. Account existence and canonical records

- A nonexistent account has semantic balance 0 and nonce 0.
- The pair `(balance=0, nonce=0)` MUST NOT be stored as an occupied leaf.
- An account with `nonce>0` MUST remain occupied even when balance is zero; deleting it would reset replay protection.
- Crediting a nonexistent account with a positive amount creates it with nonce 0.
- A zero credit is a no-op and MUST NOT create an account.
- A sender need not pre-exist, but it can pass only if its default nonce is 0 and it has sufficient funds; under normal positive-value semantics it cannot.
- Removing the last balance from a nonce-0 account is possible only through a rule other than regular spending; normalization MUST remove `(0,0)` after every consensus mutation.

The canonical occupied account record used by state leaves is exactly:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | account record version `0x00` |
| 1 | 33 | binary recipient |
| 34 | 8 | balance, big-endian `u64` |
| 42 | 8 | nonce, big-endian `u64` |

It is 50 octets. Unsupported recipient versions, `(0,0)`, account-key mismatch, balance above `P_MAX_MONEY`, or trailing bytes are invalid.

## 3. Monetary arithmetic

Stored amounts, balances, fees, subsidies, and supply parameters are `u64`. Every addition, subtraction precondition, aggregation, multiplication, or conversion involved in money MUST be evaluated with checked unsigned arithmetic using at least 128 bits. No float, decimal, signed wrap, saturating arithmetic, modulo arithmetic, or debug/release-dependent overflow is allowed.

Rules:

```text
checked_money_add(a:u64, b:u64):
  x:u128 = u128(a) + u128(b)          # checked
  require x <= u128(P_MAX_MONEY)
  require x <= u128(u64::MAX)
  return u64(x)

checked_money_sum(values):
  total:u128 = 0
  for v in values in specified order:
    total = checked_u128_add(total, u128(v))
    require total <= u128(P_MAX_MONEY)
  return total
```

For debit, compute `required:u128 = amount + fee`; require `required <= P_MAX_MONEY`, `required <= u64::MAX`, and sender balance `>= required` before subtracting. Underflow/overflow makes the transaction and containing block invalid. There is no rounding.

`OUT-ECON-v0` fixes `P_MAX_MONEY` to 2,102,400,000,000,000 base units and display precision to 8 decimal places. The sum of all account balances is the circulating supply. Fees are transferred, not minted or burned; only subsidy increases total supply. For every valid post-state:

```text
sum_balances_u128 == sum(subsidy(h), h=1..height)
sum_balances_u128 <= P_MAX_MONEY
```

The genesis manifest MUST be rejected before launch if the schedule could violate the maximum under exact checked arithmetic. A node MAY maintain a cached supply scalar, but it is derived data and MUST be cross-checkable from ratified issuance plus state. Cache loss cannot alter validation.

Display denominations and decimal places are wallet policy. Consensus uses indivisible integer base units only.

## 4. Nonce and regular transaction transition

`account.nonce` is the next expected nonce. A new/nonexistent account expects 0. A regular transaction is valid only if `tx.nonce == sender_account.nonce`. Lower and higher nonces are both invalid in a block. Mempools MAY queue higher nonces, but that does not change consensus.

When a sender nonce is `u64::MAX`, no further regular transaction can be applied because checked increment would overflow. The account remains spend-receivable; overflow is not wrapping.

Given a structurally/signature-valid regular transaction and mutable state `S`, apply exactly:

```text
apply_regular(S, tx, fee_total_u128):
  sender_key = account_key(tx.sender)
  recipient_key = account_key(tx.recipient)
  sender = S.get(tx.sender).unwrap_or(Account(0, 0))

  require tx.amount > 0                         # ratified OUT-ECON-v0
  require tx.fee >= P_MIN_CONSENSUS_FEE
  require tx.nonce == sender.nonce
  next_nonce = checked_u64_add(sender.nonce, 1) # overflow => invalid

  required_u128 = checked_u128_add(tx.amount, tx.fee)
  require required_u128 <= P_MAX_MONEY
  require required_u128 <= u64::MAX
  require u128(sender.balance) >= required_u128

  # Debit and consume nonce first.
  sender.balance = sender.balance - u64(required_u128)
  sender.nonce = next_nonce
  S.put_normalized(tx.sender, sender)

  # Then read recipient from the already-updated S. This is essential for self-send.
  recipient = S.get(tx.recipient).unwrap_or(Account(0, 0))
  recipient.balance = checked_money_add(recipient.balance, tx.amount)
  S.put_normalized(tx.recipient, recipient)

  fee_total_u128 = checked_u128_add(fee_total_u128, u128(tx.fee))
  require fee_total_u128 <= P_MAX_MONEY
  return fee_total_u128
```

For `sender == recipient`, the result is balance `old_balance - fee` and nonce `old_nonce + 1`; the amount is debited then credited to the same updated account. Insufficient funds is tested against `amount + fee`, even for self-send. A failed transaction changes no state: implementations MUST use a temporary state view/undo journal and commit only after every check succeeds.

Regular transactions are applied in exact block-body order starting at index 1. Sorting by sender, nonce, fee, transaction ID, database order, or parallel completion time is forbidden. Parallel preverification is allowed only if the committed transition is observationally identical to sequential order.

## 5. Reward and fee processing

Transaction index 0 is the sole reward transaction. It is structurally checked early but credited only after all regular transactions succeed.

```text
apply_reward_last(S, reward, height, fee_total_u128, supply_before_u128):
  expected_subsidy = subsidy_schedule(height)
  require reward.height == height
  require reward.subsidy == expected_subsidy
  require u128(reward.fees) == fee_total_u128

  reward_total = checked_u128_add(u128(reward.subsidy), fee_total_u128)
  require reward_total <= P_MAX_MONEY
  require reward_total <= u64::MAX

  issued_after = checked_u128_add(supply_before_u128, u128(reward.subsidy))
  require issued_after <= P_MAX_MONEY

  acct = S.get(reward.recipient).unwrap_or(Account(0, 0))
  acct.balance = checked_money_add(acct.balance, u64(reward_total))
  S.put_normalized(reward.recipient, acct)
```

Fees are absent from intermediate account state after sender debit until reward credit within the same atomic pure transition. No intermediate root is consensus-visible. Reward nonce is unchanged. If subsidy and fees are both zero, credit is a no-op and does not create an account. The reward's declared fields MUST match exactly; overclaim and underclaim are both invalid. Genesis uses descriptor allocations and no reward transaction.

`OUT-ECON-v0` defines the reward function directly for `height >= 1`:

```text
ERA_LENGTH = 2,102,400
INITIAL_SUBSIDY = 500,000,000 base units
era = floor((height - 1) / ERA_LENGTH)
subsidy(height) = floor(INITIAL_SUBSIDY / 2^era)
```

Heights 1 through 2,102,400 are era 0. Eras 0 through 28 are positive; era 29 begins at height 60,969,601 and has zero subsidy forever. A descriptor materializes this as 30 strictly ascending segments: positive segment `e` starts at `1 + e*2,102,400`, followed by the zero segment at height 60,969,601. Exact lifetime subsidy is 2,102,399,972,668,800 base units, leaving 27,331,200 below `P_MAX_MONEY`. Genesis has no allocation and no reward.

## 6. Sparse authenticated state tree

### 6.1 Shape

Candidate state tree version 0 is a fixed-depth, 256-level, binary sparse Merkle tree. Leaves correspond one-to-one with all possible 256-bit account keys; there is no path compression. Left is key bit 0; right is key bit 1. The root has height 256 and leaves have height 0. Tree shape is independent of insertion order, database keys, and pruning.

### 6.2 Leaf and empty hashes

Let `H_leaf(m) = OUT_HASH(STATE_LEAF_CONTEXT, m)` and `H_node(m) = OUT_HASH(STATE_NODE_CONTEXT, m)`.

Empty leaf:

```text
E[0] = H_leaf(0x00 || 0x00)
```

First octet is tree version; second is empty tag. Occupied leaf for account key `k` and its 50-byte canonical record `r`:

```text
Leaf(k,r) = H_leaf(0x00 || 0x01 || k[32] || r[50])
```

No occupied leaf may encode `(balance=0, nonce=0)`. The record recipient MUST derive to `k`.

Empty subtree hashes for heights `h=1..256`:

```text
E[h] = H_node(0x00 || BE16(h) || E[h-1] || E[h-1])
```

Every nonempty internal node of height `h` uses the identical formula with its exact left and right child hashes:

```text
Node(h,left,right) = H_node(0x00 || BE16(h) || left[32] || right[32])
```

`h` MUST be in `1..=256`. Left/right order MUST NOT be sorted or swapped. A node whose children are both the canonical `E[h-1]` is represented by `E[h]`; storing or omitting it locally has no effect.

### 6.3 Root construction pseudocode

The following conceptual algorithm defines the root; implementations SHOULD use sparse updates rather than materializing `2^256` leaves.

```text
root(accounts):
  items = []
  for each occupied account:
    r = canonical_account_record(account)
    k = account_key(r.recipient)
    require unique k and supported/canonical r
    items.append(k, Leaf(k,r))
  sort items by k raw bytes ascending

  return sparse_fold(prefix_bits="", height=256, sorted_items=items,
                     empty_hashes=E[0..256])

sparse_fold(prefix, height, items):
  if items empty: return E[height]
  if height == 0:
    require exactly one item whose full key == prefix
    return item.leaf_hash
  bit_index = 256 - height
  left_items  = items with key[bit_index] == 0
  right_items = items with key[bit_index] == 1
  left  = sparse_fold(prefix||0, height-1, left_items)
  right = sparse_fold(prefix||1, height-1, right_items)
  return Node(height,left,right)
```

The empty global state root is `E[256]`. A block header's `state_root` is exactly the root after all regular transactions and the reward have been applied. Genesis root is built from descriptor allocations with nonce 0.

RocksDB, redb, in-memory Python, and independent implementations MUST return identical roots. Database iteration MUST be collected and sorted by raw account key or avoided via direct tree paths; native comparator/collation is not a consensus rule.

### 6.4 Proofs and pruning

State inclusion/non-inclusion proof wire format is **deferred**. No v0 implementation may invent a proof format and call it consensus. The root/hash rules are not deferred. Until a proof format is activated, peer-supplied individual state proofs are advisory/unusable for consensus validation.

Content-addressed internal nodes MAY be pruned only if the node retains enough current state plus undo/history/snapshots to satisfy its advertised validation and reorg capability. Pruning storage nodes does not change empty hashes, roots, or validity.

## 7. Snapshot format and verification

Snapshot v0 is optional but, if implemented, uses this exact uncompressed canonical file:

| Order | Size | Field |
|---:|---:|---|
| 1 | 1 | snapshot codec `0x00` |
| 2 | 32 | chain ID |
| 3 | 4 | network ID |
| 4 | 32 | genesis commitment |
| 5 | 8 | anchor height |
| 6 | 32 | anchor block ID |
| 7 | 32 | claimed state root |
| 8 | 8 | account count |
| 9 | 8 | body length |
| 10 | body length | account entries |
| 11 | 32 | snapshot commitment |

Each body entry is exactly 82 octets: `account_key[32] || account_record[50]`. Entries MUST be strictly ascending by raw key, unique, canonical, and key-consistent. `body_len` MUST equal checked `account_count * 82`. Before allocation/read, both values MUST fit remaining file size and ratified `P_MAX_SNAPSHOT_BODY_BYTES = 68,719,476,736` bytes (64 GiB). Readers MUST stream; this cap is not allocation permission. Compression/container formats may wrap this file operationally but decompression MUST be bounded to that maximum and produce these exact bytes.

Snapshot commitment material is every field from codec through body, exactly as encoded (it excludes the final commitment field):

```text
snapshot_commitment = OUT_HASH(SNAPSHOT_CONTEXT,
  0x00 || chain_id || BE32(network_id) || genesis_commitment ||
  BE64(height) || block_id || state_root ||
  BE64(account_count) || BE64(body_len) || body)
```

Verification MUST:

1. Bound file/body/count before allocation and reject truncation/trailing bytes.
2. Verify network identity and commitment.
3. Verify every entry, strict order, uniqueness, money bounds, and checked total supply expected at anchor height.
4. Recompute the sparse root and require equality with claimed root.
5. Verify the anchor header's block ID and state root.
6. Verify the valid header chain, PoW, target rules, and cumulative work from pinned genesis through the anchor (or explicitly invoke a separately approved trusted-checkpoint model, which v0 does not include).
7. Atomically install state and anchor metadata; an interruption leaves the previous state selected.

Snapshot publisher signatures, catalogs, mirrors, and transport are non-consensus discovery/authenticity hints. They never replace steps 1–6.

## 8. Rollback, branches, and crash safety

Each applied block MUST preserve either an exact inverse account-change set or persistent prior-root nodes sufficient to restore its parent state. Undo records are local encoding, but restoring then recomputing MUST yield the exact parent header root.

Branch validation reads an immutable parent view and creates a new content-addressed/rooted view. A failed transaction, invalid root, I/O error, or crash MUST NOT mutate the selected canonical state. Block data, post-state/root, transaction index, supply metadata, cumulative work, undo linkage, and canonical-tip pointer MUST become visible atomically or through a write-ahead protocol with deterministic recovery.

On recovery, the node MUST select either the complete pre-commit state or complete post-commit state, verify referential/root consistency, and never synthesize validity from PostgreSQL/Redis mirrors. Backend corruption is a local fault requiring recovery/resync; it does not redefine consensus.
