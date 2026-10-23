> Export scope: dated verification statements below are historical. See [current export scope](../EXPORT-SCOPE.md) and root VALIDATION.md for fresh results and excluded tools.

# OUT Consensus v0 test vectors

The 12 files in `examples/` are concrete illustrative vectors covering every required deliverable category. Each is marked `independently_verified` because the complete underlying result bundle matched between dependency-free Python and independently written C paths. They are golden examples, but they are not yet the exhaustive boundary, mutation, signature-strictness, retarget, reorg, or CPU/CUDA conformance corpus required for release.

No BLAKE3 digest, transaction/block ID, Bech32m address, signature, PoW result, Merkle root, or state root may be changed to `independently_verified` until two genuinely independent implementations produce the same value from the same raw inputs. The Python path implements BLAKE3 and Ed25519 directly; the C path uses the pinned official portable BLAKE3 C source and OpenSSL EVP Ed25519. Their OUT encoders, address codecs, state trees, transition checks, and parsers are separate implementations.

## Conventions

- JSON files MUST validate against `schema.json`.
- Hex is lowercase, even-length, without `0x`. Hex represents bytes in wire order, not host words.
- Decimal U256 values are strings to avoid JSON number precision loss.
- `${P_NAME}` is an unresolved owner-ratified parameter and is never a literal consensus value.
- Every byte-producing vector SHOULD include both structured fields and the complete expected hex.
- Every hash vector MUST include exact context ASCII and exact material hex.
- Invalid vectors MUST identify the earliest normative failure code expected from the reference validation order. Diagnostic wording is not normative.
- For the transaction/state bundle, `verification.implementations[].result_digest` is ordinary BLAKE3 over UTF-8 output from `jq -S .` including its final newline. The common bundle digest is `21528d5476ab75154427117b34d65d82ce73bb1e981489619e039cdf02c78ae6`. It is provenance only, not consensus. Genesis vectors use `null` because their older comparison run did not assign this optional provenance digest.

The public test seeds are `00..1f` and `20..3f`; they MUST NEVER secure funds. Reproduce the bundle with `python3 tools/python/out_ref.py --vectors` and `tools/build/out_vectors_c`, canonicalize both with `jq -S .`, and require byte equality.

## Promotion workflow

1. Ratify and insert every network/limit/economic parameter.
2. Freeze exact input bytes and set vector `status` to `computed` after one implementation records outputs and its version.
3. Have an independent implementation compute from the specification, not from the first implementation's intermediate outputs.
4. Compare complete raw outputs and important intermediates. Resolve disagreement; never average or select the preferred implementation.
5. Record at least two producers and promote each expected field and vector to `independently_verified`.
6. Run the same vectors in Rust, Python, C++, and CUDA where applicable. Negative vectors MUST be run, not merely parsed as documentation.

## Required final coverage

- Minimum/maximum lengths and every maximum+1 rejection.
- Every integer at 0, 1, maximum, and byte/limb boundaries.
- Every hash context with a wrong-context negative case.
- Strict Ed25519 malformed/noncanonical/weak key and signature cases.
- Bech32m case, checksum, HRP, padding, payload-size, and version failures.
- Merkle counts 0 genesis-only, 1, powers of two, and power ±1.
- Empty state, one account, shared prefixes, insertion permutations, self-send, reward, and rollback.
- Target equality, one above/below, work/cumulative overflow, all retarget clamp/rounding boundaries.
- Cross-network mismatch of each tuple component independently.

The example files map one-to-one to the deliverable categories; final vector suites SHOULD contain many cases per category.
