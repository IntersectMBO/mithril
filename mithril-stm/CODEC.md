# CBOR Codec — Compatibility Rules

This document describes the versioned CBOR encoding used by `mithril-stm` for
`to_bytes` / `from_bytes` and the rules to follow when evolving serialized
structures.

## Canonical bytes are out of scope

This document does not concern the canonical bytes encoding. Canonical bytes are
a fixed-size encoding without version byte nor CBOR payload, exposed by
`to_canonical_bytes` / `from_canonical_bytes` on:

- BLS types: `BlsSigningKey`, `BlsVerificationKey`, `BlsProofOfPossession`,
  `BlsSignature`, `BlsVerificationKeyProofOfPossession`
- Schnorr types: `SchnorrSigningKey`, `SchnorrVerificationKey`,
  `StandardSchnorrSignature`, `UniqueSchnorrSignature`
- Jubjub types: `BaseFieldElement`, `ScalarFieldElement`, `ProjectivePoint`,
  `PrimeOrderProjectivePoint`
- Merkle tree leaves: `MerkleTreeConcatenationLeaf`, `MerkleTreeSnarkLeaf`

The rigid slot layouts consumed by the circuits (`Parameters::to_rigid_bytes`,
`AggregateVerificationKeyForSnark::to_rigid_slot_bytes`) are canonical bytes too.

Hash computations must only rely on canonical bytes, so that an evolution of
the CBOR codec never alters a hash. The canonical bytes of a type must never
change, and each of them is protected by a golden test.

## Wire format

Every CBOR-encoded value is prefixed with a **version byte**:

```text
[version_byte = 0x01][CBOR payload]
```

The `from_bytes` implementation inspects the first byte:

- `0x01` — decode the remaining bytes as CBOR.
- Anything else — fall back to the legacy big-endian byte-packed decoder.

## Disambiguating legacy data from CBOR

The version byte `0x01` must never collide with the first byte of legacy data.
This works because most types start their legacy encoding with a big-endian
`u64` counter or length, whose most significant byte is `0x00` for any
realistic value (values below `2^56`).

The following table lists every type's legacy first byte and why it is safe:

| Type                                       | Legacy first byte                                       | Why safe                                                                     |
| ------------------------------------------ | ------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `Parameters`                               | `u64 m` → `0x00`                                        | `m` is a protocol parameter (tens of thousands)                              |
| `SingleSignature`                          | `u64 nr_indexes` → `0x00`                               | Bounded by `m`                                                               |
| `SingleSignatureWithRegisteredParty`       | `u64 size` → `0x00`                                     | Byte length of inner struct                                                  |
| `AggregateSignature`                       | Discriminator `0x00` or `0x01` (Snark)                  | **Ambiguous when `snark` — uses try-CBOR-then-fallback**                     |
| `Initializer`                              | `u64 stake` → `0x00`                                    | Stake fits in 6 bytes                                                        |
| `ClosedRegistrationEntry`                  | BLS compressed key → `≥ 0x80`                           | BLS12-381 compressed points set bit 7                                        |
| `AggregateVerificationKeyForConcatenation` | `u64 nr_leaves` → `0x00`                                | Few thousand leaves                                                          |
| `ConcatenationProof`                       | `u64 total_sigs` → `0x00`                               | Bounded by signer count                                                      |
| `MerkleTreeBatchCommitment`                | `u64 nr_leaves` → `0x00`                                | Few thousand leaves                                                          |
| `MerkleTree`                               | `u64 n` → `0x00`                                        | Few thousand leaves                                                          |
| `MerklePath`                               | `u64 index` → `0x00`                                    | Bounded by tree size                                                         |
| `MerkleBatchPath`                          | `u64 len_v` → `0x00`                                    | Bounded by tree depth × batch size                                           |
| `SnarkProof`                               | `u64 m` (via Parameters) → `0x00`                       | Parameters starts with `m`                                                   |
| `AggregateVerificationKeyForSnark`         | Raw hash digest (via `MerkleTreeCommitment`) → any byte | **Ambiguous — uses try-CBOR-then-fallback (same as `MerkleTreeCommitment`)** |
| **`MerkleTreeCommitment`**                 | **Raw hash digest → any byte**                          | **Ambiguous — uses try-CBOR-then-fallback**                                  |

### Special case: `MerkleTreeCommitment` and `AggregateVerificationKeyForSnark`

`MerkleTreeCommitment` (gated behind `snark`) stores its legacy format
as the raw Merkle root hash with no length prefix. The first byte of a hash
digest is pseudo-random and can be `0x01` (~0.4% probability). Because the
legacy encoding of `AggregateVerificationKeyForSnark` begins with a
`MerkleTreeCommitment` hash digest, it is subject to the same ambiguity. To
handle this, their `from_bytes` methods try CBOR decoding first and fall back
to the legacy decoder if CBOR fails:

```rust
if codec::has_cbor_v1_prefix(bytes) {
    codec::from_cbor_bytes(&bytes[1..])
        .or_else(|_| Self::from_bytes_legacy(bytes))
} else {
    Self::from_bytes_legacy(bytes)
}
```

### Special case: `AggregateSignature`

`AggregateSignature` uses a type-discriminator byte as its legacy first byte:
`0x00` for `Concatenation` and `0x01` for `Snark` (gated behind `snark`).
The `Snark` discriminator collides with the CBOR version byte `0x01`. To handle
this ambiguity, its `from_bytes` method uses the same try-CBOR-then-fallback
pattern as `MerkleTreeCommitment`.

### Adding a new type

When adding `to_bytes` / `from_bytes` to a new type, verify that the legacy
format's first byte **cannot** be `0x01`. If the legacy format starts with raw
cryptographic material (hashes, signatures, public keys), use the
try-CBOR-then-fallback pattern shown above instead of the simple version-byte
dispatch.

## Backward compatibility (new code reads old data)

Handled automatically by the dual-read dispatch:

```rust
if codec::has_cbor_v1_prefix(bytes) {
    // decode CBOR
} else {
    Self::from_bytes_legacy(bytes)
}
```

No action is required when adding fields — old data that predates CBOR will
continue to be decoded through the legacy path.

## Forward compatibility (old code reads new data)

ciborium deserializes CBOR maps and **silently ignores unknown keys**. This
means that data produced by a newer version of the code (with extra fields) can
still be read by an older version that does not know about those fields.

> **Non-idempotent round-trip:** because unknown keys are silently dropped
> during deserialization, a deserialize-then-reserialize cycle performed by
> older code will **not** reproduce the original bytes. The extra fields
> written by the newer version are lost. This means the transformation is
> **not idempotent**: `to_bytes(from_bytes(data)) ≠ data` when `data`
> contains keys unknown to the running code. Keep this in mind when older
> nodes store or relay re-encoded values, downstream consumers running
> newer code will see the additional fields missing.
>
> The same applies to **feature-gated fields** (`#[cfg(feature = "...")]`):
> if data is serialized with a feature enabled (e.g. `snark`) and
> then deserialized by a binary compiled **without** that feature, the
> gated fields are silently dropped at compile time — the struct simply
> does not have them. Re-serializing will permanently lose those fields.

## Adding a new field

1. Add the field to the struct (or to the envelope struct for types that use
   one).
2. Annotate it with `#[serde(default)]` so that data written before the field
   existed can still be decoded — the field will receive its `Default` value.

```rust
#[derive(Serialize, Deserialize)]
pub struct Parameters {
    pub m: u64,
    pub k: u64,
    pub phi_f: f64,
    #[serde(default)] // missing key decodes as 0
    pub new_field: u64,
}
```

For optional features, prefer `Option<T>` which defaults to `None`:

```rust
#[derive(Serialize, Deserialize)]
pub struct Parameters {
    pub m: u64,
    pub k: u64,
    pub phi_f: f64,
    #[serde(default)] // missing key decodes as None
    pub optional_feature: Option<String>,
}
```

No version byte bump is needed.

## Removing or renaming a field

**Do not remove or rename fields.** These are breaking changes because:

- Removing a field means old data that contains it can no longer populate the
  struct (the value is silently dropped, which may cause semantic errors).
- Renaming a field is equivalent to removing the old name and adding a new one.

If a field is no longer needed, deprecate it and stop writing meaningful values
to it, but keep it in the struct definition so old data can still be decoded.

## Changing a field type

**Do not change the type of an existing field.** For example, changing `u64` to
`String` will cause a deserialization error when reading data written with the
old type.

If you need a different type, add a new field with the desired type and
deprecate the old one.

## Bumping the version byte

The version byte should only be changed for an intentionally **breaking** format
migration. If you bump to `0x02`, add a new decoder branch:

```rust
if bytes[0] == 0x02 {
    // decode v2 CBOR
} else if codec::has_cbor_v1_prefix(bytes) {
    // decode v1 CBOR
} else {
    Self::from_bytes_legacy(bytes)
}
```

Under normal evolution (adding fields), this is **not** necessary.

## Envelope structs

Some types use intermediate envelope structs for CBOR serialization because
their `Serialize` and `Deserialize` implementations are incompatible with
ciborium (for example, custom tuple serialization paired with derived map
deserialization, or `#[serde(untagged)]`).

The same compatibility rules apply to envelope structs: add new fields with
`#[serde(default)]`, do not remove or rename existing fields.

## Golden byte tests

Every migrated type has a hardcoded `GOLDEN_CBOR_BYTES` constant and two
assertions:

- **`cbor_golden_bytes_can_be_decoded`** — verifies that `from_bytes` can
  decode the golden constant and that re-encoding produces the same bytes.
- **`cbor_encoding_is_stable`** — verifies that encoding the deterministic
  golden value produces exactly the golden constant.

Types whose serialization differs depending on cargo features (e.g.
`SingleSignature`, `ClosedRegistrationEntry`, `SingleSignatureWithRegisteredParty`)
have two `GOLDEN_CBOR_BYTES` constants gated with `#[cfg(not(feature = "snark"))]`
and `#[cfg(feature = "snark")]`.

Types whose encoding is non-deterministic (e.g. `AggregateSignature::Snark`,
because the underlying SNARK proof is non-deterministic) replace the stability
test with a legacy-to-CBOR roundtrip test.

The following table lists every type with its golden byte size(s):

| Type                                 | Bytes      | Feature-gated |
| ------------------------------------ | ---------- | ------------- |
| `MerkleBatchPath`                    | 155        | No            |
| `MerklePath`                         | 149        | `snark` only  |
| `MerkleTree`                         | 485        | No            |
| `SingleSignature`                    | 131 / 396  | Yes           |
| `ClosedRegistrationEntry`            | 219 / 433  | Yes           |
| `SingleSignatureWithRegisteredParty` | 730 / 1721 | Yes           |
| `Initializer`                        | 490        | No            |
| `ConcatenationProof`                 | 2974       | No            |
| `AggregateVerificationKeyForSnark`   | 115        | `snark` only  |
| `AggregateSignature` (Concatenation) | 5937       | No            |
| `AggregateSignature` (Snark)         | 19234      | `snark` only  |

When adding a field with `#[serde(default)]`, the existing golden bytes remain
valid (the new field is absent and defaults). However, the **encoding** of the
golden value will change if the golden value construction produces a non-default
value for the new field. In that case, update the `GOLDEN_CBOR_BYTES` constant
accordingly.

## Summary

| Scenario                                | Action                                                                 |
| --------------------------------------- | ---------------------------------------------------------------------- |
| New code reads legacy bytes             | Automatic — `has_cbor_v1_prefix()` dispatches to `from_bytes_legacy()` |
| New code reads old CBOR (missing field) | `#[serde(default)]` on new fields                                      |
| Old code reads new CBOR (extra field)   | Automatic — ciborium ignores unknown map keys                          |
| Old code re-encodes new CBOR            | Non-idempotent — unknown fields are dropped on round-trip              |
| Add a field                             | Add with `#[serde(default)]`, no version bump                          |
| Remove or rename a field                | Do not — deprecate instead                                             |
| Change a field type                     | Do not — add a new field instead                                       |
| Breaking format change                  | Bump version byte, add new decoder branch                              |
| New type with raw crypto first byte     | Use try-CBOR-then-fallback pattern                                     |
