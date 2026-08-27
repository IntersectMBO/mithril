# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.12.10 (08-28-2026)

### Changed

- Recovered the seven ignored IVC prover input preparation tests, which no CI tier ran because no job passes `--run-ignored`, and retired the two of them that no longer matched the API after the genesis step was simplified.
- Narrowed `IvcProverInput::prepare` and its helpers to a verification context holding only the verifying keys, their fixed bases and the KZG verifier parameters, so that preparing a prover input no longer requires the IVC proving key.
- Rebuilt the preparation tests on the committed assets and removed their inert `OnceLock` fixtures, so that the module needs no key generation, no SRS and no cache and its tests now run in the fast tier.

## 0.12.9 (08-26-2026)

### Changed

- Consolidated the recursive circuit `MockProver` negative tests into one case per transition context, so that the public-statement bindings of a context are covered by a single circuit synthesis instead of one per tampered field.
- Replaced the rejection-only assertions of the recursive circuit negative tests with exact failure signatures, so that each case now requires the circuit to reject through the expected failure class and to implicate exactly the expected public-statement rows.
- Rebuilt the non-genesis `MockProver` fixtures from the committed assets, which makes the same-epoch and next-epoch cases satisfiable when untampered and gives each of them an untampered canary.

## 0.12.8 (08-20-2026)

### Changed

- Extended the on-disk test cache to the recursive circuit fixtures, so the recursive verifying key, the certificate golden circuit keys and the deterministic signer fixture are derived once and shared across test processes instead of being rebuilt by each one.
- Shared the unsafe SRS cache between the circuit test generators and the prover setup, so the SRS is generated once per degree across the whole test suite.

### Removed

- Removed the `StmCircuitError::CircuitKeysCacheLockPoisoned` variant, which became unreachable once the in-process circuit key cache was replaced by the on-disk cache.

## 0.12.7 (08-19-2026)

### Changed

- Updated the slow certificate proof tests to verify the committed golden proof instead of each generating its own, which removes eight proof generations from the test suite.
- Moved the golden certificate proof tests out of the slow test tier so that they run on every pull request.

## 0.12.5 (08-05-2026)

### Changed

- Updated the `verify` function of `IvcProof` to combine its two pairing checks into one. The MSMs are combined by drawing a random scalar from the transcript and using it to scale the accumulator values.

## 0.12.3 (08-05-2026)

### Changed

- Updated the test handling of the unsafe srs. It is now shared across more tests.
- Updated the cache of the test circuit keys so they can be shared more broadly.
- Removed most of the srs downsizing used in the tests.

## 0.12.2 (08-04-2026)

### Changed

- Encoded the proof bytes of the aggregate signature, the SNARK proof and the IVC proof as CBOR byte strings instead of arrays of integers, which halves their encoded size at each nesting level (the previous encoding remains decodable)

## 0.12.1 (08-03-2026)

### Changed

- The `future_snark` feature no longer enables the `rustls` feature: the TLS backend of the SRS download is now selected by the caller, which makes the `native-tls` feature usable.

## 0.12.0 (07-29-2026)

### Added

- Added a `ProtocolError` enum with a `PhiFValueOutOfRange` variant for invalid `phi_f` values

### Changed

- Updated the `from_bytes_legacy` functions for `MerkleTreeBatchCommitment`, `MerkleTree`, `ConcatenationProof` and `SingleSignature`
- Updated the validation of the `phi_f` value in the lottery/eligibility computations
- Updated the visibility of `ClosedKeyRegistration`, `RegistrationEntry` and `ClosedRegistrationEntry` to ensure proper verification of the proof of possession
- Updated `RegisterError::EntryAlreadyRegistered` to no longer carry the conflicting `RegistrationEntry`, since the type is now crate-private
- Updated `ClosedKeyRegistration::number_of_registered_parties` to be available only when the `future_snark` feature is enabled
- Updated `ConcatenationProofSigner::check_lottery` to return `StmResult<Vec<u64>>` instead of `Vec<u64>`

### Removed

- Removed the unused `to_bytes` and `from_bytes` methods from `MerkleTree`

## 0.11.4 (07-27-2026)

### Added

- Added benchmarks for the recursive IVC (SNARK) circuit covering proving (Poseidon and Blake2b transcripts), verification, and off-circuit accumulator folding across the genesis, same-epoch, and next-epoch transition paths, plus cold/warm setup measurements for the SRS and circuit keys, all driven through a `benchmark-internals` façade over the production proof system.
- Added a `mithril-stm/benches/README.md` documenting the recursive IVC and non-recursive certificate benchmarks and the IVC harness's fail-closed CLI.

## 0.11.3 (07-22-2026)

### Changed

- Updated the `from_bytes_legacy` functions for `MerklePath`, `MerkleBatchPath` and `AggregateVerificationKeyForConcatenation`
- Updated the `KeyRegistration` to track the registered key independently from the `registration_entries`

## 0.11.2 (07-20-2026)

### Changed

- Typed the non-recursive (certificate) circuit's `Relation` error boundary: `StmCertificateCircuit::Error` is now `StmCircuitError` (with a `Backend(String)` catch-all and a `From<plonk::Error>` conversion) instead of `plonk::Error`, removing the `to_synthesis_error` flattening adapter so domain-guard errors stay typed end-to-end

## 0.11.1 (07-20-2026)

### Changed

- Updated the transcript hash function for the recursive circuit from `Blake2b512` to the Plutus friendly `Blake2b256`
- Removed `blake2b_simd` dependency to use the `Blake2b256` transcript hash from `midnight-proofs`

## 0.11.0 (07-16-2026)

### Changed

- Upgraded `midnight-circuits` to `7.2.2`, `midnight-curves` to `0.3.1`, `midnight-proofs` to `0.8.1`, and `midnight-zk-stdlib` to `2.3.3`
- Adapted the IVC circuit configuration to the `midnight-circuits 7.2.2` API: replaced `ForeignEccChip`/`ForeignEccConfig` with `ForeignWeierstrassEccChip`/`ForeignWeierstrassEccConfig`
- Removed the `com_instance` dummy fixed-base entry from the IVC circuit's fixed-base map, which is no longer present in the `midnight-circuits 7.2.2` verifying key
- Renamed the internal constants `CERTIFICATE_VERIFICATION_KEY_NAME` and `IVC_VERIFICATION_KEY_NAME` to `CERTIFICATE_FIXED_BASES_PREFIX` and `IVC_FIXED_BASES_PREFIX` to better reflect their role as MSM name prefixes
- Added `check_dual_msm_matches_fixed_bases` pre-flight check in the accumulator module to return an error instead of panicking when the MSM fixed-base names do not match the provided map
- Regenerate the recursive and non-recursive circuit keys

## 0.10.50 (07-16-2026)

### Changed

- Moved the non-recursive (certificate) SNARK circuit verification key out of `SnarkProof` into the certificate's ancillary verifier data (new `AncillaryVerifierData::Snark` carrying a `SnarkVerifierData`); it is sourced from there at verification, making the proof slimmer

## 0.10.49 (07-10-2026)

### Changed

- Refactored the recursive (IVC) circuit for modularity: extracted reusable gadgets (genesis Schnorr, byte-combination) into a new `gadgets` module, moved the witness/public-input assignment and off-circuit accumulator helpers into dedicated modules, and decomposed the state transition into named helpers
- Renamed the circuit's `IvcGadget` to `IvcConstraintBuilder`
- Documented the recursive circuit's constraint builder, gadgets, and instance columns

## 0.10.47 (07-08-2026)

### Changed

- Decoupled the recursive (IVC) circuit from Midnight proving-library types: single-sourced the backend aliases into a dedicated module, adopted the shared `CircuitCurve`, and isolated `Value<T>` behind a local `CircuitValue<T>` alias
- Single-sourced the non-recursive verifying-key serde through its byte codec
- Documented the recursive circuit module, its intentional Midnight couplings, and the serialized accumulator/MSM wire format

## 0.10.46 (07-07-2026)

### Added

- Tests to verify that the degree of the circuits is unchanged

## 0.10.45 (07-07-2026)

### Changed

- Renamed the recursive (IVC) circuit's Midnight backend type aliases to meaningful names

## 0.10.44 (07-06-2026)

### Changed

- Refactors `IvcProverInput::prepare` for readability using helper functions
- Reworked the way the `Genesis` case is handled: now happens when no rolling state is given to the `prove` function
- Renamed variables to clarify which proof or epoch they correspond to
- Added tests for the helper functions

## 0.10.43 (07-02-2026)

### Changed

- Separated the production trusted setup from the deterministic unsafe setup used in tests, so the production SNARK setup no longer relies on any unsafe-setup code path.
- Restructured the certificate and IVC key management around a trusted setup provider and an on-disk key provider, with per-circuit key types and clearer naming.

## 0.10.42 (06-29-2026)

### Changed

- Better context for the `IvcCircuitError::CertificateProofRejected` error
- Better handling of the `GenesisMessagePreimage` in tests
- Name change for the `AncillaryProverData` variant

## 0.10.41 (06-29-2026)

### Added

- `GenesisVerificationKeyBundle`, carrying the trusted genesis verification key supplied to aggregate signature verification.

### Changed

- `AggregateSignature::verify` and `AggregateSignature::batch_verify` now take a genesis verification key bundle and source the genesis Schnorr verification key from it (instead of the certificate-carried `IvcVerifierData`), returning `AggregateSignatureError::MissingGenesisVerificationKeyBundle` when it is absent.

### Removed

- The `genesis_schnorr_verification_key` field from `IvcVerifierData`.
- The unused `AggregationError::MissingRollingStateForNextCertificate` variant.

## 0.10.39 (06-24-2026)

### Added

- Added wiring of the IVC prover and verifier in the `Clerk` and `AggregateSignature`.

### Changed

- `Clerk::aggregate_signatures_with_type` IVC variant is completed.
- `AggregateSignature::verify` IVC variant is completed.
- `IvcProof::verify` now also checks that the input message is the same as the one used to create the proof.
- More fixes: downsizing the srs properly for the ivc keys, proper deserialization of `VerifyingKey`, carrying the `AncillaryVerifierData` in the certificate.

## 0.10.38 (06-17-2026)

### Added

- Added `AncillaryProofOutput`, carrying the optional prover and verifier data produced during aggregate signature creation.

### Changed

- `Clerk::aggregate_signatures_with_type` now returns the aggregate signature together with an `AncillaryProofOutput` instead of the optional `AncillaryVerifierData`.
- `AncillaryGenesisData` now also carries the genesis Schnorr verification key, gated behind the `future_snark` feature.
- `AncillaryProofInput` now also carries the rigid preimage of the protocol message being aggregated, gated behind the `future_snark` feature.

## 0.10.37 (06-17-2026)

### Added

- Added `IvcProver::prove` for IVC SNARK proof generation with genesis bootstrap and incremental step transitions.

## 0.10.36 (06-15-2026)

### Changed

- Renamed the `AncillaryGenesisData` `genesis_message` field to `genesis_message_preimage` and gated it, with its getter, behind the `future_snark` feature.

## 0.10.35 (06-12-2026)

### Added

- Added proof-system-agnostic ancillary data carriers (`AncillaryProverData`, `AncillaryVerifierData`, `AncillaryGenesisData`, and `AncillaryProofInput`) with versioned CBOR `to_bytes`/`from_bytes`.
- Added the `AggregateSignatureType::certifies_full_certificate_chain` predicate.

### Changed

- `Clerk::aggregate_signatures_with_type` now takes an `AncillaryProofInput` and returns the aggregate signature together with the optional `AncillaryVerifierData`.
- `AggregateSignature::verify` and `AggregateSignature::batch_verify` now accept the optional `AncillaryVerifierData`.

## 0.10.34 (06-12-2026)

### Added

- Added `IvcVerifierSetup` structure to bundle the embedded KZG verifier parameters, `tau_g2`, IVC verifying key, and combined fixed-base map needed to verify IVC proofs without loading the full SRS.
- Added `IvcProof::verify` for off-circuit IVC proof verification using a Blake2b transcript.
- Added `IvcProofError::ProofGenerationFailed` error variant for the IVC prove path.

## 0.10.33 (06-11-2026)

### Added

- Added Ivc prover input preparation `IvcProverInput::prepare()`.

## 0.10.30 (06-05-2026)

### Changed

- Aligned `halo2_ivc` APIs with STM and domain-specific types, including typed state and witness fields, certificate and recursive proof byte wrappers, and aggregate verification key protocol-message handling.
- Aligned `halo2_ivc` naming with STM and certificate-circuit terminology across circuit data, state, witness, protocol-message, proof-system callers, and test/generator identifiers.

## 0.10.29 (06-02-2026)

### Changed

- Fixed flakiness in the unit test of the SNARK prover due to race condition on SRS generation.
- Update the signature of the `SnarkProof::verify` to take the SRS verifier parametes as input.

## 0.10.26 (05-28-2026)

### Changed

- Replaced `helpers/` module in `halo2_ivc` with STM equivalents and removed it entirely.
- Moved `MerklePath` and `TryFrom<&StmMerklePath<D>>` adapter to a new shared `circuits/common/merkle` module.
- Added `SchnorrVerificationKey::as_jubjub_subgroup()` crate-private accessor for circuit witness encoding.
- Enriched `MerklePathAdapterError::InvalidDigestLength` with `expected` and `actual` byte-length fields.

## 0.10.25 (05-27-2026)

### Added

- Added constructors for `IvcSetup`, `EpochData`, and `IvcRollingState`.

## 0.10.24 (05-22-2026)

### Changed

- Replaced infallible `IvcCircuit::new` with fallible `try_new` and `unknown` returning `StmResult` with typed `IvcCircuitError` variants.
- Added `validate_self_vk_degree` and `validate_column_counts` pre-flight guards in the `halo2_ivc` circuit.
- Added unit tests for `IvcCircuitError` variants in the `halo2_ivc` off-circuit test suite.

## 0.10.22 (05-21-2026)

### Added

- Added a `SnarkVerifierSetup` structure to hold the SNARK verifier setup parameters (relies on unsafe helpers).

## 0.10.21 (05-21-2026)

### Added

- Added Criterion benchmarks for `StmCertificateCircuit` covering VK/PK setup, proof generation, and verification across small, medium, large, and production parameter tiers.
- Added CI parameter benchmarks comparing `MockProver` and real prover across a range of `k` values, with E2E extrapolation formula and reference results table documented in the README.

### Changed

- Corrected production tier `k` from `2093` to `1944` in benchmarks and README.
- Unified `setup`, `prove`, and `verify` benchmarks into a single Criterion group with consistent flat sampling configuration.

## 0.10.20 (05-19-2026)

### Added

- IVC prover input preparation helper structures defined.
- A SNARK proof verification function that exposes `DualMsm` and will be used by IVC prover is added.

## 0.10.19 (05-15-2026)

### Changed

- Replaced the temporary `Certificate` circuit with the real `StmCertificateCircuit` in the `halo2_ivc` test infrastructure.
- Renamed `StmCircuit` to `StmCertificateCircuit` for consistency with the STM naming convention.

## 0.10.18 (05-12-2026)

### Changed

- Added Layer C2 off-circuit accumulator and verification mechanics tests, covering accumulator construction, fixed-base extraction, collapse, folding pipeline, and combined proof verification.
- Removed `ivc_e2e.rs` test file whose coverage is fully replaced by the golden tests and Layer C2.

## 0.10.17 (05-11-2026)

### Added

- Rigid slot bytes creation for SNARK aggregate verification key and parameters.

## 0.10.16 (05-07-2026)

### Changed

- Added a system to handle the downloading and verification of the SRS and to store it locally.

## 0.10.15 (05-07-2026)

### Changed

- Replaced Layer C1 real-prover slow tests with off-circuit accumulator checks and MockProver-based constraint tests.
- Reduced CI test time by splitting combined test loops into individual tests to enable nextest parallelism.
- Switched MockProver-only tests to load verifying keys from committed binary assets, eliminating redundant SRS generation.

## 0.10.14 (05-06-2026)

### Added

- Added standard Schnorr signature implementation.

## 0.10.13 (05-01-2026)

### Added

- Added golden test to detect when a change in any of the circuits happens.
- Added functions to compute the verification keys for recursive and non-recursive circuits.
- Added a runbook explaining the steps to follow to update the verification keys when a change happens.

## 0.10.12 (04-30-2026)

### Added

- Fixed the flakiness in some of the circuit tests by making the generation of the srs more stable for access by multiple threads.

## 0.10.11 (04-30-2026)

### Added

- Added Layer B state transition tests for the `halo2_ivc` prototype, covering positive and negative transition checks for genesis, same-epoch, and next-epoch steps, including fast asset-based verifier rejections and slow MockProver constraint checks for linkage and hash consistency rules.

## 0.10.10 (04-28-2026)

### Changed

- Moved some tests in slow modules and changed some parameters to make the SNARK tests faster

## 0.10.9 (04-28-2026)

### Changed

- Split slow `MockProver` tests into `mod slow` submodules in the `halo2_ivc` test suite and registered `circuits::halo2_ivc` in the CI slow-test filter, preventing slow tests from triggering on unrelated file changes.

## 0.10.8 (04-28-2026)

### Added

- Added Layer A encoding and transition tests for the `halo2_ivc` prototype, covering preimage byte-range extraction, state public input ordering, genesis state initialisation, accumulator and verifying key serialisation round-trips, tampered-public-input rejection, and MockProver constraint checks for wrong preimage bytes.

## 0.10.6 (04-23-2026)

### Added

- Updated the creation of merkle path during witness generation to use a constant length for the path by completing it with `0` padding.
- Updated the non-recursive circuit to ignore `0` values during the check of the merkle path to exclude the padding from the computation of the root.

## 0.10.5 (04-23-2026)

### Added

- Added Layer D golden tests for the `halo2_ivc` prototype, covering committed asset readers, deterministic asset generators, and a positive golden suite validating stored recursive proofs, the genesis base case, same-epoch and next-epoch recursive steps, and a chained-flow replay check.

## 0.10.4 (04-22-2026)

### Changed

- Enhanced the index selection mechanism of snark proof system.

## 0.10.1 (04-09-2026)

### Changed

- Reduced the `lower_than` constraint bit-length from 32 bits to 16 bits in the non-recursive circuit implementation.

## 0.10.0 (04-09-2026)

### Changed

- Refactored the bytes codec for all types with cbor bytes encoding and decoding, and added support for backward/forward compatibility.

## 0.9.38 (04-09-2026)

### Added

- Added a feature-gated Halo2 IVC prototype module.

## 0.9.37 (04-01-2026)

### Added

- Added a fix for the encoded message received not matching the expected length
- Added a way to save and load the srs and to cache the circuit verification key (only for testing purposes)

## 0.9.36 (03-27-2026)

### Added

- Added support for SNARK in aggregate signature proof systems.

## 0.9.35 (03-26-2026)

### Changed

- Changed proptest range for `phi_f` to not use floats anymore as it was cause severe slowdowns in the computations.

## 0.9.34 (03-24-2026)

### Changed

- Added a verify functionnality to the SnarkProof and a wrapper for MidnightVK to make handling the circuit verification key easier.

## 0.9.33 (03-20-2026)

### Changed

- Switched the Halo2 SNARK transcript from Blake2b to Poseidon in STM proof generation and circuit tests.

## 0.9.32 (03-19-2026)

### Changed

- Created a `SnarkProver` and `SnarkProof` structures in `proof_system/halo2_snark/proof.rs` that are responsible for creating a snark proof.
- Created a `unsafe_helpers.rs` file that handles the unsafe snark setup (`srs`, `circuit` `verification_key`, `proving_key`) that will be replaced later.

## 0.9.31 (03-19-2026)

### Changed

- Refactored the Halo2 STM circuit to clarify module boundaries, keep `circuit.rs` focused on orchestration, split gadget logic into dedicated modules, introduce explicit witness/instance types, and add focused unit tests for adapters and gadgets.

## 0.9.30 (03-16-2026)

### Added

- Added preparation of SNARK prover input.

## 0.9.29 (03-13-2026)

### Changed

- Completed the Halo2 STM naming alignment across circuit types, gadgets, and golden tests, including clearer circuit witness naming and constraint-oriented lottery gadget semantics.

## 0.9.28 (03-12-2026)

### Changed

- Replaced the default lottery target value used to create `ClosedRegistrationEntry` by the actual computation.

## 0.9.27 (03-11-2026)

### Changed

- Introduced circuit-local Halo2 types in `circuits/halo2/types.rs` with shared `CircuitBaseField`, `CircuitBase`, and `CircuitCurve`.
- Replaced duplicated local `F`/`C` aliases with shared circuit types across Halo2 circuit, gadgets, and golden helper code.
- Standardized Halo2 conversion paths using `From`/`Into` implementations for circuit/domain field wrappers.
- Added `circuits/halo2/adapters.rs` to convert STM Merkle paths into Halo2 witness paths for circuit consumption.
- Removed `circuits/halo2/utils/mod.rs` and inlined field-limb split logic into `circuits/halo2/gadgets.rs`.
- Unified synthesis error mapping through `to_synthesis_error` in `circuits/halo2/errors.rs`.

## 0.9.26 (03-09-2026)

### Changed

- Updated the circuit creation function to ensure the types coming from the STM protocol are compatible with the circuit types.

## 0.9.25 (03-06-2026)

### Changed

- Removed panic-based failure paths from the Halo2 SNARK circuit prototype and switched to structured `Result`-based error handling.
- Replaced `assert!(self.quorum < self.num_lotteries)` with explicit validation returning a typed circuit error.
- Added pre-validation guards to reject malformed witnesses and inconsistent Merkle path shapes before Midnight stdlib panics.
- Reworked remaining failure paths in `circuits/halo2/circuit.rs` and `circuits/halo2/gadgets.rs` to return structured errors.
- Updated Halo2 negative tests to assert structured errors rather than using `#[should_panic]`.

## 0.9.24 (03-04-2026)

### Added

- Added SNARK compatibility for signer and single signature.

## 0.9.23 (03-03-2026)

### Changed

- Renamed `DST_SIGNATURE` to `DOMAIN_SEPARATION_TAG_SIGNATURE` in STM signature scheme exports and usage chain.
- Updated Halo2 circuit code to use STM-level `DOMAIN_SEPARATION_TAG_LOTTERY` and `DOMAIN_SEPARATION_TAG_SIGNATURE` directly.

### Removed

- Removed `circuits/halo2/constants.rs` as DST constants are now sourced from STM signature scheme constants.

### Added

- Added Halo2 DST alignment unit tests for:
  - collision guard (`signature DST != lottery DST`),
  - reference signature DST formula check vs STM computation,
  - reference lottery DST formula check vs STM computation.

## 0.9.22 (03-03-2026)

### Added

- Added negative tests for `SingleSignature::verify` to reject invalid inputs (wrong verification key, out-of-bounds index, wrong message, and mismatched registration).

## 0.9.20 (03-02-2026)

### Changed

- Changed the number of iterations of the Taylor expansions used to compute the lottery target value.

## 0.9.19 (02-25-2026)

### Fixed

- Flakiness in the CI due to non deterministic test SRS generation.

## 0.9.18 (02-20-2026)

### Added

- Added a `from_raw` conversion function for `BaseFieldElement` that applies modulus reduction to the input.

## 0.9.17 (02-19-2026)

### Added

- Added the computation of the lottery target value for SNARK.
- Switched back-end for computation from rug to num-integer.

## 0.9.16 (02-18-2026)

### Changed

- Switched Halo2 circuit and golden helpers to reuse existing STM types and implementations.
- Applied internal refactoring and cleanup in Halo2 witness and helper layers.

### Removed

- Removed the `circuits/halo2/off-circuit` module.

## 0.9.15 (02-13-2026)

### Added

- Added SNARK compatibility for key registration.

## 0.9.14 (02-11-2026)

### Added

- Fixed `hash_to_projective_point` function and Schnorr signature implementation to match the circuit.

## 0.9.13 (02-06-2026)

### Added

- Added golden tests for the Halo2 STM circuit.

## 0.9.12 (02-02-2026)

### Added

- Added `halo2_snark` module for `proof_system` and updated `tree.rs` with new leaf type.

## 0.9.11 (01-29-2026)

### Added

- Removed `Ok()` wrapper during conversion from `KeyRegistration` to `MerkleTree`.

## 0.9.10 (01-26-2026)

### Added

- `MerkleTreeSnarkLeaf` is added.

## 0.9.9 (01-23-2026)

### Changed

- Refactored `AggregateVerificationKey` for better SNARK support.

## 0.9.8 (01-23-2026)

### Changed

- `KeyRegistration` functionality is updated to support different types of registrations.

## 0.9.7 (01-23-2026)

### Added

- Implemented `Digest` trait for the Poseidon hash in a new `hash` module.

## 0.9.6 (01-23-2026)

### Added

- Integrated the Halo2 certificate circuit prototype behind the `future_snark` feature.

## 0.9.5 (01-19-2026)

### Changed

- Changed backend for Jubjub and Poseidon to Midnight ZK in `unique_schnorr_signature`.

## 0.9.4 (01-14-2026)

### Changed

- Renamed `schnorr_signature` module to `unique_schnorr_signature`.

## 0.9.3 (01-13-2026)

### Added

- Golden test for `avk` is added.

## 0.9.2 (01-09-2026)

### Added

- Golden test for closed key registration is added.

## 0.9.1 (01-07-2026)

### Added

- `SingleSignatureForConcatenation` is added.

## 0.9.0 (01-05-2026)

### Removed

- Removed the deprecated structures and functions in version `0.5.0`.

## 0.8.4 (12-30-2025)

### Added

- Golden tests added for `SingleSignature`.

## 0.8.3 (12-23-2025)

### Changed

- The `MerkleTreeLeaf` struct is converted to a trait to support multiple leaf types.

## 0.8.2 (12-23-2025)

### Added

- Golden tests added for `MerkleTreeBatchCommitment`.

## 0.8.1 (12-22-2025)

### Added

- Jubjub wrapper is added for `schnorr_signature` module.

## 0.8.0 (12-17-2025)

### Changed

- The `D: Digest` generic is changed with a `D: MembershipDigest` trait supporting multiple hash functions for different proof systems.

## 0.7.0 (12-16-2025)

### Removed

- Basic verifier functionality is removed.

## 0.6.4 (12-12-2025)

### Changed

- Error types in the Stm library moved to corresponding sub-modules.

## 0.6.2 (11-27-2025)

### Changed

- Stm library re-organized for SNARK-friendliness.

## 0.6.1 (11-27-2025)

### Added

- Added Schnorr signature modules.

## 0.6.0 (11-19-2025)

### Changed

- Stm error handling is done with `anyhow`.

## 0.5.5 (10-13-2025)

### Fixed

- Fixed compilation issues with `rug` when targeting `musl` environment.

## 0.5.4 (10-07-2025)

### Added

- Added golden tests for JSON (de)serialization.

## 0.5.3 (10-07-2025)

### Added

- Added support for multiple aggregate signature proof systems.

## 0.5.0 (09-09-2025)

### Changed

- Bumped new minor version for release following deprecations of structure names and functions.

## 0.4.9 (07-07-2025)

### Changed

- Function names are changed.

## 0.4.8 (02-07-2025)

### Deprecated

- Old struct names are deprecated.

## 0.4.6 (27-06-2025)

### Changed

- Struct names are changed.

## 0.4.5 (23-06-2025)

### Changed

- `gen` will become a keyword of the language with Rust 2024 so, `SigningKey::gen` is renamed as `SigningKey::generate`.

### Removed

- Deprecated `batch-verify-aggregates` feature is removed.

## 0.4.4 (12-06-2025)

### Changed

- Fixed the `from_bytes` implementations to avoid panics with safe slice range gets.
- Fixed the `to_bytes`/`from_bytes` implementations of the `StmAggrSig` to support variable length signatures.

### Added

- Integration tests for to ensure correct serialization and deserialization to bytes.

## 0.4.3 (11-06-2025)

### Added

- Added a `parameter` module and `StmParameters` functionality covered by that.

### Changed

- Moved doc test to `lib.rs`.

## 0.4.2 (04-06-2025)

### Added

- Added a `aggregate_signature` module and `StmAggrSig`, `StmAggrVerificationKey`, `StmClerk` and `CoreVerifier` functionality covered by its submodules.

## 0.4.1 (04-06-2025)

### Added

- Added a `single_signature` module and `StmSig` and `StmSigRegParty` functionality covered by its submodules.

## 0.4.0 (15-05-2025)

### Added

- Added a `participant` module and `StmInitializer` and `StmSigner` functionality covered by its submodules.

### Changed

- STM module visibilities are changed.

## 0.3.44 (28-04-2025)

- Removed the build script and deprecated `batch-verify-aggregate` feature as the code behind this feature is now
  compatible with WASM.

## 0.3.43 (05-04-2025)

### Added

- Added a `bls_multi_signature` module and multi-signature functionality covered by its submodules.

## 0.3.41 (20-03-2025)

### Added

- Added a `merkle_tree` module and Merkle tree functionality covered by its submodules:
  - Module `leaf`: Includes structure `MTLeaf` and its implementation.
  - Module `path`: Includes structures `Path` and `BatchPath` and their implementations.
  - Module `commitment`: Includes structures `MerkleTreeCommitment` and `MerkleTreeCommitmentBatchCompat` and their implementations.
  - Module `tree`: Includes structure `MerkleTree` and its implementation.

## 0.3.40 (18-03-2025)

### Changed

- Moved implementation blocks under their respective structures.
- Ordered property tests.

## 0.3.18 (11-04-2024)

- Deprecate `portable` feature:
  - Instead, always enable BLST `portable` feature for runtime check of intel ADX instruction set.
  - `portable` feature now has no effect and should be removed from crate dependencies.

## 0.3.7 (10-10-2023)

### Added

- Implemented a build script that automatically detects that WASM is not targeted, and automatically activates the feature `batch-verify-aggregates` (which enables batch verification of signatures).

## 0.3.0 (10-08-2023)

### Added

- Added `Coreverifier` struct and its functionalities to cover signature procedure for a full node.
- Adapted existing functionality to inherit from a more generic structure `Coreverifier`.
- Added tests for core verification.

## 0.2.5 (15-03-2023)

### Added

- Included helper functions for unsafe code
- Added tests for batch verification

## 0.2.1 (04-01-2023)

### Added

- Batch verification for `StmAggrSig`.

## 0.2.0 (16-12-2022)

### Changed

- Adapted the `Signature` struct, so that it does not contain the verification key and
  the stake, as these values are not required.

## 0.1.0 (05-12-2022)

Initial release.
