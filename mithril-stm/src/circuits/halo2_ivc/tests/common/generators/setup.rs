use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
};

use ff::Field;
use midnight_curves::Bls12;
use midnight_proofs::{
    plonk::{keygen_pk, keygen_vk_with_k},
    poly::kzg::params::{ParamsKZG, ParamsVerifierKZG},
};
use midnight_zk_stdlib as zk_lib;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::AggregateVerificationKeyForSnark;
use crate::circuits::halo2::circuit::StmCertificateCircuit;
use crate::circuits::halo2::keys::NonRecursiveCircuitVerifyingKey;
use crate::circuits::halo2_ivc::RECURSIVE_CIRCUIT_DEGREE;
use crate::circuits::halo2_ivc::accumulator::fixed_bases_and_names_from_verifying_key;
use crate::circuits::halo2_ivc::keys::{RecursiveCircuitProvingKey, RecursiveCircuitVerifyingKey};
use crate::circuits::halo2_ivc::types::MessageHash;
use crate::circuits::halo2_ivc::{
    CERTIFICATE_FIXED_BASES_PREFIX, EmulatedCurve, IVC_FIXED_BASES_PREFIX, NativeField,
    PairingEngine, RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION, circuit::IvcCircuitData,
    state::Global,
};
use crate::circuits::test_utils::file_mutex::FileMutex;
use crate::circuits::trusted_setup::{TrustedSetupProvider, UNSAFE_SRS_SEED};
use crate::codec::{TryFromBytes, TryToBytes};
use crate::membership_commitment::{MerkleTree as StmMerkleTree, MerkleTreeSnarkLeaf};
use crate::signature_scheme::{
    BaseFieldElement, SchnorrSigningKey, SchnorrVerificationKey, StandardSchnorrSignature,
};
use crate::{MembershipDigest, MithrilMembershipDigest, Parameters};

use super::super::field_encoding::jubjub_base_from_raw_le_bytes;
use super::super::{ASSET_SEED, CERTIFICATE_CIRCUIT_DEGREE};
use super::transitions::build_genesis_protocol_message;

type SnarkHash = <MithrilMembershipDigest as MembershipDigest>::SnarkHash;
type SignerRegistrationMerkleTree = StmMerkleTree<SnarkHash, MerkleTreeSnarkLeaf>;

pub(super) const INITIAL_CHAIN_LENGTH: usize = 3;
pub(crate) const GENESIS_EPOCH: u64 = 5;
pub(crate) const QUORUM_SIZE: u32 = 2;
pub(crate) const SIGNER_COUNT: usize = 3000;
/// Total stake committed by the deterministic AVK used in asset generation.
pub(crate) const TOTAL_STAKE: u64 = 1_000_000;

/// Paths for the minimal stored asset set used by asset-based golden tests.
#[derive(Debug, Clone)]
pub(super) struct AssetPaths {
    /// Path to the stored recursive chain checkpoint asset.
    pub(super) recursive_chain_state: PathBuf,
    /// Path to the stored verification-context asset.
    pub(super) verification_context: PathBuf,
    /// Path to the stored one-step recursive output asset.
    pub(super) recursive_step_output: PathBuf,
    /// Path to the stored genesis step output asset.
    pub(super) genesis_step_output: PathBuf,
    /// Path to the stored same-epoch step output asset.
    pub(super) same_epoch_step_output: PathBuf,
    /// Path to the stored first-step certificate asset.
    pub(super) first_step_cert: PathBuf,
    /// Path to the additive genesis benchmark fixture asset.
    pub(super) genesis_benchmark_fixture: PathBuf,
}

impl AssetPaths {
    /// Builds the committed asset paths rooted at `base_dir`.
    pub(super) fn new(base_dir: PathBuf) -> Self {
        Self {
            recursive_chain_state: base_dir.join("recursive_chain_state.bin"),
            verification_context: base_dir.join("verification_context.bin"),
            recursive_step_output: base_dir.join("recursive_step_output.bin"),
            genesis_step_output: base_dir.join("genesis_step_output.bin"),
            same_epoch_step_output: base_dir.join("same_epoch_step_output.bin"),
            first_step_cert: base_dir.join("first_step_cert.bin"),
            genesis_benchmark_fixture: base_dir.join("genesis_benchmark_fixture.bin"),
        }
    }
}

impl Default for AssetPaths {
    fn default() -> Self {
        Self::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/circuits/halo2_ivc/tests/assets"),
        )
    }
}

/// Deterministic setup data for asset generation.
///
/// This carries the shared `halo2_ivc` context needed to reproduce the same
/// stored asset contents across runs.
#[derive(Debug)]
pub(crate) struct AssetGenerationSetup {
    /// Deterministic certificate relation used by the golden generators.
    pub(crate) certificate_relation: StmCertificateCircuit,
    /// Verification key for the trusted genesis signature.
    pub(crate) genesis_verification_key: SchnorrVerificationKey,
    /// Hash of the deterministic genesis protocol message.
    pub(crate) genesis_message: MessageHash,
    /// Deterministic trusted genesis signature.
    pub(crate) genesis_signature: StandardSchnorrSignature,
    /// Deterministic signer-membership Merkle tree.
    pub(crate) merkle_tree: SignerRegistrationMerkleTree,
    /// Leaves committed into the deterministic signer-membership tree.
    pub(crate) merkle_tree_leaves: Vec<MerkleTreeSnarkLeaf>,
    /// Deterministic signing keys used to build certificate witnesses.
    pub(crate) signing_keys: Vec<SchnorrSigningKey>,
    /// Deterministic aggregate verification key committed by generated protocol messages.
    pub(crate) aggregate_verification_key:
        AggregateVerificationKeyForSnark<MithrilMembershipDigest>,
    /// Deterministic next Merkle-tree commitment committed by the genesis message.
    pub(crate) genesis_next_merkle_tree_commitment: NativeField,
    /// Deterministic next protocol parameters committed by the genesis message.
    pub(crate) genesis_next_protocol_parameters: NativeField,
}

/// Shared recursive verifier-side setup reused by generators and golden helpers.
pub(crate) struct SharedRecursiveContext {
    /// Shared universal KZG parameters built at the maximum circuit degree.
    pub(crate) universal_kzg_parameters: ParamsKZG<Bls12>,
    /// Verifier-side view of the shared universal KZG parameters.
    pub(crate) universal_verifier_params: ParamsVerifierKZG<PairingEngine>,
    /// Certificate-sized commitment parameters derived from the shared SRS.
    pub(crate) certificate_commitment_parameters: ParamsKZG<Bls12>,
    /// Recursive-circuit-sized commitment parameters derived from the shared SRS.
    pub(crate) recursive_commitment_parameters: ParamsKZG<Bls12>,
    /// Verifying key for the certificate relation.
    pub(crate) certificate_verifying_key: NonRecursiveCircuitVerifyingKey,
    /// Verifying key for the recursive IVC circuit.
    pub(crate) recursive_verifying_key: RecursiveCircuitVerifyingKey,
}

/// Builds the deterministic signer keys, leaves, and commitment tree used by the assets.
fn build_merkle_tree(
    random_generator: &mut (impl RngCore + CryptoRng),
    signer_count: usize,
) -> (
    Vec<SchnorrSigningKey>,
    Vec<MerkleTreeSnarkLeaf>,
    SignerRegistrationMerkleTree,
) {
    let mut signing_keys = Vec::with_capacity(signer_count);
    let mut merkle_tree_leaves = Vec::with_capacity(signer_count);
    for _ in 0..signer_count {
        let signing_key = SchnorrSigningKey::generate(random_generator);
        let schnorr_vk = SchnorrVerificationKey::new_from_signing_key(signing_key.clone());
        merkle_tree_leaves.push(MerkleTreeSnarkLeaf(
            schnorr_vk,
            BaseFieldElement::from(-NativeField::ONE),
        ));
        signing_keys.push(signing_key);
    }

    let merkle_tree = StmMerkleTree::new(&merkle_tree_leaves);
    (signing_keys, merkle_tree_leaves, merkle_tree)
}

fn merkle_tree_commitment_from_stm_tree(merkle_tree: &SignerRegistrationMerkleTree) -> NativeField {
    let commitment = merkle_tree.to_merkle_tree_commitment();
    // `MidnightPoseidonDigest` emits Jubjub base-field roots with `to_bytes_le()`;
    // the recursive state stores the same root as the circuit field element.
    let root_bytes: [u8; 32] = commitment
        .root
        .as_slice()
        .try_into()
        .expect("STM Merkle-tree commitment should be 32 bytes");
    NativeField::from_bytes_le(&root_bytes)
        .into_option()
        .expect("STM Merkle-tree commitment should be a canonical field element")
}

/// Builds the shared universal KZG parameters that both circuits derive from.
pub(crate) fn build_deterministic_params(circuit_degree: u32) -> ParamsKZG<Bls12> {
    ParamsKZG::<Bls12>::unsafe_setup(circuit_degree, ChaCha20Rng::seed_from_u64(ASSET_SEED))
}

/// Loads the shared unsafe SRS of degree `circuit_degree` from the content-keyed test cache,
/// generating and persisting it on a miss.
///
/// The cache entry is the one [`IvcSnarkProverSetup::build_for_test`] writes: both derive their SRS
/// from the same seed, so the bytes are identical and the generation cost is paid once per degree
/// across the whole test suite. The lock is released as soon as the parameters are loaded, so a
/// caller can then take a second cache lock without holding two at once.
fn load_shared_unsafe_srs(circuit_degree: u32) -> ParamsKZG<Bls12> {
    let srs_cache = FileMutex::for_shared_cache("unsafe-srs", &[&UNSAFE_SRS_SEED.to_le_bytes()]);
    let srs_directory = srs_cache.directory().to_path_buf();
    let _srs_cache_lock = srs_cache.lock().expect("the shared unsafe SRS cache should lock");

    TrustedSetupProvider::with_unsafe_srs(&srs_directory, circuit_degree)
        .get_trusted_setup_parameters()
        .expect("the shared unsafe SRS should load from the test cache")
}

/// File holding the cached recursive verifying key inside its fingerprinted cache directory.
const RECURSIVE_VERIFYING_KEY_CACHE_FILE: &str = "recursive-verifying-key";

/// Where the expensive recursive verifying key comes from.
enum RecursiveVerifyingKeySource {
    /// Always derived. Required wherever the result is written to a committed asset.
    Derived,
    /// Loaded from the content-keyed test cache, derived only on a miss.
    Cached,
}

/// Derives the recursive verifying key for the default IVC circuit shape (about 8.9 s).
fn derive_recursive_verifying_key(
    recursive_commitment_parameters: &ParamsKZG<Bls12>,
    certificate_verifying_key: &NonRecursiveCircuitVerifyingKey,
) -> RecursiveCircuitVerifyingKey {
    let default_ivc_circuit =
        IvcCircuitData::unknown(certificate_verifying_key).expect("valid IvcCircuitData unknown");
    RecursiveCircuitVerifyingKey::new(
        keygen_vk_with_k(
            recursive_commitment_parameters,
            &default_ivc_circuit,
            RECURSIVE_CIRCUIT_DEGREE,
        )
        .expect("recursive verifying key generation should not fail"),
    )
}

/// Reads `cache_file`, or builds the value and publishes it there on a miss.
///
/// An absent file, a decode failure, or any byte difference on re-encoding counts as a miss and is
/// rebuilt rather than reported: a corrupt test cache must never fail a test run. This is
/// deliberately unlike [`KeyProvider`](crate::circuits::key_provider::KeyProvider), which
/// propagates deserialization errors. The re-encode comparison is what rejects trailing or
/// non-canonical bytes, since the verifying-key codec stops at the end of the key and ignores
/// whatever follows it.
fn load_or_build<T: TryToBytes + TryFromBytes>(cache_file: &Path, build: impl FnOnce() -> T) -> T {
    if let Some(cached) = read_cache_file(cache_file) {
        return cached;
    }

    let value = build();
    store_cache_file(cache_file, &value);
    value
}

/// Returns the cached value, or `None` when the entry is absent, undecodable, or not byte-identical
/// to a re-encoding of what it decodes to.
fn read_cache_file<T: TryToBytes + TryFromBytes>(cache_file: &Path) -> Option<T> {
    let bytes = std::fs::read(cache_file).ok()?;
    let value = T::try_from_bytes(&bytes).ok()?;
    (value.to_bytes_vec().ok()? == bytes).then_some(value)
}

/// Publishes `value` at `cache_file` durably: a per-process temporary sibling is written, fsynced,
/// then renamed, so a reader sees either no file or the whole value.
fn store_cache_file<T: TryToBytes>(cache_file: &Path, value: &T) {
    let bytes = value.to_bytes_vec().expect("the cached value should serialize");
    let directory = cache_file
        .parent()
        .expect("the cache file should have a parent directory");
    std::fs::create_dir_all(directory).expect("the cache directory should be created");

    let temporary_file = directory.join(format!(
        "{RECURSIVE_VERIFYING_KEY_CACHE_FILE}.{}.temp",
        std::process::id()
    ));
    let mut file = std::fs::File::create(&temporary_file).expect("the temporary file should open");
    file.write_all(&bytes).expect("the cached value should be written");
    file.sync_all().expect("the cached value should be flushed");
    drop(file);
    std::fs::rename(&temporary_file, cache_file).expect("the cached value should be published");

    // Makes the rename itself durable. Best effort: on platforms where a directory cannot be
    // opened this is a no-op, and losing a test-cache entry only costs a rebuild.
    let _ = std::fs::File::open(directory).and_then(|directory_file| directory_file.sync_all());
}

/// Builds the shared verifier-side recursive setup, **always deriving** the recursive verifying key.
///
/// Asset generators must use this: they write committed assets, and a stale cached key would
/// silently produce assets derived from it. Behavior tests that only read should call
/// [`build_shared_recursive_context_from_cache`].
pub(crate) fn build_shared_recursive_context(
    setup: &AssetGenerationSetup,
) -> SharedRecursiveContext {
    build_shared_recursive_context_with(setup, RecursiveVerifyingKeySource::Derived)
}

/// Builds the shared verifier-side recursive setup, taking the recursive verifying key from the
/// content-keyed test cache when one is present.
///
/// The cache address folds in the freshly derived certificate verifying key, the committed
/// production recursive key, both circuit degrees, and the SRS seed, so a change to the certificate
/// circuit or a regenerated production key resolves to a different entry. **Never call this from an
/// asset generator** — see [`build_shared_recursive_context`].
pub(crate) fn build_shared_recursive_context_from_cache(
    setup: &AssetGenerationSetup,
) -> SharedRecursiveContext {
    build_shared_recursive_context_with(setup, RecursiveVerifyingKeySource::Cached)
}

fn build_shared_recursive_context_with(
    setup: &AssetGenerationSetup,
    recursive_verifying_key_source: RecursiveVerifyingKeySource,
) -> SharedRecursiveContext {
    let shared_srs_degree = RECURSIVE_CIRCUIT_DEGREE.max(CERTIFICATE_CIRCUIT_DEGREE);
    let universal_kzg_parameters = load_shared_unsafe_srs(shared_srs_degree);
    let universal_verifier_params = universal_kzg_parameters.verifier_params();

    let params_for = |degree| {
        if degree == shared_srs_degree {
            universal_kzg_parameters.clone()
        } else {
            build_deterministic_params(degree)
        }
    };

    let (certificate_commitment_parameters, recursive_commitment_parameters) = (
        params_for(CERTIFICATE_CIRCUIT_DEGREE),
        params_for(RECURSIVE_CIRCUIT_DEGREE),
    );

    // Derived on every call: at about 93 ms it is not worth caching, and its bytes are what make
    // the recursive key's cache address sensitive to the certificate circuit.
    let certificate_verifying_key = NonRecursiveCircuitVerifyingKey::new(zk_lib::setup_vk(
        &certificate_commitment_parameters,
        &setup.certificate_relation,
    ));

    let recursive_verifying_key = match recursive_verifying_key_source {
        RecursiveVerifyingKeySource::Derived => derive_recursive_verifying_key(
            &recursive_commitment_parameters,
            &certificate_verifying_key,
        ),
        RecursiveVerifyingKeySource::Cached => {
            let certificate_verifying_key_bytes = certificate_verifying_key
                .to_bytes_vec()
                .expect("the certificate verifying key should serialize");
            let key_cache = FileMutex::for_shared_cache(
                "ivc-recursive-verifying-key-v1",
                &[
                    &certificate_verifying_key_bytes,
                    RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
                    &RECURSIVE_CIRCUIT_DEGREE.to_le_bytes(),
                    &CERTIFICATE_CIRCUIT_DEGREE.to_le_bytes(),
                    &UNSAFE_SRS_SEED.to_le_bytes(),
                ],
            );
            let cache_file = key_cache.directory().join(RECURSIVE_VERIFYING_KEY_CACHE_FILE);
            let _key_cache_lock = key_cache
                .lock()
                .expect("the recursive verifying key cache should lock");

            load_or_build(&cache_file, || {
                derive_recursive_verifying_key(
                    &recursive_commitment_parameters,
                    &certificate_verifying_key,
                )
            })
        }
    };

    SharedRecursiveContext {
        universal_kzg_parameters,
        universal_verifier_params,
        certificate_commitment_parameters,
        recursive_commitment_parameters,
        certificate_verifying_key,
        recursive_verifying_key,
    }
}

/// Builds the recursive proving key for the default IVC circuit shape.
pub(crate) fn build_recursive_proving_key(
    context: &SharedRecursiveContext,
) -> RecursiveCircuitProvingKey {
    let default_ivc_circuit = IvcCircuitData::unknown(&context.certificate_verifying_key)
        .expect("valid IvcCircuitData unknown");
    RecursiveCircuitProvingKey::new(
        keygen_pk(
            context.recursive_verifying_key.verifying_key().clone(),
            &default_ivc_circuit,
        )
        .expect("recursive proving key generation should not fail"),
    )
}

/// Returns the certificate, recursive, and combined fixed-base maps.
pub(crate) fn build_recursive_fixed_bases(
    certificate_verifying_key: &NonRecursiveCircuitVerifyingKey,
    recursive_verifying_key: &RecursiveCircuitVerifyingKey,
) -> (
    BTreeMap<String, EmulatedCurve>,
    BTreeMap<String, EmulatedCurve>,
    BTreeMap<String, EmulatedCurve>,
) {
    let (certificate_fixed_bases, _) = fixed_bases_and_names_from_verifying_key(
        CERTIFICATE_FIXED_BASES_PREFIX,
        certificate_verifying_key.as_ref(),
    );
    let (recursive_fixed_bases, _) = fixed_bases_and_names_from_verifying_key(
        IVC_FIXED_BASES_PREFIX,
        recursive_verifying_key.as_ref(),
    );
    let mut combined_fixed_bases = certificate_fixed_bases.clone();
    combined_fixed_bases.extend(recursive_fixed_bases.clone());

    (
        certificate_fixed_bases,
        recursive_fixed_bases,
        combined_fixed_bases,
    )
}

/// Builds the shared recursive global inputs from the deterministic setup.
pub(crate) fn build_recursive_global(
    setup: &AssetGenerationSetup,
    certificate_verifying_key: &NonRecursiveCircuitVerifyingKey,
    recursive_verifying_key: &RecursiveCircuitVerifyingKey,
) -> Global {
    Global::new(
        setup.genesis_message,
        setup.genesis_verification_key,
        certificate_verifying_key,
        recursive_verifying_key,
    )
}

/// Builds the deterministic shared setup used by all asset generators.
pub(crate) fn build_asset_generation_setup() -> AssetGenerationSetup {
    let mut rng = ChaCha20Rng::seed_from_u64(ASSET_SEED);

    let depth = SIGNER_COUNT.next_power_of_two().trailing_zeros();
    let number_of_lotteries = QUORUM_SIZE * 10;
    let total_stake = TOTAL_STAKE;

    let certificate_relation = StmCertificateCircuit::try_new(
        &Parameters {
            k: QUORUM_SIZE as u64,
            m: number_of_lotteries as u64,
            phi_f: 0.2,
        },
        depth,
    )
    .expect("certificate relation construction should not fail");
    let (signing_keys, merkle_tree_leaves, merkle_tree) = build_merkle_tree(&mut rng, SIGNER_COUNT);
    let genesis_next_merkle_tree_commitment = merkle_tree_commitment_from_stm_tree(&merkle_tree);

    let aggregate_verification_key = {
        let commitment = merkle_tree.to_merkle_tree_commitment();
        // `AggregateVerificationKeyForSnark` has no public constructor from
        // commitment plus stake. Decode the deterministic components once, and
        // let protocol-message builders serialize this STM type in the
        // production-compatible message-part format.
        let mut avk_input = [0u8; 40];
        avk_input[0..32].copy_from_slice(&commitment.root);
        avk_input[32..40].copy_from_slice(&total_stake.to_be_bytes());
        AggregateVerificationKeyForSnark::<MithrilMembershipDigest>::from_bytes(&avk_input)
            .expect("deterministic aggregate verification key should decode")
    };

    let genesis_signing_key = SchnorrSigningKey::generate(&mut rng);
    let genesis_verification_key =
        SchnorrVerificationKey::new_from_signing_key(genesis_signing_key.clone());
    let genesis_epoch = GENESIS_EPOCH;
    let genesis_next_protocol_parameters = NativeField::from(7u64);

    let genesis_message = {
        let protocol_message = build_genesis_protocol_message(
            &aggregate_verification_key,
            genesis_next_protocol_parameters.to_bytes_le(),
            genesis_epoch,
        );
        let preimage = protocol_message
            .try_rigid_preimage()
            .expect("genesis protocol message preimage should succeed");
        let message_hash = Sha256::digest(preimage);
        jubjub_base_from_raw_le_bytes(message_hash.as_ref())
    };

    let genesis_message_base = BaseFieldElement::from(genesis_message);
    let genesis_signature = genesis_signing_key
        .sign_standard(&[genesis_message_base], &mut rng)
        .expect("deterministic genesis signature should be produced");
    genesis_signature
        .verify(&[genesis_message_base], &genesis_verification_key)
        .expect("deterministic genesis signature should verify");

    AssetGenerationSetup {
        certificate_relation,
        genesis_verification_key,
        genesis_message: MessageHash::from_field(genesis_message),
        genesis_signature,
        merkle_tree,
        merkle_tree_leaves,
        signing_keys,
        aggregate_verification_key,
        genesis_next_merkle_tree_commitment,
        genesis_next_protocol_parameters,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use tempfile::TempDir;

    use super::*;
    use crate::StmResult;

    /// Stand-in for a cached key: cheap to build, and its encoding is exact, so the tests exercise
    /// the cache protocol itself rather than a verifying key's cost.
    #[derive(Debug, PartialEq, Eq)]
    struct CachedValue(Vec<u8>);

    impl TryToBytes for CachedValue {
        fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    impl TryFromBytes for CachedValue {
        fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
            if bytes.len() < 4 {
                return Err(anyhow::anyhow!("a cached value is at least four bytes"));
            }
            // Decodes a fixed-width prefix and ignores the rest, mirroring the verifying-key codec
            // that stops at the end of the key.
            Ok(Self(bytes[..4].to_vec()))
        }
    }

    /// Builder that records how many times it ran, so a cache hit is observable without inspecting
    /// or mutating key material.
    struct CountingBuilder {
        calls: Cell<usize>,
    }

    impl CountingBuilder {
        fn new() -> Self {
            Self {
                calls: Cell::new(0),
            }
        }

        fn build(&self) -> CachedValue {
            self.calls.set(self.calls.get() + 1);
            CachedValue(vec![1, 2, 3, 4])
        }
    }

    fn cache_file_in(directory: &TempDir) -> PathBuf {
        directory.path().join(RECURSIVE_VERIFYING_KEY_CACHE_FILE)
    }

    #[test]
    fn cold_cache_builds_the_value_and_publishes_it() {
        let directory = TempDir::new().expect("temporary directory");
        let cache_file = cache_file_in(&directory);
        let builder = CountingBuilder::new();

        let value = load_or_build(&cache_file, || builder.build());

        assert_eq!(builder.calls.get(), 1, "a cold cache must build once");
        assert_eq!(value, CachedValue(vec![1, 2, 3, 4]));
        assert!(cache_file.exists(), "the entry must be published");
    }

    #[test]
    fn warm_cache_returns_the_stored_value_without_building() {
        let directory = TempDir::new().expect("temporary directory");
        let cache_file = cache_file_in(&directory);
        let builder = CountingBuilder::new();

        let first = load_or_build(&cache_file, || builder.build());
        let second = load_or_build(&cache_file, || builder.build());

        assert_eq!(builder.calls.get(), 1, "a warm cache must not rebuild");
        assert_eq!(first, second);
    }

    #[test]
    fn truncated_entry_is_treated_as_a_miss() {
        let directory = TempDir::new().expect("temporary directory");
        let cache_file = cache_file_in(&directory);
        let builder = CountingBuilder::new();
        load_or_build(&cache_file, || builder.build());

        std::fs::write(&cache_file, [1, 2]).expect("the entry should be truncated");
        let value = load_or_build(&cache_file, || builder.build());

        assert_eq!(builder.calls.get(), 2, "a truncated entry must be rebuilt");
        assert_eq!(value, CachedValue(vec![1, 2, 3, 4]));
    }

    #[test]
    fn trailing_bytes_are_rejected_rather_than_ignored() {
        let directory = TempDir::new().expect("temporary directory");
        let cache_file = cache_file_in(&directory);
        let builder = CountingBuilder::new();
        load_or_build(&cache_file, || builder.build());

        // The decoder itself would accept these bytes and silently ignore the tail; the re-encode
        // comparison is what rejects them.
        std::fs::write(&cache_file, [1, 2, 3, 4, 99]).expect("the entry should gain a tail");
        let value = load_or_build(&cache_file, || builder.build());

        assert_eq!(builder.calls.get(), 2, "trailing bytes must be rebuilt");
        assert_eq!(value, CachedValue(vec![1, 2, 3, 4]));
    }

    #[test]
    fn distinct_fingerprints_resolve_to_distinct_entries() {
        let seed_bytes = UNSAFE_SRS_SEED.to_le_bytes();
        let one =
            FileMutex::for_shared_cache("ivc-recursive-verifying-key-v1", &[b"a", &seed_bytes]);
        let other =
            FileMutex::for_shared_cache("ivc-recursive-verifying-key-v1", &[b"b", &seed_bytes]);

        assert_ne!(
            one.directory(),
            other.directory(),
            "a fingerprint change must resolve elsewhere"
        );
    }
}
