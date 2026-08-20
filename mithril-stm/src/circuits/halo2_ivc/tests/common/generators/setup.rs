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
use serde::{Deserialize, Serialize};
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
use crate::codec::{TryFromBytes, TryToBytes, from_versioned_bytes, to_cbor_bytes};
use crate::membership_commitment::{MerkleTree as StmMerkleTree, MerkleTreeSnarkLeaf};
use crate::signature_scheme::{
    BaseFieldElement, SchnorrSigningKey, SchnorrVerificationKey, StandardSchnorrSignature,
};
use crate::{MembershipDigest, MithrilMembershipDigest, Parameters, StmResult};

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
/// This is the entry [`IvcSnarkProverSetup::build_for_test`] writes: both derive from the same
/// seed, so the generation cost is paid once per degree across the whole suite.
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
    /// Always derived. Required wherever the result is written to a committed asset, so today it is
    /// reached only from the asset generators.
    Derived,
    /// Loaded from the content-keyed test cache, derived only on a miss. The path for tests, which
    /// read committed assets rather than write them.
    Cached,
}

/// Derives the recursive verifying key for the default IVC circuit shape, on the order of ten
/// seconds.
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

/// Content-keyed cache entry holding the recursive verifying key derived from these inputs.
///
/// Every input is a parameter, so the address is a pure function of them and a test can vary each
/// one.
fn recursive_verifying_key_cache(
    certificate_verifying_key_bytes: &[u8],
    production_recursive_verifying_key: &[u8],
    recursive_circuit_degree: u32,
    certificate_circuit_degree: u32,
    unsafe_srs_seed: u64,
) -> FileMutex {
    FileMutex::for_shared_cache(
        "ivc-recursive-verifying-key-v1",
        &[
            certificate_verifying_key_bytes,
            production_recursive_verifying_key,
            &recursive_circuit_degree.to_le_bytes(),
            &certificate_circuit_degree.to_le_bytes(),
            &unsafe_srs_seed.to_le_bytes(),
        ],
    )
}

/// Content-keyed cache entry holding the signer fixture built from these inputs.
fn signer_fixture_cache(
    signer_count: usize,
    asset_seed: u64,
    total_stake: u64,
    genesis_epoch: u64,
    genesis_next_protocol_parameters: u64,
) -> FileMutex {
    FileMutex::for_shared_cache(
        "ivc-signer-fixture-v1",
        &[
            &signer_count.to_le_bytes(),
            &asset_seed.to_le_bytes(),
            &total_stake.to_le_bytes(),
            &genesis_epoch.to_le_bytes(),
            &genesis_next_protocol_parameters.to_le_bytes(),
        ],
    )
}

/// Reads `cache_file`, or builds the value and publishes it there on a miss.
///
/// An entry that is absent, unreadable, not canonically encoded or rejected by `is_valid` is
/// rebuilt rather than reported: a spoiled test cache must not fail a test run. Anything that does
/// pass is trusted, which is acceptable only because this cache is disposable and is never read by
/// anything that writes committed assets.
fn load_or_build<T: TryToBytes + TryFromBytes>(
    cache_file: &Path,
    is_valid: impl FnOnce(&T) -> bool,
    build: impl FnOnce() -> T,
) -> T {
    if let Some(cached) = read_cache_file(cache_file).filter(is_valid) {
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

    let file_name = cache_file
        .file_name()
        .expect("the cache file should have a name")
        .to_string_lossy();
    let temporary_file = directory.join(format!("{file_name}.{}.temp", std::process::id()));
    let mut file = std::fs::File::create(&temporary_file).expect("the temporary file should open");
    file.write_all(&bytes).expect("the cached value should be written");
    file.sync_all().expect("the cached value should be flushed");
    drop(file);
    std::fs::rename(&temporary_file, cache_file).expect("the cached value should be published");

    // Makes the rename itself durable. Best effort: on platforms where a directory cannot be
    // opened this is a no-op, and losing a test-cache entry only costs a rebuild.
    let _ = std::fs::File::open(directory).and_then(|directory_file| directory_file.sync_all());
}

/// Builds the shared verifier-side recursive setup, always deriving the recursive verifying key.
///
/// Asset generators must use this: a stale cached key would silently produce assets derived from
/// it. Read-only behavior tests should call [`build_shared_recursive_context_from_cache`].
pub(crate) fn build_shared_recursive_context(
    setup: &AssetGenerationSetup,
) -> SharedRecursiveContext {
    build_shared_recursive_context_with(setup, RecursiveVerifyingKeySource::Derived)
}

/// Builds the shared verifier-side recursive setup, taking the recursive verifying key from the
/// content-keyed test cache when one is present.
///
/// **Never call this from an asset generator** — see [`build_shared_recursive_context`].
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
            load_shared_unsafe_srs(degree)
        }
    };

    let (certificate_commitment_parameters, recursive_commitment_parameters) = (
        params_for(CERTIFICATE_CIRCUIT_DEGREE),
        params_for(RECURSIVE_CIRCUIT_DEGREE),
    );

    // Derived on every call: on the order of 100 milliseconds, so not worth caching, and its bytes
    // are what make the recursive key's cache address sensitive to the certificate circuit.
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
            let key_cache = recursive_verifying_key_cache(
                &certificate_verifying_key_bytes,
                RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
                RECURSIVE_CIRCUIT_DEGREE,
                CERTIFICATE_CIRCUIT_DEGREE,
                UNSAFE_SRS_SEED,
            );
            let cache_file = key_cache.directory().join(RECURSIVE_VERIFYING_KEY_CACHE_FILE);
            let _key_cache_lock = key_cache
                .lock()
                .expect("the recursive verifying key cache should lock");

            load_or_build(
                &cache_file,
                // A verifying key is self-describing: the byte round trip is the whole check.
                |_| true,
                || {
                    derive_recursive_verifying_key(
                        &recursive_commitment_parameters,
                        &certificate_verifying_key,
                    )
                },
            )
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

/// Value committed by the genesis message as the next protocol parameters.
const GENESIS_NEXT_PROTOCOL_PARAMETERS: u64 = 7;

/// File holding the cached signer fixture inside its fingerprinted cache directory.
const SIGNER_FIXTURE_CACHE_FILE: &str = "signer-fixture";

/// The random-generator-derived half of [`AssetGenerationSetup`].
///
/// One seeded generator produces the signer keys **and then** the genesis key and signature, so
/// caching only the tree would leave it at a different position and silently change the genesis
/// material the committed assets embed. Everything drawn from the generator is cached together.
#[derive(Serialize, Deserialize)]
struct CachedSignerFixture {
    signing_keys: Vec<SchnorrSigningKey>,
    merkle_tree_leaves: Vec<MerkleTreeSnarkLeaf>,
    merkle_tree: SignerRegistrationMerkleTree,
    genesis_verification_key: SchnorrVerificationKey,
    genesis_signature: StandardSchnorrSignature,
}

impl TryToBytes for CachedSignerFixture {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        to_cbor_bytes(self)
    }
}

impl TryFromBytes for CachedSignerFixture {
    fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
        from_versioned_bytes(bytes, |_| {
            Err(anyhow::anyhow!(
                "the cached signer fixture is not in the current codec version"
            ))
        })
    }
}

/// The genesis values every consumer needs, all derived from the signer Merkle tree and constants.
struct DerivedGenesisData {
    aggregate_verification_key: AggregateVerificationKeyForSnark<MithrilMembershipDigest>,
    genesis_next_merkle_tree_commitment: NativeField,
    genesis_next_protocol_parameters: NativeField,
    genesis_message: NativeField,
}

/// Recomputes the derived genesis values from the signer Merkle tree.
///
/// Used on both the cached and uncached paths, so the two can never disagree.
fn derive_genesis_data(merkle_tree: &SignerRegistrationMerkleTree) -> DerivedGenesisData {
    let genesis_next_merkle_tree_commitment = merkle_tree_commitment_from_stm_tree(merkle_tree);

    let aggregate_verification_key = {
        let commitment = merkle_tree.to_merkle_tree_commitment();
        // `AggregateVerificationKeyForSnark` has no public constructor from
        // commitment plus stake. Decode the deterministic components once, and
        // let protocol-message builders serialize this STM type in the
        // production-compatible message-part format.
        let mut avk_input = [0u8; 40];
        avk_input[0..32].copy_from_slice(&commitment.root);
        avk_input[32..40].copy_from_slice(&TOTAL_STAKE.to_be_bytes());
        AggregateVerificationKeyForSnark::<MithrilMembershipDigest>::from_bytes(&avk_input)
            .expect("deterministic aggregate verification key should decode")
    };

    let genesis_next_protocol_parameters = NativeField::from(GENESIS_NEXT_PROTOCOL_PARAMETERS);

    let genesis_message = {
        let protocol_message = build_genesis_protocol_message(
            &aggregate_verification_key,
            genesis_next_protocol_parameters.to_bytes_le(),
            GENESIS_EPOCH,
        );
        let preimage = protocol_message
            .try_rigid_preimage()
            .expect("genesis protocol message preimage should succeed");
        let message_hash = Sha256::digest(preimage);
        jubjub_base_from_raw_le_bytes(message_hash.as_ref())
    };

    DerivedGenesisData {
        aggregate_verification_key,
        genesis_next_merkle_tree_commitment,
        genesis_next_protocol_parameters,
        genesis_message,
    }
}

/// Runs the deterministic generator sequence: signer keys and tree first, then the genesis key and
/// its signature over the message derived from that tree.
fn build_signer_fixture() -> CachedSignerFixture {
    let mut random_generator = ChaCha20Rng::seed_from_u64(ASSET_SEED);
    let (signing_keys, merkle_tree_leaves, merkle_tree) =
        build_merkle_tree(&mut random_generator, SIGNER_COUNT);

    let genesis_signing_key = SchnorrSigningKey::generate(&mut random_generator);
    let genesis_verification_key =
        SchnorrVerificationKey::new_from_signing_key(genesis_signing_key.clone());

    let genesis_message_base =
        BaseFieldElement::from(derive_genesis_data(&merkle_tree).genesis_message);
    let genesis_signature = genesis_signing_key
        .sign_standard(&[genesis_message_base], &mut random_generator)
        .expect("deterministic genesis signature should be produced");
    genesis_signature
        .verify(&[genesis_message_base], &genesis_verification_key)
        .expect("deterministic genesis signature should verify");

    CachedSignerFixture {
        signing_keys,
        merkle_tree_leaves,
        merkle_tree,
        genesis_verification_key,
        genesis_signature,
    }
}

/// Whether a decoded fixture is internally consistent.
///
/// The signature check is the strong one: it is made over the genesis message derived from the
/// cached tree, so a tampered tree, a tampered key or a tampered signature all fail it.
fn signer_fixture_is_valid(fixture: &CachedSignerFixture) -> bool {
    if fixture.signing_keys.len() != SIGNER_COUNT
        || fixture.merkle_tree_leaves.len() != SIGNER_COUNT
    {
        return false;
    }

    let genesis_message_base =
        BaseFieldElement::from(derive_genesis_data(&fixture.merkle_tree).genesis_message);
    fixture
        .genesis_signature
        .verify(&[genesis_message_base], &fixture.genesis_verification_key)
        .is_ok()
}

/// Assembles the full setup around a signer fixture, deriving everything that is a pure function of
/// it and the module constants.
fn assemble_asset_generation_setup(fixture: CachedSignerFixture) -> AssetGenerationSetup {
    let depth = SIGNER_COUNT.next_power_of_two().trailing_zeros();
    let number_of_lotteries = QUORUM_SIZE * 10;

    // Rebuilt on every call: it is derived from constants, not from the random generator.
    let certificate_relation = StmCertificateCircuit::try_new(
        &Parameters {
            k: QUORUM_SIZE as u64,
            m: number_of_lotteries as u64,
            phi_f: 0.2,
        },
        depth,
    )
    .expect("certificate relation construction should not fail");

    let derived = derive_genesis_data(&fixture.merkle_tree);

    AssetGenerationSetup {
        certificate_relation,
        genesis_verification_key: fixture.genesis_verification_key,
        genesis_message: MessageHash::from_field(derived.genesis_message),
        genesis_signature: fixture.genesis_signature,
        merkle_tree: fixture.merkle_tree,
        merkle_tree_leaves: fixture.merkle_tree_leaves,
        signing_keys: fixture.signing_keys,
        aggregate_verification_key: derived.aggregate_verification_key,
        genesis_next_merkle_tree_commitment: derived.genesis_next_merkle_tree_commitment,
        genesis_next_protocol_parameters: derived.genesis_next_protocol_parameters,
    }
}

/// Builds the deterministic asset-generation setup, always running the generator sequence.
///
/// Asset writers and the drift guard must use this: a stale cached fixture would let them produce
/// or check committed bytes from outdated signer data.
pub(crate) fn build_asset_generation_setup() -> AssetGenerationSetup {
    assemble_asset_generation_setup(build_signer_fixture())
}

/// Builds the deterministic asset-generation setup, taking the signer fixture from the content-keyed
/// test cache when a valid one is present.
///
/// **Never call this from an asset writer** — see [`build_asset_generation_setup`].
pub(crate) fn build_asset_generation_setup_from_cache() -> AssetGenerationSetup {
    let fixture_cache = signer_fixture_cache(
        SIGNER_COUNT,
        ASSET_SEED,
        TOTAL_STAKE,
        GENESIS_EPOCH,
        GENESIS_NEXT_PROTOCOL_PARAMETERS,
    );
    let cache_file = fixture_cache.directory().join(SIGNER_FIXTURE_CACHE_FILE);
    let fixture = {
        let _fixture_cache_lock =
            fixture_cache.lock().expect("the signer fixture cache should lock");
        load_or_build(&cache_file, signer_fixture_is_valid, build_signer_fixture)
    };

    assemble_asset_generation_setup(fixture)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use tempfile::TempDir;

    use super::*;

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

        let value = load_or_build(&cache_file, |_| true, || builder.build());

        assert_eq!(builder.calls.get(), 1, "a cold cache must build once");
        assert_eq!(value, CachedValue(vec![1, 2, 3, 4]));
        assert!(cache_file.exists(), "the entry must be published");
    }

    #[test]
    fn warm_cache_returns_the_stored_value_without_building() {
        let directory = TempDir::new().expect("temporary directory");
        let cache_file = cache_file_in(&directory);
        let builder = CountingBuilder::new();

        let first = load_or_build(&cache_file, |_| true, || builder.build());
        let second = load_or_build(&cache_file, |_| true, || builder.build());

        assert_eq!(builder.calls.get(), 1, "a warm cache must not rebuild");
        assert_eq!(first, second);
    }

    #[test]
    fn a_value_rejected_by_the_validator_is_treated_as_a_miss() {
        let directory = TempDir::new().expect("temporary directory");
        let cache_file = cache_file_in(&directory);
        let builder = CountingBuilder::new();
        load_or_build(&cache_file, |_| true, || builder.build());

        // The bytes are intact and decode cleanly; only the semantic check rejects them.
        let value = load_or_build(&cache_file, |_| false, || builder.build());

        assert_eq!(
            builder.calls.get(),
            2,
            "a value failing validation must be rebuilt"
        );
        assert_eq!(value, CachedValue(vec![1, 2, 3, 4]));
    }

    #[test]
    fn truncated_entry_is_treated_as_a_miss() {
        let directory = TempDir::new().expect("temporary directory");
        let cache_file = cache_file_in(&directory);
        let builder = CountingBuilder::new();
        load_or_build(&cache_file, |_| true, || builder.build());

        std::fs::write(&cache_file, [1, 2]).expect("the entry should be truncated");
        let value = load_or_build(&cache_file, |_| true, || builder.build());

        assert_eq!(builder.calls.get(), 2, "a truncated entry must be rebuilt");
        assert_eq!(value, CachedValue(vec![1, 2, 3, 4]));
    }

    #[test]
    fn trailing_bytes_are_rejected_rather_than_ignored() {
        let directory = TempDir::new().expect("temporary directory");
        let cache_file = cache_file_in(&directory);
        let builder = CountingBuilder::new();
        load_or_build(&cache_file, |_| true, || builder.build());

        // The decoder itself would accept these bytes and silently ignore the tail; the re-encode
        // comparison is what rejects them.
        std::fs::write(&cache_file, [1, 2, 3, 4, 99]).expect("the entry should gain a tail");
        let value = load_or_build(&cache_file, |_| true, || builder.build());

        assert_eq!(builder.calls.get(), 2, "trailing bytes must be rebuilt");
        assert_eq!(value, CachedValue(vec![1, 2, 3, 4]));
    }

    /// The real validator, not the generic hook: a freshly built fixture must be accepted.
    #[test]
    fn a_freshly_built_signer_fixture_is_valid() {
        assert!(signer_fixture_is_valid(&build_signer_fixture()));
    }

    #[test]
    fn a_signer_fixture_with_wrong_vector_lengths_is_rejected() {
        let mut fixture = build_signer_fixture();
        fixture.signing_keys.pop();
        assert!(!signer_fixture_is_valid(&fixture), "short signing keys");

        let mut fixture = build_signer_fixture();
        fixture.merkle_tree_leaves.pop();
        assert!(!signer_fixture_is_valid(&fixture), "short leaves");
    }

    #[test]
    fn a_signer_fixture_with_a_changed_tree_is_rejected() {
        let mut fixture = build_signer_fixture();
        // A different tree over the same signers changes the root, so the genesis message derived
        // from it no longer matches the one the cached signature was made over.
        let mut reordered_leaves = fixture.merkle_tree_leaves.clone();
        reordered_leaves.reverse();
        fixture.merkle_tree = SignerRegistrationMerkleTree::new(&reordered_leaves);

        assert!(!signer_fixture_is_valid(&fixture));
    }

    #[test]
    fn a_signer_fixture_with_a_changed_genesis_key_or_signature_is_rejected() {
        let mut random_generator = ChaCha20Rng::seed_from_u64(ASSET_SEED + 1);
        let other_signing_key = SchnorrSigningKey::generate(&mut random_generator);

        let mut fixture = build_signer_fixture();
        fixture.genesis_verification_key =
            SchnorrVerificationKey::new_from_signing_key(other_signing_key.clone());
        assert!(!signer_fixture_is_valid(&fixture), "changed genesis key");

        let mut fixture = build_signer_fixture();
        let unrelated_message = BaseFieldElement::from(NativeField::from(1u64));
        fixture.genesis_signature = other_signing_key
            .sign_standard(&[unrelated_message], &mut random_generator)
            .expect("a signature over an unrelated message should be produced");
        assert!(!signer_fixture_is_valid(&fixture), "changed signature");
    }

    /// Exercises the production cache address, so dropping an input from
    /// [`recursive_verifying_key_cache`] makes this fail rather than silently sharing an entry.
    #[test]
    fn every_recursive_verifying_key_cache_input_changes_the_address() {
        let directory = |certificate_key: &[u8],
                         production_key: &[u8],
                         recursive_degree: u32,
                         certificate_degree: u32,
                         seed: u64| {
            recursive_verifying_key_cache(
                certificate_key,
                production_key,
                recursive_degree,
                certificate_degree,
                seed,
            )
            .directory()
            .to_path_buf()
        };
        let baseline = directory(b"certificate-key", b"production-key", 19, 13, 42);

        for (label, varied) in [
            (
                "certificate verifying key",
                directory(b"another-certificate-key", b"production-key", 19, 13, 42),
            ),
            (
                "production recursive key",
                directory(b"certificate-key", b"another-production-key", 19, 13, 42),
            ),
            (
                "recursive circuit degree",
                directory(b"certificate-key", b"production-key", 20, 13, 42),
            ),
            (
                "certificate circuit degree",
                directory(b"certificate-key", b"production-key", 19, 14, 42),
            ),
            (
                "unsafe srs seed",
                directory(b"certificate-key", b"production-key", 19, 13, 43),
            ),
        ] {
            assert_ne!(
                baseline, varied,
                "a change of {label} must resolve to a different cache entry"
            );
        }
    }

    /// Same guard for the signer fixture address.
    #[test]
    fn every_signer_fixture_cache_input_changes_the_address() {
        let directory = |signer_count: usize,
                         seed: u64,
                         total_stake: u64,
                         genesis_epoch: u64,
                         next_protocol_parameters: u64| {
            signer_fixture_cache(
                signer_count,
                seed,
                total_stake,
                genesis_epoch,
                next_protocol_parameters,
            )
            .directory()
            .to_path_buf()
        };
        let baseline = directory(3000, 42, 1_000_000, 5, 7);

        for (label, varied) in [
            ("signer count", directory(3001, 42, 1_000_000, 5, 7)),
            ("asset seed", directory(3000, 43, 1_000_000, 5, 7)),
            ("total stake", directory(3000, 42, 1_000_001, 5, 7)),
            ("genesis epoch", directory(3000, 42, 1_000_000, 6, 7)),
            (
                "next protocol parameters",
                directory(3000, 42, 1_000_000, 5, 8),
            ),
        ] {
            assert_ne!(
                baseline, varied,
                "a change of {label} must resolve to a different cache entry"
            );
        }
    }
}
