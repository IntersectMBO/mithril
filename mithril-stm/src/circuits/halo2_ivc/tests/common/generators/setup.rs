use std::{collections::BTreeMap, path::PathBuf};

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
    PairingEngine, circuit::IvcCircuitData, state::Global,
};
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

/// Derives circuit-specific commitment parameters from a shared universal SRS.
pub(super) fn derive_commitment_params(
    universal_kzg_parameters: &ParamsKZG<Bls12>,
    shared_srs_degree: u32,
    circuit_degree: u32,
) -> ParamsKZG<Bls12> {
    let mut commitment_parameters = universal_kzg_parameters.clone();
    if circuit_degree < shared_srs_degree {
        commitment_parameters.downsize(circuit_degree);
    }
    commitment_parameters
}

/// Builds the shared verifier-side recursive setup from the deterministic SRS.
pub(crate) fn build_shared_recursive_context(
    setup: &AssetGenerationSetup,
) -> SharedRecursiveContext {
    let shared_srs_degree = RECURSIVE_CIRCUIT_DEGREE.max(CERTIFICATE_CIRCUIT_DEGREE);
    let universal_kzg_parameters = build_deterministic_params(shared_srs_degree);
    let universal_verifier_params = universal_kzg_parameters.verifier_params();

    let certificate_commitment_parameters = derive_commitment_params(
        &universal_kzg_parameters,
        shared_srs_degree,
        CERTIFICATE_CIRCUIT_DEGREE,
    );
    let recursive_commitment_parameters = derive_commitment_params(
        &universal_kzg_parameters,
        shared_srs_degree,
        RECURSIVE_CIRCUIT_DEGREE,
    );

    let certificate_verifying_key = NonRecursiveCircuitVerifyingKey::new(zk_lib::setup_vk(
        &certificate_commitment_parameters,
        &setup.certificate_relation,
    ));
    let default_ivc_circuit =
        IvcCircuitData::unknown(&certificate_verifying_key).expect("valid IvcCircuitData unknown");
    let recursive_verifying_key = RecursiveCircuitVerifyingKey::new(
        keygen_vk_with_k(
            &recursive_commitment_parameters,
            &default_ivc_circuit,
            RECURSIVE_CIRCUIT_DEGREE,
        )
        .expect("recursive verifying key generation should not fail"),
    );

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
