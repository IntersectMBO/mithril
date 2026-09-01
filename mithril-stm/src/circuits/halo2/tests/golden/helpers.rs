use std::fs::create_dir_all;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, anyhow};
use midnight_circuits::hash::poseidon::PoseidonState;
use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::utils::SerdeFormat;
use midnight_zk_stdlib as zk;
use midnight_zk_stdlib::MidnightCircuit;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::circuits::halo2::NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
use crate::circuits::halo2::circuit::CertificateCircuit;
use crate::circuits::halo2::errors::CertificateCircuitError;
use crate::circuits::halo2::keys::{
    NonRecursiveCircuitProvingKey, NonRecursiveCircuitVerifyingKey,
};
use crate::circuits::halo2::types::CircuitBase;
use crate::circuits::halo2::witness::{
    CircuitMerkleTreeLeaf, CircuitWitnessEntry, LotteryTargetValue as CircuitLotteryTargetValue,
    MerklePath, MerkleTreeCommitment, SignedMessageWithoutPrefix,
};
use crate::circuits::key_provider::KeyProvider;
use crate::circuits::test_utils::file_mutex::FileMutex;
use crate::circuits::test_utils::setup::{generate_params, load_params};
use crate::circuits::trusted_setup::UNSAFE_SRS_SEED;
use crate::hash::poseidon::MidnightPoseidonDigest;
use crate::membership_commitment::{
    MerkleTree as StmMerkleTree, MerkleTreeSnarkLeaf as StmMerkleTreeSnarkLeaf,
};
use crate::signature_scheme::{
    BaseFieldElement, SchnorrSigningKey, SchnorrVerificationKey, UniqueSchnorrSignature,
};
use crate::{LotteryIndex, LotteryTargetValue, Parameters, StmResult};

/// Default number of signers used in golden test environments.
const DEFAULT_NUM_SIGNERS: usize = 3000;
/// Lottery count multiplier per k size used in golden test environments.
pub(crate) const LOTTERIES_PER_K: u32 = 10;
/// Default message value used by golden test cases.
const DEFAULT_TEST_MSG: u64 = 42;

/// Verification/proving key pair derived for an STM circuit configuration.
type CircuitVerificationAndProvingKeyPair = (
    NonRecursiveCircuitVerifyingKey,
    NonRecursiveCircuitProvingKey,
);

fn checked_len_u32(actual: usize) -> u32 {
    u32::try_from(actual).unwrap_or(u32::MAX)
}

/// Assert that proving succeeded but the verifier rejected the generated proof.
pub(crate) fn assert_proof_rejected_by_verifier(result: StmResult<()>) {
    match result {
        Err(error) => {
            let has_verification_rejected = error.chain().any(|err| {
                matches!(
                    err.downcast_ref::<CertificateCircuitError>(),
                    Some(CertificateCircuitError::VerificationRejected)
                )
            });
            assert!(
                has_verification_rejected,
                "expected verification failure, got: {error}"
            );
        }
        other => panic!("expected verification failure, got: {other:?}"),
    }
}

/// Extract the circuit-level proving failure from a prove+verify result.
///
/// Panics when the result is not a circuit proving failure.
pub(crate) fn assert_proving_circuit_error<T>(result: StmResult<T>) -> CertificateCircuitError {
    match result {
        Err(error) => error
            .chain()
            .find_map(|err| err.downcast_ref::<CertificateCircuitError>())
            .cloned()
            .unwrap_or_else(|| {
                panic!("expected CertificateCircuitError in source chain, got: {error}")
            }),
        _ => panic!("expected circuit proving failure"),
    }
}

fn validate_relation_for_setup(relation: &CertificateCircuit) -> StmResult<()> {
    relation
        .validate_parameters()
        .with_context(|| "Circuit parameter validation failed before setup")
}

/// Shared environment for STM circuit golden cases (SRS, relation, keys, sizing).
pub(crate) struct StmCircuitEnv {
    /// Structured reference string used by the Halo2/KZG proving system.
    ///
    /// Generated or loaded once per test case.
    srs: ParamsKZG<Bls12>,

    /// The STM circuit relation defining all constraints enforced in-circuit.
    relation: CertificateCircuit,

    /// Verification key corresponding to `relation` and `srs`.
    vk: NonRecursiveCircuitVerifyingKey,

    /// Proving key corresponding to `relation` and `vk`.
    pk: NonRecursiveCircuitProvingKey,

    /// Number of signers used to size the Merkle tree in golden tests.
    num_signers: usize,

    /// Number of lotteries (`m`) configured for the STM circuit relation.
    m: u32,
}

/// Concrete STM circuit scenario inputs for proving/verifying in golden tests.
pub(crate) struct StmCircuitScenario {
    /// Public Merkle tree commitment carried by the statement.
    merkle_tree_commitment: MerkleTreeCommitment,
    /// Public message bound into the proof transcript.
    message: SignedMessageWithoutPrefix,
    /// Private witness entries supplied to the STM circuit relation.
    witness: Vec<CircuitWitnessEntry>,
}

/// Signer fixture material used to build STM Merkle trees and Halo2 witness leaves.
#[derive(Clone)]
pub(crate) struct SignerFixture {
    /// Signing key used to generate test signatures.
    sk: SchnorrSigningKey,
    /// Verification key committed into both STM and circuit leaves.
    vk: SchnorrVerificationKey,
    /// Lottery target value carried in the Halo2 witness leaf.
    circuit_lottery_target_value: CircuitLotteryTargetValue,
    /// Lottery target value represented in the STM-side leaf format.
    stm_lottery_target_value: LotteryTargetValue,
}

impl From<&SignerFixture> for StmMerkleTreeSnarkLeaf {
    fn from(value: &SignerFixture) -> Self {
        StmMerkleTreeSnarkLeaf(value.vk, value.stm_lottery_target_value)
    }
}

impl From<&SignerFixture> for CircuitMerkleTreeLeaf {
    fn from(value: &SignerFixture) -> Self {
        CircuitMerkleTreeLeaf(value.vk, value.circuit_lottery_target_value)
    }
}

fn stm_lottery_target_value_from_circuit(
    lottery_target_value: CircuitLotteryTargetValue,
) -> LotteryTargetValue {
    lottery_target_value.into()
}

fn generate_signer_fixture(
    rng: &mut ChaCha20Rng,
    lottery_target_value: CircuitLotteryTargetValue,
) -> StmResult<SignerFixture> {
    let stm_sk = SchnorrSigningKey::generate(rng);
    let stm_vk = SchnorrVerificationKey::new_from_signing_key(stm_sk.clone());
    let stm_lottery_target_value = stm_lottery_target_value_from_circuit(lottery_target_value);
    Ok(SignerFixture {
        sk: stm_sk,
        vk: stm_vk,
        circuit_lottery_target_value: lottery_target_value,
        stm_lottery_target_value,
    })
}

/// STM Merkle tree wrapper that exposes circuit-friendly commitment and path accessors.
///
/// The wrapper stores STM Merkle leaves internally, then converts signer fixtures and
/// Merkle paths into circuit witness types (`CircuitMerkleTreeLeaf`, `MerklePath`) as needed.
pub(crate) struct StmMerkleTreeWrapper {
    /// Underlying STM Merkle tree used as the source of truth for paths and commitments.
    stm_tree: StmMerkleTree<MidnightPoseidonDigest, StmMerkleTreeSnarkLeaf>,
    /// Circuit-friendly commitment converted into a Halo2 public input wrapper.
    merkle_tree_commitment: MerkleTreeCommitment,
    /// Signer fixtures stored in leaf order for path and witness construction.
    signer_fixtures: Vec<SignerFixture>,
}

/// Selects which leaf index is assigned the controlled lottery target value.
pub(crate) enum LeafSelector {
    /// Use the leftmost leaf (index 0).
    LeftMost,
    /// Use the rightmost leaf (index n - 1).
    RightMost,
    /// Use a specific leaf index.
    Index(usize),
}

impl StmMerkleTreeWrapper {
    /// Return the Merkle tree commitment used by Halo2 as a circuit wrapper field value.
    pub(crate) fn merkle_tree_commitment(&self) -> MerkleTreeCommitment {
        self.merkle_tree_commitment
    }

    /// Return a circuit witness Merkle path for the given leaf index.
    pub(crate) fn get_path(&self, i: usize) -> StmResult<MerklePath> {
        let stm_path = self.stm_tree.compute_merkle_tree_path(i);
        let stm_leaf: StmMerkleTreeSnarkLeaf = self.signer_fixture(i)?.into();
        self.stm_tree
            .to_merkle_tree_commitment()
            .verify_leaf_membership_from_path(&stm_leaf, &stm_path)
            .map_err(|_| anyhow!(CertificateCircuitError::MerklePathVerificationFailed))?;
        (&stm_path).try_into().map_err(Into::into)
    }

    /// Return signer fixture material at index `i`.
    fn signer_fixture(&self, i: usize) -> StmResult<&SignerFixture> {
        self.signer_fixtures.get(i).ok_or_else(|| {
            anyhow!(CertificateCircuitError::InvalidSignerFixtureIndex {
                index: checked_len_u32(i),
                num_signers: checked_len_u32(self.signer_fixtures.len()),
            })
        })
    }
}

fn decode_merkle_tree_commitment(root_bytes: &[u8]) -> StmResult<MerkleTreeCommitment> {
    let actual = root_bytes.len();
    let root_array: [u8; 32] = root_bytes.try_into().map_err(|_| {
        anyhow!(
            CertificateCircuitError::InvalidMerkleTreeCommitmentDigestLength {
                actual: checked_len_u32(actual),
            }
        )
    })?;
    BaseFieldElement::from_bytes(&root_array)
        .ok()
        .map(Into::into)
        .ok_or_else(|| anyhow!(CertificateCircuitError::NonCanonicalMerkleTreeCommitmentDigest))
}

fn build_merkle_tree_wrapper(
    n: usize,
    selected_index: Option<usize>,
    lottery_target_value: CircuitLotteryTargetValue,
) -> StmResult<StmMerkleTreeWrapper> {
    if let Some(i) = selected_index
        && i >= n
    {
        return Err(anyhow!(CertificateCircuitError::InvalidSelectedLeafIndex {
            index: checked_len_u32(i),
            num_leaves: checked_len_u32(n),
        }));
    }

    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut signer_fixtures = Vec::with_capacity(n);
    for i in 0..n {
        let leaf_lottery_target_value = if selected_index == Some(i) {
            lottery_target_value
        } else {
            -CircuitLotteryTargetValue::ONE
        };
        signer_fixtures.push(generate_signer_fixture(
            &mut rng,
            leaf_lottery_target_value,
        )?);
    }

    let stm_leaves: Vec<StmMerkleTreeSnarkLeaf> = signer_fixtures.iter().map(Into::into).collect();
    let stm_tree =
        StmMerkleTree::<MidnightPoseidonDigest, StmMerkleTreeSnarkLeaf>::new(&stm_leaves);
    let root_bytes = stm_tree.to_merkle_tree_commitment().root;
    let merkle_tree_commitment = decode_merkle_tree_commitment(root_bytes.as_slice())?;
    Ok(StmMerkleTreeWrapper {
        stm_tree,
        merkle_tree_commitment,
        signer_fixtures,
    })
}

/// Build a default Merkle tree with all leaves set to the max lottery target value.
pub(crate) fn create_default_merkle_tree(n: usize) -> StmResult<StmMerkleTreeWrapper> {
    build_merkle_tree_wrapper(n, None, -CircuitLotteryTargetValue::ONE)
}

/// Build a full tree with one controlled leaf selected by `selector` and return its index.
pub(crate) fn create_merkle_tree_with_leaf_selector(
    depth: u32,
    selector: LeafSelector,
    lottery_target_value: CircuitLotteryTargetValue,
) -> StmResult<(StmMerkleTreeWrapper, usize)> {
    if depth >= usize::BITS {
        return Err(anyhow!(CertificateCircuitError::InvalidMerkleTreeDepth {
            depth
        }));
    }
    let n = 1usize << depth;
    let selected_index = match selector {
        LeafSelector::LeftMost => 0usize,
        LeafSelector::RightMost => n - 1,
        LeafSelector::Index(i) => {
            if i >= n {
                return Err(anyhow!(CertificateCircuitError::InvalidSelectedLeafIndex {
                    index: checked_len_u32(i),
                    num_leaves: checked_len_u32(n),
                }));
            }
            i
        }
    };

    let tree = build_merkle_tree_wrapper(n, Some(selected_index), lottery_target_value)?;
    Ok((tree, selected_index))
}
fn transcript_message(
    merkle_tree_commitment: MerkleTreeCommitment,
    message: SignedMessageWithoutPrefix,
) -> [BaseFieldElement; 2] {
    [merkle_tree_commitment.into(), message.into()]
}

fn assert_challenge_endianness(sig: &UniqueSchnorrSignature) -> StmResult<()> {
    let challenge_bytes = sig.challenge.to_bytes();
    let challenge_base = CircuitBase::from_bytes_le(&challenge_bytes)
        .into_option()
        .ok_or_else(|| anyhow!(CertificateCircuitError::InvalidChallengeBytes))?;
    if SignedMessageWithoutPrefix::from(challenge_base)
        != SignedMessageWithoutPrefix::from(sig.challenge)
    {
        return Err(anyhow!(
            CertificateCircuitError::ChallengeEndiannessMismatch
        ));
    }
    Ok(())
}

fn sign_and_verify_lottery_message(
    signer_fixture: &SignerFixture,
    merkle_tree_commitment: MerkleTreeCommitment,
    message: SignedMessageWithoutPrefix,
    rng: &mut ChaCha20Rng,
) -> StmResult<UniqueSchnorrSignature> {
    let transcript = transcript_message(merkle_tree_commitment, message);
    let stm_sig = signer_fixture
        .sk
        .sign_unique(&transcript, rng)
        .map_err(|_| anyhow!(CertificateCircuitError::SignatureGenerationFailed))?;
    assert_challenge_endianness(&stm_sig)?;
    stm_sig
        .verify(&transcript, &signer_fixture.vk)
        .map_err(|_| anyhow!(CertificateCircuitError::SignatureVerificationFailed))?;
    Ok(stm_sig)
}

/// Build a witness with default strictly increasing indices [0..k).
pub(crate) fn build_witness(
    merkle_tree: &StmMerkleTreeWrapper,
    merkle_tree_commitment: MerkleTreeCommitment,
    message: SignedMessageWithoutPrefix,
    k: u32,
) -> StmResult<Vec<CircuitWitnessEntry>> {
    let indices: Vec<LotteryIndex> = (0..k).map(u64::from).collect();
    build_witness_with_indices(merkle_tree, merkle_tree_commitment, message, &indices)
}

/// Build a witness using caller-provided indices without enforcing ordering;
/// the circuit is responsible for strict ordering checks in negative tests.
pub(crate) fn build_witness_with_indices(
    merkle_tree: &StmMerkleTreeWrapper,
    merkle_tree_commitment: MerkleTreeCommitment,
    message: SignedMessageWithoutPrefix,
    indices: &[LotteryIndex],
) -> StmResult<Vec<CircuitWitnessEntry>> {
    build_witness_internal(
        merkle_tree,
        merkle_tree_commitment,
        message,
        WitnessBuildMode::Indices(indices),
    )
}

/// Reuse the same signer, Merkle path, and signature across indices to stress
/// Merkle-path shape in golden vectors; not a realistic lottery model, and any
/// grinding or signature randomness considerations are out of scope.
pub(crate) fn build_witness_with_fixed_signer(
    merkle_tree: &StmMerkleTreeWrapper,
    signer_index: usize,
    merkle_tree_commitment: MerkleTreeCommitment,
    message: SignedMessageWithoutPrefix,
    indices: &[LotteryIndex],
) -> StmResult<Vec<CircuitWitnessEntry>> {
    build_witness_internal(
        merkle_tree,
        merkle_tree_commitment,
        message,
        WitnessBuildMode::FixedSigner {
            signer_index,
            indices,
        },
    )
}

enum WitnessBuildMode<'a> {
    Indices(&'a [LotteryIndex]),
    FixedSigner {
        signer_index: usize,
        indices: &'a [LotteryIndex],
    },
}

fn build_witness_internal(
    merkle_tree: &StmMerkleTreeWrapper,
    merkle_tree_commitment: MerkleTreeCommitment,
    message: SignedMessageWithoutPrefix,
    mode: WitnessBuildMode<'_>,
) -> StmResult<Vec<CircuitWitnessEntry>> {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut witness = Vec::new();

    match mode {
        WitnessBuildMode::Indices(indices) => {
            if indices.is_empty() {
                return Err(anyhow!(CertificateCircuitError::EmptyIndices));
            }
            let num_signers = merkle_tree.signer_fixtures.len();
            if num_signers == 0 {
                return Err(anyhow!(CertificateCircuitError::EmptySignerLeaves));
            }

            for (i, index) in indices.iter().enumerate() {
                let signer_index = i % num_signers;
                let signer_fixture = merkle_tree.signer_fixture(signer_index)?;
                let stm_sig = sign_and_verify_lottery_message(
                    signer_fixture,
                    merkle_tree_commitment,
                    message,
                    &mut rng,
                )?;
                let merkle_path = merkle_tree.get_path(signer_index)?;
                witness.push(CircuitWitnessEntry {
                    leaf: signer_fixture.into(),
                    merkle_path,
                    unique_schnorr_signature: stm_sig,
                    lottery_index: *index,
                });
            }
        }
        WitnessBuildMode::FixedSigner {
            signer_index,
            indices,
        } => {
            if indices.is_empty() {
                return Err(anyhow!(CertificateCircuitError::EmptyIndices));
            }
            let signer_fixture = merkle_tree.signer_fixture(signer_index)?;
            let merkle_path = merkle_tree.get_path(signer_index)?;
            let stm_sig = sign_and_verify_lottery_message(
                signer_fixture,
                merkle_tree_commitment,
                message,
                &mut rng,
            )?;
            for index in indices {
                witness.push(CircuitWitnessEntry {
                    leaf: signer_fixture.into(),
                    merkle_path: merkle_path.clone(),
                    unique_schnorr_signature: stm_sig,
                    lottery_index: *index,
                });
            }
        }
    }

    Ok(witness)
}

/// Return the first two witness entries if their leaves are distinct.
///
/// This helper assumes callers construct witnesses so entries `0` and `1` come
/// from different signer fixtures (negative-test precondition). If not, it
/// returns an error instead of searching later entries.
pub(crate) fn find_two_distinct_witness_entries(
    witness: &[CircuitWitnessEntry],
) -> StmResult<(usize, usize)> {
    if witness.len() < 2 {
        return Err(anyhow!(CertificateCircuitError::WitnessTooShort {
            actual: checked_len_u32(witness.len()),
        }));
    }
    let leaf0 = witness[0].leaf;
    let leaf1 = witness[1].leaf;
    if leaf0 != leaf1 {
        return Ok((0, 1));
    }
    Err(anyhow!(CertificateCircuitError::NoDistinctWitnessEntries))
}

impl StmCircuitEnv {
    /// Number of signers used to size the default Merkle tree in golden cases.
    pub(crate) fn num_signers(&self) -> usize {
        self.num_signers
    }

    /// Number of lotteries configured for the STM circuit relation.
    pub(crate) fn m(&self) -> u32 {
        self.m
    }
}

impl StmCircuitScenario {
    /// Construct a new STM circuit scenario from its instance and witness data.
    pub(crate) fn new(
        merkle_tree_commitment: MerkleTreeCommitment,
        message: SignedMessageWithoutPrefix,
        witness: Vec<CircuitWitnessEntry>,
    ) -> Self {
        Self {
            merkle_tree_commitment,
            message,
            witness,
        }
    }
}

/// Construct the STM circuit relation environment and setup keys for a case.
pub(crate) fn setup_stm_circuit_env(
    case_name: &str,
    circuit_degree: u32,
    k: u32,
    m: u32,
) -> StmResult<StmCircuitEnv> {
    let srs = load_or_generate_params(circuit_degree)?;

    let num_signers: usize = DEFAULT_NUM_SIGNERS;
    let depth = num_signers.next_power_of_two().trailing_zeros();
    let stm_params = Parameters {
        k: k as u64,
        m: m as u64,
        phi_f: 0.2,
    };
    let relation = CertificateCircuit::try_new(&stm_params, depth).unwrap();
    validate_relation_for_setup(&relation)?;

    {
        let stm_circuit = MidnightCircuit::from_relation(&relation, None);
        println!("\n=== STM circuit case: {case_name} ===");
        println!("circuit degree (selected) {circuit_degree}");
        println!("k (mithril parameter) {k}");
        println!("k (log2 of circuit size) {:?}", stm_circuit.k());
        println!("{:?}", zk::cost_model(&relation, None));
    }

    let (vk, pk) = get_or_build_circuit_keys(&stm_params, depth, circuit_degree, &relation, &srs)?;

    Ok(StmCircuitEnv {
        srs,
        relation,
        vk,
        pk,
        num_signers,
        m,
    })
}

/// Prove and verify a scenario, returning `StmResult` for negative tests.
pub(crate) fn prove_and_verify_result(
    env: &StmCircuitEnv,
    scenario: StmCircuitScenario,
) -> StmResult<()> {
    let instance = (scenario.merkle_tree_commitment, scenario.message);

    let start = Instant::now();
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let proof = zk::prove::<CertificateCircuit, PoseidonState<CircuitBase>>(
        &env.srs,
        env.pk.midnight_pk(),
        &env.relation,
        &instance,
        scenario.witness,
        &mut rng,
    )
    .with_context(|| "Proving step failed")?;
    let duration = start.elapsed();
    println!("\nProof generation took: {:?}", duration);
    println!("Proof size: {:?}", proof.len());

    let start = Instant::now();
    let verify_result = zk::verify::<CertificateCircuit, PoseidonState<CircuitBase>>(
        &env.srs.verifier_params(),
        env.vk.midnight_vk(),
        &instance,
        None,
        &proof,
    );
    let duration = start.elapsed();
    println!("Proof verification took: {:?}", duration);

    if verify_result.is_ok() {
        Ok(())
    } else {
        Err(anyhow!(CertificateCircuitError::VerificationRejected))
            .with_context(|| format!("Proof verification step failed: {verify_result:?}"))
    }
}

/// Run a case using the default message (SignedMessageWithoutPrefix::from(DEFAULT_TEST_MSG)).
pub(crate) fn run_stm_circuit_case_default(
    case_name: &str,
    circuit_degree: u32,
    k: u32,
) -> StmResult<()> {
    run_stm_circuit_case(
        case_name,
        circuit_degree,
        k,
        SignedMessageWithoutPrefix::from(DEFAULT_TEST_MSG),
    )
}

/// Run a case with a caller-specified message.
pub(crate) fn run_stm_circuit_case(
    case_name: &str,
    circuit_degree: u32,
    k: u32,
    message: SignedMessageWithoutPrefix,
) -> StmResult<()> {
    let m = k * LOTTERIES_PER_K;
    let env = setup_stm_circuit_env(case_name, circuit_degree, k, m)?;
    let merkle_tree = create_default_merkle_tree(env.num_signers())?;

    let merkle_tree_commitment = merkle_tree.merkle_tree_commitment();

    let witness = build_witness(&merkle_tree, merkle_tree_commitment, message, k)?;
    let scenario = StmCircuitScenario::new(merkle_tree_commitment, message, witness);

    prove_and_verify_result(&env, scenario)
}

// Load cached KZG params if present; otherwise generate and persist them for reuse.
fn load_or_generate_params(circuit_degree: u32) -> StmResult<ParamsKZG<Bls12>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let assets_dir = manifest_dir.join("src").join("circuits").join("halo2").join("assets");
    // The seed belongs in the name: a file identified only by degree would be reused after a seed
    // change, pairing an old-seed SRS with keys cached under the new seed.
    let path = assets_dir.join(format!(
        "params_kzg_unsafe_degree_{circuit_degree}_seed_{UNSAFE_SRS_SEED}"
    ));

    if path.exists() {
        return Ok(load_params(
            path.to_string_lossy().as_ref(),
            SerdeFormat::RawBytesUnchecked,
        ));
    }

    create_dir_all(&assets_dir)
        .map_err(|_| anyhow!(CertificateCircuitError::ParamsAssetsDirCreate))
        .with_context(|| {
            format!(
                "Failed to create params assets directory at '{}'",
                assets_dir.to_string_lossy()
            )
        })?;
    Ok(generate_params(
        circuit_degree,
        path.to_string_lossy().as_ref(),
        SerdeFormat::RawBytesUnchecked,
    ))
}

/// Content-keyed cache entry holding the certificate keys derived from these inputs.
///
/// Distinct configurations never share a directory, which is what lets [`KeyProvider`] be built
/// with no expected verifying key.
fn certificate_golden_key_cache(
    production_verifying_key: &[u8],
    parameters: &Parameters,
    merkle_tree_depth: u32,
    circuit_degree: u32,
    unsafe_srs_seed: u64,
) -> StmResult<FileMutex> {
    Ok(FileMutex::for_shared_cache(
        "certificate-golden-keys",
        &[
            production_verifying_key,
            &parameters.to_bytes()?,
            &merkle_tree_depth.to_le_bytes(),
            &circuit_degree.to_le_bytes(),
            &unsafe_srs_seed.to_le_bytes(),
        ],
    ))
}

/// Loads the verification/proving key pair for this configuration from the on-disk cache, deriving
/// and storing it on a miss.
///
/// The lock is taken before the lookup so parallel processes racing a cold miss derive the pair
/// once rather than once each.
fn get_or_build_circuit_keys(
    parameters: &Parameters,
    merkle_tree_depth: u32,
    circuit_degree: u32,
    relation: &CertificateCircuit,
    srs: &ParamsKZG<Bls12>,
) -> StmResult<CircuitVerificationAndProvingKeyPair> {
    let key_cache = certificate_golden_key_cache(
        NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        parameters,
        merkle_tree_depth,
        circuit_degree,
        UNSAFE_SRS_SEED,
    )?;
    let key_provider = KeyProvider::new(
        key_cache.directory().to_path_buf(),
        "non-recursive",
        &[],
        relation.clone(),
    );
    let _key_cache_lock = key_cache.lock()?;

    let start = Instant::now();
    // Midnight's setup panics rather than returning an error on some malformed relations; keep
    // converting that into a test failure with the payload attached.
    let key_pair = panic::catch_unwind(AssertUnwindSafe(|| key_provider.key_pair(srs))).map_err(
        |panic_payload| {
            let details = panic_payload
                .downcast_ref::<&str>()
                .map(|message| (*message).to_owned())
                .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_string());
            anyhow!("Midnight setup panicked before proving: {details}")
        },
    )??;
    println!("\nvk pk load or generation took: {:?}", start.elapsed());

    Ok(key_pair)
}

/// Function used to compute the verification key for tests
/// It uses an unsafe setup function to create the SRS
pub(crate) fn compute_unsafe_circuit_verification_key(
    params: &Parameters,
    merkle_tree_depth: u32,
) -> Vec<u8> {
    const RNG_SEED: u64 = 42;
    let circuit = CertificateCircuit::try_new(params, merkle_tree_depth).unwrap();
    let circuit_degree = MidnightCircuit::from_relation(&circuit, None).k();
    let srs: ParamsKZG<Bls12> =
        ParamsKZG::unsafe_setup(circuit_degree, ChaCha20Rng::seed_from_u64(RNG_SEED));

    let circuit_verification_key = midnight_zk_stdlib::setup_vk(&srs, &circuit);
    let mut buf_cvk = vec![];
    circuit_verification_key
        .write(&mut buf_cvk, SerdeFormat::RawBytes)
        .unwrap();
    buf_cvk
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASELINE_PRODUCTION_KEY: &[u8] = b"production-verifying-key";
    const BASELINE_DEPTH: u32 = 12;
    const BASELINE_DEGREE: u32 = 13;
    const BASELINE_SEED: u64 = 42;

    fn parameters(k: u64, m: u64, phi_f: f64) -> Parameters {
        Parameters { k, m, phi_f }
    }

    fn baseline_parameters() -> Parameters {
        parameters(3, 30, 0.2)
    }

    fn cache_directory(
        production_verifying_key: &[u8],
        parameters: &Parameters,
        merkle_tree_depth: u32,
        circuit_degree: u32,
        unsafe_srs_seed: u64,
    ) -> PathBuf {
        certificate_golden_key_cache(
            production_verifying_key,
            parameters,
            merkle_tree_depth,
            circuit_degree,
            unsafe_srs_seed,
        )
        .expect("the cache entry should resolve")
        .directory()
        .to_path_buf()
    }

    fn baseline_cache_directory() -> PathBuf {
        cache_directory(
            BASELINE_PRODUCTION_KEY,
            &baseline_parameters(),
            BASELINE_DEPTH,
            BASELINE_DEGREE,
            BASELINE_SEED,
        )
    }

    /// Exercises the production cache address with every input varied in turn, so dropping any input
    /// from [`certificate_golden_key_cache`] makes this fail rather than silently sharing an entry.
    #[test]
    fn every_input_changes_the_cache_address() {
        let baseline = baseline_cache_directory();

        let variations = [
            (
                "production verifying key",
                cache_directory(
                    b"a-different-production-verifying-key",
                    &baseline_parameters(),
                    BASELINE_DEPTH,
                    BASELINE_DEGREE,
                    BASELINE_SEED,
                ),
            ),
            (
                "quorum size",
                cache_directory(
                    BASELINE_PRODUCTION_KEY,
                    &parameters(4, 30, 0.2),
                    BASELINE_DEPTH,
                    BASELINE_DEGREE,
                    BASELINE_SEED,
                ),
            ),
            (
                "lottery count",
                cache_directory(
                    BASELINE_PRODUCTION_KEY,
                    &parameters(3, 40, 0.2),
                    BASELINE_DEPTH,
                    BASELINE_DEGREE,
                    BASELINE_SEED,
                ),
            ),
            (
                "phi_f",
                cache_directory(
                    BASELINE_PRODUCTION_KEY,
                    &parameters(3, 30, 0.3),
                    BASELINE_DEPTH,
                    BASELINE_DEGREE,
                    BASELINE_SEED,
                ),
            ),
            (
                "merkle tree depth",
                cache_directory(
                    BASELINE_PRODUCTION_KEY,
                    &baseline_parameters(),
                    BASELINE_DEPTH + 1,
                    BASELINE_DEGREE,
                    BASELINE_SEED,
                ),
            ),
            (
                "circuit degree",
                cache_directory(
                    BASELINE_PRODUCTION_KEY,
                    &baseline_parameters(),
                    BASELINE_DEPTH,
                    BASELINE_DEGREE + 1,
                    BASELINE_SEED,
                ),
            ),
            (
                "unsafe srs seed",
                cache_directory(
                    BASELINE_PRODUCTION_KEY,
                    &baseline_parameters(),
                    BASELINE_DEPTH,
                    BASELINE_DEGREE,
                    BASELINE_SEED + 1,
                ),
            ),
        ];

        for (label, directory) in variations {
            assert_ne!(
                baseline, directory,
                "a change of {label} must resolve to a different cache entry"
            );
        }
    }

    #[test]
    fn the_same_configuration_resolves_to_the_same_cache_address() {
        assert_eq!(baseline_cache_directory(), baseline_cache_directory());
    }
}
