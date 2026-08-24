use std::collections::BTreeMap;

use midnight_circuits::types::Instantiable;
use midnight_curves::Bls12;
use midnight_proofs::{
    dev::MockProver,
    poly::kzg::params::{ParamsKZG, ParamsVerifierKZG},
};

use crate::circuits::halo2_ivc::{
    Accumulator, AssignedAccumulator, EmulatedCurve, NativeField, PREIMAGE_SIZE, PairingEngine,
    RecursiveEmulation,
    accumulator::trivial_accumulator,
    circuit::IvcCircuitData,
    state::{Global, State, Witness},
    types::{CertificateProofBytes, IvcProofBytes, MerkleTreeCommitment, ProtocolMessagePreimage},
};
use crate::circuits::halo2_ivc::{IVC_FIXED_BASES_PREFIX, keys::RecursiveCircuitVerifyingKey};
use crate::circuits::{
    halo2::keys::NonRecursiveCircuitVerifyingKey, halo2_ivc::CERTIFICATE_FIXED_BASES_PREFIX,
};

pub(crate) use super::generators::{
    try_verify_prepare_poseidon_ivc as try_verify_prepare_poseidon_recursive_proof,
    verify_prepare_blake2b_ivc as verify_prepare_blake2b_recursive_proof,
    verify_prepare_poseidon_ivc as verify_prepare_poseidon_recursive_proof,
};
use super::{
    asset_readers::{
        RecursiveChainStateAsset, load_embedded_following_certificate_in_epoch_asset,
        load_embedded_next_epoch_step_output_asset, load_embedded_recursive_chain_state_asset,
        load_embedded_verification_context_asset,
    },
    generators::{
        AssetGenerationSetup, build_recursive_fixed_bases, build_recursive_global,
        build_shared_recursive_context_from_cache, certificate_public_inputs_for_step,
    },
};

/// Lightweight setup for MockProver-only tests that load VKs from the committed asset,
/// skipping the ~465s SRS generation required by `build_recursive_mock_prover_setup`.
pub(crate) struct MockProverSetup {
    /// Shared recursive global inputs.
    pub(crate) global: Global,
    /// Certificate verifying key loaded from the committed asset.
    pub(crate) certificate_verifying_key: NonRecursiveCircuitVerifyingKey,
    /// Recursive verifying key loaded from the committed asset.
    pub(crate) recursive_verifying_key: RecursiveCircuitVerifyingKey,
    /// Trivial accumulator derived from the loaded VKs.
    pub(crate) trivial_accumulator: Accumulator<RecursiveEmulation>,
}

/// Builds the lightweight MockProver setup by loading VKs from the committed asset.
///
/// Unlike `build_recursive_mock_prover_setup`, this skips SRS generation entirely
/// (~465s saved per process) and should be used by all MockProver-only negative tests.
pub(crate) fn build_mock_prover_setup_from_assets(setup: &AssetGenerationSetup) -> MockProverSetup {
    let context =
        load_embedded_verification_context_asset().expect("verification context asset should load");
    let (_, _, combined_fixed_bases) = build_recursive_fixed_bases(
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    );
    let fixed_base_names = combined_fixed_bases.keys().cloned().collect::<Vec<_>>();
    let global = build_recursive_global(
        setup,
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    );
    MockProverSetup {
        global,
        certificate_verifying_key: context.certificate_verifying_key,
        recursive_verifying_key: context.recursive_verifying_key,
        trivial_accumulator: trivial_accumulator(&fixed_base_names),
    }
}

/// Shared recursive context reused by MockProver-based golden cases.
pub(crate) struct RecursiveMockProverSetup {
    /// Certificate-sized commitment parameters used by the golden checks.
    pub(crate) certificate_commitment_parameters: ParamsKZG<Bls12>,
    /// Certificate verifying key reused by the golden checks.
    pub(crate) certificate_verifying_key: NonRecursiveCircuitVerifyingKey,
    /// Recursive verifying key reused by the golden checks.
    pub(crate) recursive_verifying_key: RecursiveCircuitVerifyingKey,
    /// Shared recursive global inputs.
    pub(crate) global: Global,
    /// Fixed bases extracted from the certificate verifying key.
    pub(crate) certificate_fixed_bases: BTreeMap<String, EmulatedCurve>,
    /// Fixed bases extracted from the recursive verifying key.
    pub(crate) recursive_fixed_bases: BTreeMap<String, EmulatedCurve>,
    /// Union of certificate and recursive fixed bases.
    pub(crate) combined_fixed_bases: BTreeMap<String, EmulatedCurve>,
    /// Verifier-side view of the shared universal KZG parameters.
    pub(crate) universal_verifier_params: ParamsVerifierKZG<PairingEngine>,
}

/// Builds the shared recursive circuit context needed by MockProver-based golden tests.
///
/// This mirrors the verifier-side setup used by the asset generators, but keeps
/// the logic local to the golden helper layer so the base-case test can be
/// reviewed independently from the generator code.
pub(crate) fn build_recursive_mock_prover_setup(
    setup: &AssetGenerationSetup,
) -> RecursiveMockProverSetup {
    let context = build_shared_recursive_context_from_cache(setup);
    let (certificate_fixed_bases, recursive_fixed_bases, combined_fixed_bases) =
        build_recursive_fixed_bases(
            &context.certificate_verifying_key,
            &context.recursive_verifying_key,
        );

    let global = build_recursive_global(
        setup,
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    );

    RecursiveMockProverSetup {
        certificate_commitment_parameters: context.certificate_commitment_parameters,
        certificate_verifying_key: context.certificate_verifying_key,
        recursive_verifying_key: context.recursive_verifying_key,
        global,
        certificate_fixed_bases,
        recursive_fixed_bases,
        combined_fixed_bases,
        universal_verifier_params: context.universal_verifier_params,
    }
}

/// Runs `MockProver` on the recursive circuit and asserts that at least one constraint fails.
pub(crate) fn assert_recursive_mock_prover_rejects(
    ivc_circuit_data: IvcCircuitData,
    public_inputs: Vec<NativeField>,
) {
    let prover = MockProver::run(&ivc_circuit_data, vec![vec![], public_inputs])
        .expect("recursive MockProver setup should succeed");
    prover
        .verify()
        .expect_err("recursive MockProver should reject the provided circuit and public inputs");
}

/// Runs `MockProver` and asserts all constraints hold, printing `label` on failure so
/// the failing case is identifiable when multiple scenarios share one `#[test]` function.
pub(crate) fn assert_recursive_mock_prover_accepts_with_label(
    ivc_circuit_data: IvcCircuitData,
    public_inputs: Vec<NativeField>,
    label: &str,
) {
    let prover = MockProver::run(&ivc_circuit_data, vec![vec![], public_inputs])
        .expect("recursive MockProver setup should succeed");
    prover.verify().unwrap_or_else(|errors| {
        panic!(
            "MockProver should accept the circuit and public inputs — case: {label}\n\
             Constraint failures: {errors:?}"
        )
    });
}

/// Prepares the stored previous recursive proof and returns its accumulator contribution.
///
/// This mirrors the first half of the normal recursive-step asset generation:
/// the previous recursive proof is verified off-circuit against the stored
/// state/accumulator public inputs, then reduced to the accumulator term that
/// the next step folds in-circuit.
pub(crate) fn prepare_previous_recursive_proof_accumulator(
    setup: &RecursiveMockProverSetup,
    recursive_chain_state: &RecursiveChainStateAsset,
) -> Accumulator<RecursiveEmulation> {
    let previous_public_inputs = [
        setup.global.as_public_input(),
        recursive_chain_state.state.as_public_input(),
        AssignedAccumulator::as_public_input(&recursive_chain_state.accumulator),
    ]
    .concat();

    let previous_dual_msm = verify_prepare_poseidon_recursive_proof(
        setup.recursive_verifying_key.as_ref(),
        recursive_chain_state.ivc_proof.as_bytes(),
        &previous_public_inputs,
    );
    assert!(
        previous_dual_msm.clone().check(&setup.universal_verifier_params),
        "stored previous recursive proof should verify before the normal step check"
    );

    let mut previous_proof_accumulator: Accumulator<RecursiveEmulation> =
        Accumulator::from_dual_msm(
            previous_dual_msm,
            IVC_FIXED_BASES_PREFIX,
            &setup.recursive_fixed_bases,
        );
    previous_proof_accumulator.collapse();
    previous_proof_accumulator
}

/// Computes the expected next accumulator for one normal non-genesis recursive step.
///
/// This folds the stored previous accumulator, the fresh certificate
/// contribution, and the prepared previous recursive-proof contribution exactly
/// as the generator does for `recursive_step_output`.
pub(crate) fn compute_expected_next_accumulator(
    setup: &RecursiveMockProverSetup,
    recursive_chain_state: &RecursiveChainStateAsset,
    certificate_accumulator: Accumulator<RecursiveEmulation>,
) -> Accumulator<RecursiveEmulation> {
    let previous_proof_accumulator =
        prepare_previous_recursive_proof_accumulator(setup, recursive_chain_state);

    let mut next_accumulator = Accumulator::accumulate(&[
        recursive_chain_state.accumulator.clone(),
        certificate_accumulator,
        previous_proof_accumulator,
    ]);
    next_accumulator.collapse();
    assert!(
        next_accumulator.check(
            &setup.universal_verifier_params,
            &setup.combined_fixed_bases
        ),
        "expected next accumulator should verify before the normal step check"
    );
    next_accumulator
}

/// Prepares the stored certificate proof used by the committed recursive step.
///
/// The certificate proof is verified against the public inputs implied by the
/// stored chain transition:
/// - `merkle_tree_commitment` comes from the previous state's `next_merkle_tree_commitment`
/// - `message` is the committed `next_state.message`
pub(crate) fn prepare_stored_step_certificate_accumulator(
    setup: &RecursiveMockProverSetup,
    recursive_chain_state: &RecursiveChainStateAsset,
    expected_next_state: &State,
    certificate_proof: &[u8],
) -> Accumulator<RecursiveEmulation> {
    let certificate_public_inputs =
        certificate_public_inputs_for_step(&recursive_chain_state.state, expected_next_state);

    let certificate_dual_msm = verify_prepare_poseidon_recursive_proof(
        setup.certificate_verifying_key.as_ref(),
        certificate_proof,
        &certificate_public_inputs,
    );
    assert!(
        certificate_dual_msm
            .clone()
            .check(&setup.certificate_commitment_parameters.verifier_params()),
        "stored step certificate proof should verify before the chained-flow check"
    );

    let mut certificate_accumulator: Accumulator<RecursiveEmulation> = Accumulator::from_dual_msm(
        certificate_dual_msm,
        CERTIFICATE_FIXED_BASES_PREFIX,
        &setup.certificate_fixed_bases,
    );
    certificate_accumulator.collapse();
    certificate_accumulator
}

/// A non-genesis MockProver stimulus assembled entirely from committed step assets.
///
/// Unlike [`build_genesis_mock_prover_circuit`], this carries the stored certificate proof, the
/// stored previous recursive proof and the stored previous accumulator, so the accumulator the
/// circuit computes is the stored next accumulator. That is what makes it satisfiable at a
/// non-genesis step, where the accumulator contributions are no longer gated to the group identity.
pub(crate) struct AssetBackedStepFixture {
    /// Circuit data for the step.
    pub(crate) ivc_circuit_data: IvcCircuitData,
    /// Public statement the step is expected to satisfy.
    pub(crate) public_inputs: Vec<NativeField>,
}

/// The stored half of one recursive step, plus the commitment its certificate was produced against.
///
/// That commitment is not read from the step-output asset but chosen by transition type: a
/// same-epoch certificate is produced against the checkpoint's current Merkle-tree commitment, a
/// next-epoch one against its next commitment. The stored final recursive proof is deliberately
/// absent — MockProver checks the step's constraints and never verifies the step's own output.
struct StepFixtureData {
    certificate_merkle_tree_commitment: MerkleTreeCommitment,
    certificate_proof: CertificateProofBytes,
    message_preimage: [u8; PREIMAGE_SIZE],
    next_state: State,
    next_accumulator: Accumulator<RecursiveEmulation>,
}

/// Assembles a non-genesis fixture from a stored chain checkpoint and a stored step output.
fn build_asset_backed_step_fixture(
    mock_prover_setup: &MockProverSetup,
    recursive_chain_state: RecursiveChainStateAsset,
    stored: StepFixtureData,
) -> AssetBackedStepFixture {
    let RecursiveChainStateAsset {
        global_field_elements,
        state,
        ivc_proof,
        accumulator,
        genesis_signature,
    } = recursive_chain_state;

    // Turns a future drift between the reconstructed global and the stored one into a direct
    // coherence error instead of an opaque constraint failure.
    assert_eq!(
        mock_prover_setup.global.as_public_input(),
        global_field_elements,
        "the reconstructed global should match the one the stored checkpoint was proved against"
    );

    let witness = Witness::new(
        genesis_signature,
        stored.next_state.message,
        stored.certificate_merkle_tree_commitment,
        ProtocolMessagePreimage::new(stored.message_preimage),
    );
    let public_inputs = [
        mock_prover_setup.global.as_public_input(),
        stored.next_state.as_public_input(),
        AssignedAccumulator::as_public_input(&stored.next_accumulator),
    ]
    .concat();
    let ivc_circuit_data = IvcCircuitData::try_new(
        mock_prover_setup.global.clone(),
        state,
        witness,
        stored.certificate_proof,
        ivc_proof,
        accumulator,
        &mock_prover_setup.certificate_verifying_key,
        &mock_prover_setup.recursive_verifying_key,
    )
    .expect("valid IvcCircuitData construction");

    AssetBackedStepFixture {
        ivc_circuit_data,
        public_inputs,
    }
}

/// Builds the satisfiable same-epoch fixture from the committed assets.
pub(crate) fn build_asset_backed_same_epoch_fixture(
    mock_prover_setup: &MockProverSetup,
) -> AssetBackedStepFixture {
    let recursive_chain_state = load_embedded_recursive_chain_state_asset()
        .expect("recursive chain state asset should load");
    let step_output = load_embedded_following_certificate_in_epoch_asset()
        .expect("following certificate in epoch asset should load");
    let stored = StepFixtureData {
        certificate_merkle_tree_commitment: recursive_chain_state.state.merkle_tree_commitment,
        certificate_proof: step_output.certificate_proof,
        message_preimage: step_output.message_preimage,
        next_state: step_output.next_state,
        next_accumulator: step_output.next_accumulator,
    };
    build_asset_backed_step_fixture(mock_prover_setup, recursive_chain_state, stored)
}

/// Builds the satisfiable next-epoch fixture from the committed assets.
pub(crate) fn build_asset_backed_next_epoch_fixture(
    mock_prover_setup: &MockProverSetup,
) -> AssetBackedStepFixture {
    let recursive_chain_state = load_embedded_recursive_chain_state_asset()
        .expect("recursive chain state asset should load");
    let step_output = load_embedded_next_epoch_step_output_asset()
        .expect("recursive step output asset should load");
    let stored = StepFixtureData {
        certificate_merkle_tree_commitment: recursive_chain_state.state.next_merkle_tree_commitment,
        certificate_proof: step_output.certificate_proof,
        message_preimage: step_output.message_preimage,
        next_state: step_output.next_state,
        next_accumulator: step_output.next_accumulator,
    };
    build_asset_backed_step_fixture(mock_prover_setup, recursive_chain_state, stored)
}

/// Builds an `IvcCircuitData` with empty proof slots and a trivial accumulator, for MockProver
/// constraint checks at the genesis step only.
///
/// Empty proof slots work here because genesis gating scales both accumulator contributions to the
/// group identity, so the trivial input accumulator is also the expected output. At any later step
/// the contributions are live and the circuit derives an output accumulator no trivial instance can
/// match — see [`build_asset_backed_same_epoch_fixture`] for the non-genesis stimulus.
pub(crate) fn build_genesis_mock_prover_circuit(
    setup: &MockProverSetup,
    prev_state: State,
    witness: Witness,
) -> IvcCircuitData {
    assert_eq!(
        prev_state.step_counter.as_u64(),
        0,
        "the trivial-accumulator stimulus is satisfiable only at genesis"
    );
    IvcCircuitData::try_new(
        setup.global.clone(),
        prev_state,
        witness,
        CertificateProofBytes::empty(),
        IvcProofBytes::empty(),
        setup.trivial_accumulator.clone(),
        &setup.certificate_verifying_key,
        &setup.recursive_verifying_key,
    )
    .expect("valid IvcCircuitData construction")
}

/// Builds the public-input vector for a genesis MockProver stimulus.
///
/// The accumulator section carries the trivial accumulator, which is the expected output only while
/// genesis gating scales both contributions to the group identity.
pub(crate) fn build_genesis_mock_prover_public_inputs(
    setup: &MockProverSetup,
    next_state: &State,
) -> Vec<NativeField> {
    [
        setup.global.as_public_input(),
        next_state.as_public_input(),
        AssignedAccumulator::as_public_input(&setup.trivial_accumulator),
    ]
    .concat()
}

/// Verifies the stored certificate proof and returns the accumulator
/// together with the certificate fixed-base map and `verifier_params`.
///
/// Uses the next-epoch step assets: the certificate proof lives in
/// `recursive_step_output` and its public inputs are derived from
/// `(recursive_chain_state.state, recursive_step_output.next_state)`.
pub(crate) fn build_certificate_accumulator_from_assets() -> (
    Accumulator<RecursiveEmulation>,
    BTreeMap<String, EmulatedCurve>,
    ParamsVerifierKZG<PairingEngine>,
) {
    let verification_context =
        load_embedded_verification_context_asset().expect("verification context asset should load");
    let recursive_chain_state = load_embedded_recursive_chain_state_asset()
        .expect("recursive chain state asset should load");
    let recursive_step_output = load_embedded_next_epoch_step_output_asset()
        .expect("recursive step output asset should load");

    let (certificate_fixed_bases, _, _) = build_recursive_fixed_bases(
        &verification_context.certificate_verifying_key,
        &verification_context.recursive_verifying_key,
    );

    let certificate_public_inputs = certificate_public_inputs_for_step(
        &recursive_chain_state.state,
        &recursive_step_output.next_state,
    );

    let accumulator: Accumulator<RecursiveEmulation> = Accumulator::from_dual_msm(
        verify_prepare_poseidon_recursive_proof(
            verification_context.certificate_verifying_key.as_ref(),
            recursive_step_output.certificate_proof.as_bytes(),
            &certificate_public_inputs,
        ),
        CERTIFICATE_FIXED_BASES_PREFIX,
        &certificate_fixed_bases,
    );

    (
        accumulator,
        certificate_fixed_bases,
        verification_context.verifier_params,
    )
}

/// Verifies the stored chain-state IVC proof and returns the accumulator
/// together with the recursive fixed-base map, ready for resolution tests.
///
/// The chain-state proof is a Poseidon recursive proof; its public inputs are
/// `[global | state | accumulator]` as stored in the committed assets.
pub(crate) fn build_recursive_proof_accumulator_from_assets() -> (
    Accumulator<RecursiveEmulation>,
    BTreeMap<String, EmulatedCurve>,
) {
    let verification_context =
        load_embedded_verification_context_asset().expect("verification context asset should load");
    let recursive_chain_state = load_embedded_recursive_chain_state_asset()
        .expect("recursive chain state asset should load");

    let (_, recursive_fixed_bases, _) = build_recursive_fixed_bases(
        &verification_context.certificate_verifying_key,
        &verification_context.recursive_verifying_key,
    );

    let public_inputs = [
        verification_context.global_field_elements.clone(),
        recursive_chain_state.state.as_public_input(),
        AssignedAccumulator::as_public_input(&recursive_chain_state.accumulator),
    ]
    .concat();

    let accumulator: Accumulator<RecursiveEmulation> = Accumulator::from_dual_msm(
        verify_prepare_poseidon_recursive_proof(
            verification_context.recursive_verifying_key.as_ref(),
            recursive_chain_state.ivc_proof.as_bytes(),
            &public_inputs,
        ),
        IVC_FIXED_BASES_PREFIX,
        &recursive_fixed_bases,
    );

    (accumulator, recursive_fixed_bases)
}

/// Recomputes the exact next accumulator from stored step artifacts.
pub(crate) fn compute_exact_next_accumulator_from_assets(
    setup: &RecursiveMockProverSetup,
    recursive_chain_state: &RecursiveChainStateAsset,
    expected_next_state: &State,
    certificate_proof: &[u8],
) -> Accumulator<RecursiveEmulation> {
    let certificate_accumulator = prepare_stored_step_certificate_accumulator(
        setup,
        recursive_chain_state,
        expected_next_state,
        certificate_proof,
    );
    compute_expected_next_accumulator(setup, recursive_chain_state, certificate_accumulator)
}
