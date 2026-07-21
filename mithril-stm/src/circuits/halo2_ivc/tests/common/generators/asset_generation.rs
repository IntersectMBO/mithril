use std::time::Instant;

use midnight_circuits::types::Instantiable;
use rand_core::OsRng;
use sha2::{Digest as Sha2Digest, Sha256};

use super::proofs::{
    prove_blake2b_ivc, prove_poseidon_ivc, verify_prepare_blake2b_ivc, verify_prepare_poseidon_ivc,
};
use super::setup::{
    AssetGenerationSetup, AssetPaths, GENESIS_EPOCH, INITIAL_CHAIN_LENGTH,
    build_recursive_fixed_bases, build_recursive_global, build_recursive_proving_key,
    build_shared_recursive_context,
};
use super::transitions::{
    build_genesis_base_case_next_state, build_genesis_base_case_witness,
    build_genesis_protocol_message_preimage, build_next_certificate_asset_data,
    build_same_epoch_certificate_asset_data,
};
use crate::circuits::halo2_ivc::IVC_FIXED_BASES_PREFIX;
use crate::circuits::halo2_ivc::tests::common::asset_readers::{
    FirstCertificateInEpochAsset, FollowingCertificateInEpochAsset, GenesisBenchmarkFixture,
    GenesisStepOutputAsset, NextEpochStepOutputAsset, RecursiveChainStateAsset,
    VerificationContextAsset, load_recursive_chain_state_asset,
    store_first_certificate_in_epoch_asset, store_following_certificate_in_epoch_asset,
    store_genesis_benchmark_fixture, store_genesis_step_output_asset,
    store_next_epoch_step_output_asset, store_recursive_chain_state_asset,
    store_verification_context_asset,
};
use crate::circuits::halo2_ivc::{
    Accumulator, AssignedAccumulator, EmulatedCurve, PREIMAGE_SIZE, RecursiveEmulation,
    accumulator::trivial_accumulator,
    circuit::IvcCircuitData,
    keys::RecursiveCircuitProvingKey,
    state::{Global, State},
    types::{CertificateProofBytes, IvcProofBytes},
};

struct CertificateChainArtifacts {
    certificate_proofs: Vec<CertificateProofBytes>,
    certificate_accumulators: Vec<Accumulator<RecursiveEmulation>>,
    recursive_next_states: Vec<State>,
    recursive_witnesses: Vec<crate::circuits::halo2_ivc::state::Witness>,
}

struct RecursiveChainSnapshot {
    state: State,
    ivc_proof: IvcProofBytes,
    accumulator: Accumulator<RecursiveEmulation>,
}

struct NextRecursiveStepInputs {
    certificate_proof: CertificateProofBytes,
    next_state: State,
    recursive_witness: crate::circuits::halo2_ivc::state::Witness,
    next_accumulator: Accumulator<RecursiveEmulation>,
}

fn build_certificate_chain_artifacts(
    setup: &AssetGenerationSetup,
    context: &super::setup::SharedRecursiveContext,
    recursive_fixed_base_names: &[String],
) -> CertificateChainArtifacts {
    let mut certificate_proofs = vec![CertificateProofBytes::empty()];
    let mut certificate_accumulators = vec![trivial_accumulator(recursive_fixed_base_names)];
    let mut recursive_next_states = vec![build_genesis_base_case_next_state(setup, GENESIS_EPOCH)];
    let mut recursive_witnesses = vec![build_genesis_base_case_witness(setup)];
    let mut certificate_random_generator = OsRng;

    for step in 1..=INITIAL_CHAIN_LENGTH {
        println!(
            "generate_recursive_chain_state: certificate proof {step}/{INITIAL_CHAIN_LENGTH} starting"
        );
        let certificate_step_start = Instant::now();
        let previous_state = recursive_next_states
            .last()
            .expect("recursive chain should always have a previous state")
            .clone();
        let (certificate_proof, certificate_accumulator, next_state, recursive_witness) =
            build_next_certificate_asset_data(
                setup,
                &context.certificate_commitment_parameters,
                &setup.certificate_relation,
                &context.certificate_verifying_key,
                &previous_state,
                &mut certificate_random_generator,
            );

        recursive_next_states.push(next_state);
        recursive_witnesses.push(recursive_witness);

        println!(
            "generate_recursive_chain_state: certificate proof {step}/{INITIAL_CHAIN_LENGTH} done in {:?}",
            certificate_step_start.elapsed()
        );

        certificate_proofs.push(certificate_proof);
        certificate_accumulators.push(certificate_accumulator);
    }

    CertificateChainArtifacts {
        certificate_proofs,
        certificate_accumulators,
        recursive_next_states,
        recursive_witnesses,
    }
}

fn build_recursive_chain_snapshot(
    setup: &AssetGenerationSetup,
    context: &super::setup::SharedRecursiveContext,
    global: &Global,
    recursive_proving_key: &RecursiveCircuitProvingKey,
    recursive_fixed_bases: &std::collections::BTreeMap<String, EmulatedCurve>,
    combined_fixed_bases: &std::collections::BTreeMap<String, EmulatedCurve>,
    artifacts: CertificateChainArtifacts,
) -> RecursiveChainSnapshot {
    let combined_fixed_base_names = combined_fixed_bases.keys().cloned().collect::<Vec<_>>();
    let mut current_state = State::genesis();
    let mut recursive_proof = IvcProofBytes::empty();
    let mut current_accumulator = trivial_accumulator(&combined_fixed_base_names);
    let mut next_accumulator = current_accumulator.clone();
    let mut recursive_random_generator = OsRng;

    for i in 0..=INITIAL_CHAIN_LENGTH {
        println!(
            "generate_recursive_chain_state: recursive proof {}/{} starting",
            i + 1,
            INITIAL_CHAIN_LENGTH + 1
        );
        let recursive_step_start = Instant::now();
        let ivc_circuit_data = IvcCircuitData::try_new(
            global.clone(),
            current_state.clone(),
            artifacts.recursive_witnesses[i].clone(),
            artifacts.certificate_proofs[i].clone(),
            recursive_proof.clone(),
            current_accumulator.clone(),
            &context.certificate_verifying_key,
            &context.recursive_verifying_key,
        )
        .expect("valid IvcCircuitData construction");

        let public_inputs = [
            global.as_public_input(),
            artifacts.recursive_next_states[i].as_public_input(),
            AssignedAccumulator::as_public_input(&next_accumulator),
        ]
        .concat();

        let proof = prove_poseidon_ivc(
            &context.recursive_commitment_parameters,
            recursive_proving_key,
            &ivc_circuit_data,
            &public_inputs,
            &mut recursive_random_generator,
        );
        let dual_msm = verify_prepare_poseidon_ivc(
            context.recursive_verifying_key.as_ref(),
            &proof,
            &public_inputs,
        );
        assert!(dual_msm.clone().check(&context.universal_verifier_params));
        let mut proof_accumulator: Accumulator<RecursiveEmulation> =
            Accumulator::from_dual_msm(dual_msm, IVC_FIXED_BASES_PREFIX, recursive_fixed_bases);
        proof_accumulator.collapse();

        println!(
            "generate_recursive_chain_state: recursive proof {}/{} done in {:?}",
            i + 1,
            INITIAL_CHAIN_LENGTH + 1,
            recursive_step_start.elapsed()
        );

        current_state = artifacts.recursive_next_states[i].clone();
        current_accumulator = next_accumulator.clone();
        recursive_proof = IvcProofBytes::new(proof);

        if i < INITIAL_CHAIN_LENGTH {
            let mut accumulated_accumulator = Accumulator::accumulate(&[
                next_accumulator.clone(),
                artifacts.certificate_accumulators[i + 1].clone(),
                proof_accumulator,
            ]);
            accumulated_accumulator.collapse();
            assert!(
                accumulated_accumulator.check(
                    &context.universal_kzg_parameters.verifier_params(),
                    combined_fixed_bases,
                ),
                "recursive accumulator verification failed at step {i}"
            );
            next_accumulator = accumulated_accumulator;
        }
    }

    assert_eq!(
        current_state.next_merkle_tree_commitment.as_field(),
        setup.genesis_next_merkle_tree_commitment,
        "recursive_chain_state writer is about to persist a next_merkle_tree_commitment that does not match setup"
    );

    RecursiveChainSnapshot {
        state: current_state,
        ivc_proof: recursive_proof,
        accumulator: current_accumulator,
    }
}

fn store_recursive_chain_snapshot(
    setup: &AssetGenerationSetup,
    paths: &AssetPaths,
    global: &Global,
    snapshot: &RecursiveChainSnapshot,
) {
    println!(
        "generate_recursive_chain_state: writing asset -> {}",
        paths.recursive_chain_state.display()
    );
    let asset = RecursiveChainStateAsset {
        global_field_elements: global.as_public_input(),
        state: snapshot.state.clone(),
        ivc_proof: snapshot.ivc_proof.clone(),
        accumulator: snapshot.accumulator.clone(),
        genesis_signature: setup.genesis_signature,
    };
    store_recursive_chain_state_asset(&paths.recursive_chain_state, &asset)
        .expect("failed to write recursive_chain_state asset");

    let reloaded = load_recursive_chain_state_asset(&paths.recursive_chain_state)
        .expect("failed to reload recursive_chain_state asset after writing");
    assert_eq!(
        reloaded.state.next_merkle_tree_commitment.as_field(),
        setup.genesis_next_merkle_tree_commitment,
        "reloaded recursive_chain_state next_merkle_tree_commitment does not match setup"
    );
}

fn build_next_recursive_step_inputs(
    setup: &AssetGenerationSetup,
    context: &super::setup::SharedRecursiveContext,
    global: &Global,
    recursive_chain_state: &RecursiveChainStateAsset,
    recursive_fixed_bases: &std::collections::BTreeMap<String, EmulatedCurve>,
    combined_fixed_bases: &std::collections::BTreeMap<String, EmulatedCurve>,
) -> NextRecursiveStepInputs {
    let mut recursive_step_output_random_generator = OsRng;
    println!("generate_recursive_step_output: building next certificate");
    let certificate_start = Instant::now();
    let (certificate_proof, certificate_accumulator, next_state, recursive_witness) =
        build_next_certificate_asset_data(
            setup,
            &context.certificate_commitment_parameters,
            &setup.certificate_relation,
            &context.certificate_verifying_key,
            &recursive_chain_state.state,
            &mut recursive_step_output_random_generator,
        );
    println!(
        "generate_recursive_step_output: next certificate done in {:?}",
        certificate_start.elapsed()
    );

    let previous_public_inputs = [
        global.as_public_input(),
        recursive_chain_state.state.as_public_input(),
        AssignedAccumulator::as_public_input(&recursive_chain_state.accumulator),
    ]
    .concat();
    let previous_dual_msm = verify_prepare_poseidon_ivc(
        context.recursive_verifying_key.as_ref(),
        recursive_chain_state.ivc_proof.as_bytes(),
        &previous_public_inputs,
    );
    assert!(previous_dual_msm.clone().check(&context.universal_verifier_params));
    let mut previous_proof_accumulator: Accumulator<RecursiveEmulation> =
        Accumulator::from_dual_msm(
            previous_dual_msm,
            IVC_FIXED_BASES_PREFIX,
            recursive_fixed_bases,
        );
    previous_proof_accumulator.collapse();

    let mut next_accumulator = Accumulator::accumulate(&[
        recursive_chain_state.accumulator.clone(),
        certificate_accumulator,
        previous_proof_accumulator,
    ]);
    next_accumulator.collapse();
    assert!(
        next_accumulator.check(
            &context.universal_kzg_parameters.verifier_params(),
            combined_fixed_bases,
        ),
        "next accumulator check failed"
    );
    println!("generate_recursive_step_output: next accumulator computed");

    NextRecursiveStepInputs {
        certificate_proof,
        next_state,
        recursive_witness,
        next_accumulator,
    }
}

fn build_recursive_step_output_proof(
    context: &super::setup::SharedRecursiveContext,
    global: &Global,
    recursive_proving_key: &RecursiveCircuitProvingKey,
    recursive_chain_state: &RecursiveChainStateAsset,
    next_step_inputs: &NextRecursiveStepInputs,
) -> Vec<u8> {
    let mut recursive_step_output_random_generator = OsRng;
    let ivc_circuit_data = IvcCircuitData::try_new(
        global.clone(),
        recursive_chain_state.state.clone(),
        next_step_inputs.recursive_witness.clone(),
        next_step_inputs.certificate_proof.clone(),
        recursive_chain_state.ivc_proof.clone(),
        recursive_chain_state.accumulator.clone(),
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    )
    .expect("valid IvcCircuitData construction");
    let public_inputs = [
        global.as_public_input(),
        next_step_inputs.next_state.as_public_input(),
        AssignedAccumulator::as_public_input(&next_step_inputs.next_accumulator),
    ]
    .concat();

    println!("generate_recursive_step_output: final blake2b recursive proof starting");
    let final_proof_start = Instant::now();
    let final_proof = prove_blake2b_ivc(
        &context.recursive_commitment_parameters,
        recursive_proving_key,
        &ivc_circuit_data,
        &public_inputs,
        &mut recursive_step_output_random_generator,
    );
    let final_dual_msm = verify_prepare_blake2b_ivc(
        context.recursive_verifying_key.as_ref(),
        &final_proof,
        &public_inputs,
    );
    assert!(final_dual_msm.check(&context.universal_verifier_params));
    println!(
        "generate_recursive_step_output: final blake2b recursive proof done in {:?}",
        final_proof_start.elapsed()
    );
    final_proof
}

fn store_recursive_step_output(
    paths: &AssetPaths,
    next_step_inputs: NextRecursiveStepInputs,
    proof: Vec<u8>,
) {
    println!(
        "generate_recursive_step_output: writing asset -> {}",
        paths.recursive_step_output.display()
    );
    let message_preimage = next_step_inputs.recursive_witness.message_preimage.into_inner();
    let message: [u8; 32] = Sha256::digest(message_preimage.as_slice()).into();
    let aggregate_verification_key_merkle_root: [u8; 32] = next_step_inputs
        .recursive_witness
        .certificate_merkle_tree_commitment
        .as_field()
        .to_bytes_le();
    let asset = NextEpochStepOutputAsset {
        ivc_proof: IvcProofBytes::new(proof),
        next_accumulator: next_step_inputs.next_accumulator,
        next_state: next_step_inputs.next_state,
        certificate_proof: next_step_inputs.certificate_proof,
        message,
        message_preimage,
        aggregate_verification_key_merkle_root,
    };
    store_next_epoch_step_output_asset(&paths.recursive_step_output, &asset)
        .expect("failed to write next-epoch step output asset");
}

/// Generates and writes the stored recursive chain snapshot asset.
pub(crate) fn generate_recursive_chain_state_asset(
    setup: &AssetGenerationSetup,
    paths: &AssetPaths,
) {
    println!(
        "generate_recursive_chain_state: start -> {}",
        paths.recursive_chain_state.display()
    );
    let total_start = Instant::now();

    let context = build_shared_recursive_context(setup);
    let (_, recursive_fixed_bases, combined_fixed_bases) = build_recursive_fixed_bases(
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    );
    let recursive_fixed_base_names = recursive_fixed_bases.keys().cloned().collect::<Vec<_>>();
    let recursive_proving_key = build_recursive_proving_key(&context);
    println!("generate_recursive_chain_state: shared recursive context ready");
    let global = build_recursive_global(
        setup,
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    );
    let artifacts = build_certificate_chain_artifacts(setup, &context, &recursive_fixed_base_names);
    let snapshot = build_recursive_chain_snapshot(
        setup,
        &context,
        &global,
        &recursive_proving_key,
        &recursive_fixed_bases,
        &combined_fixed_bases,
        artifacts,
    );
    store_recursive_chain_snapshot(setup, paths, &global, &snapshot);
    println!(
        "generate_recursive_chain_state: done in {:?}",
        total_start.elapsed()
    );
}

/// Generates and writes the static verifier-side asset bundle.
pub(crate) fn generate_verification_context_asset(
    setup: &AssetGenerationSetup,
    paths: &AssetPaths,
) {
    println!(
        "generate_verification_context: start -> {}",
        paths.verification_context.display()
    );
    let total_start = Instant::now();
    let context = build_shared_recursive_context(setup);
    println!("generate_verification_context: certificate and recursive verifying keys ready");

    let (_, _, combined_fixed_bases) = build_recursive_fixed_bases(
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    );

    let global = build_recursive_global(
        setup,
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    );

    let asset = VerificationContextAsset {
        global_field_elements: global.as_public_input(),
        recursive_verifying_key: context.recursive_verifying_key.clone(),
        combined_fixed_bases,
        verifier_params: context.universal_verifier_params,
        certificate_verifying_key: context.certificate_verifying_key,
    };
    store_verification_context_asset(&paths.verification_context, &asset)
        .expect("failed to write verification_context asset");
    println!(
        "generate_verification_context: done in {:?}",
        total_start.elapsed()
    );
}

/// Generates and writes the asset produced by one more recursive step.
pub(crate) fn generate_recursive_step_output_asset(
    setup: &AssetGenerationSetup,
    paths: &AssetPaths,
) {
    println!(
        "generate_recursive_step_output: start -> {}",
        paths.recursive_step_output.display()
    );
    let total_start = Instant::now();
    println!(
        "generate_recursive_step_output: loading recursive chain state <- {}",
        paths.recursive_chain_state.display()
    );
    let recursive_chain_state = load_recursive_chain_state_asset(&paths.recursive_chain_state)
        .expect("failed to load recursive_chain_state asset");

    let context = build_shared_recursive_context(setup);
    let recursive_proving_key = build_recursive_proving_key(&context);
    println!("generate_recursive_step_output: certificate and recursive keys ready");

    let (_, recursive_fixed_bases, combined_fixed_bases) = build_recursive_fixed_bases(
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    );

    let global = build_recursive_global(
        setup,
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    );
    let next_step_inputs = build_next_recursive_step_inputs(
        setup,
        &context,
        &global,
        &recursive_chain_state,
        &recursive_fixed_bases,
        &combined_fixed_bases,
    );
    let final_proof = build_recursive_step_output_proof(
        &context,
        &global,
        &recursive_proving_key,
        &recursive_chain_state,
        &next_step_inputs,
    );
    store_recursive_step_output(paths, next_step_inputs, final_proof);
    println!(
        "generate_recursive_step_output: done in {:?}",
        total_start.elapsed()
    );
}

/// Generates and writes the genesis step output asset (one Blake2b IVC proof
/// from the genesis base case, with no prior certificate or IVC proof).
pub(crate) fn generate_genesis_step_output_asset(setup: &AssetGenerationSetup, paths: &AssetPaths) {
    println!(
        "generate_genesis_step_output: start -> {}",
        paths.genesis_step_output.display()
    );
    let total_start = Instant::now();

    let context = build_shared_recursive_context(setup);
    let (_, _, combined_fixed_bases) = build_recursive_fixed_bases(
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    );
    let combined_fixed_base_names = combined_fixed_bases.keys().cloned().collect::<Vec<_>>();
    let recursive_proving_key = build_recursive_proving_key(&context);
    let global = build_recursive_global(
        setup,
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    );

    let genesis_witness = build_genesis_base_case_witness(setup);
    let genesis_next_state = build_genesis_base_case_next_state(setup, GENESIS_EPOCH);
    let current_accumulator = trivial_accumulator(&combined_fixed_base_names);
    let next_accumulator = current_accumulator.clone();

    let ivc_circuit_data = IvcCircuitData::try_new(
        global.clone(),
        State::genesis(),
        genesis_witness,
        CertificateProofBytes::empty(),
        IvcProofBytes::empty(),
        current_accumulator,
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    )
    .expect("valid IvcCircuitData construction");

    let public_inputs = [
        global.as_public_input(),
        genesis_next_state.as_public_input(),
        AssignedAccumulator::as_public_input(&next_accumulator),
    ]
    .concat();

    let mut rng = OsRng;
    println!("generate_genesis_step_output: proving Blake2b");
    let proof_start = Instant::now();
    let proof = prove_blake2b_ivc(
        &context.recursive_commitment_parameters,
        &recursive_proving_key,
        &ivc_circuit_data,
        &public_inputs,
        &mut rng,
    );
    let dual_msm = verify_prepare_blake2b_ivc(
        context.recursive_verifying_key.as_ref(),
        &proof,
        &public_inputs,
    );
    assert!(
        dual_msm.check(&context.universal_verifier_params),
        "genesis step proof verification failed"
    );
    println!(
        "generate_genesis_step_output: proven in {:?}",
        proof_start.elapsed()
    );

    println!(
        "generate_genesis_step_output: writing asset -> {}",
        paths.genesis_step_output.display()
    );
    let asset = GenesisStepOutputAsset {
        ivc_proof: IvcProofBytes::new(proof),
        next_accumulator,
        next_state: genesis_next_state,
        certificate_proof: CertificateProofBytes::empty(),
        // Genesis base case carries no certificate proof; the prepare-side tests bypass this asset.
        // Zero-byte placeholders keep the field types fixed-size across genesis and non-genesis.
        message: [0u8; 32],
        message_preimage: [0u8; PREIMAGE_SIZE],
        aggregate_verification_key_merkle_root: [0u8; 32],
    };
    store_genesis_step_output_asset(&paths.genesis_step_output, &asset)
        .expect("failed to write genesis_step_output asset");
    println!(
        "generate_genesis_step_output: done in {:?}",
        total_start.elapsed()
    );
}

/// Generates and writes the same-epoch step output asset (one Blake2b IVC
/// proof extending the stored chain state with a same-epoch certificate).
pub(crate) fn generate_same_epoch_step_output_asset(
    setup: &AssetGenerationSetup,
    paths: &AssetPaths,
) {
    println!(
        "generate_same_epoch_step_output: start -> {}",
        paths.same_epoch_step_output.display()
    );
    let total_start = Instant::now();

    let context = build_shared_recursive_context(setup);
    let (_, recursive_fixed_bases, combined_fixed_bases) = build_recursive_fixed_bases(
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    );
    let recursive_proving_key = build_recursive_proving_key(&context);
    let global = build_recursive_global(
        setup,
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    );

    println!(
        "generate_same_epoch_step_output: loading chain state <- {}",
        paths.recursive_chain_state.display()
    );
    let chain_state = load_recursive_chain_state_asset(&paths.recursive_chain_state)
        .expect("failed to load recursive_chain_state asset");

    let mut rng = OsRng;
    println!("generate_same_epoch_step_output: building same-epoch certificate");
    let cert_start = Instant::now();
    let (certificate_proof, certificate_accumulator, next_state, ivc_witness) =
        build_same_epoch_certificate_asset_data(
            setup,
            &context.certificate_commitment_parameters,
            &setup.certificate_relation,
            &context.certificate_verifying_key,
            &chain_state.state,
            &mut rng,
        );
    println!(
        "generate_same_epoch_step_output: certificate done in {:?}",
        cert_start.elapsed()
    );

    let previous_public_inputs = [
        global.as_public_input(),
        chain_state.state.as_public_input(),
        AssignedAccumulator::as_public_input(&chain_state.accumulator),
    ]
    .concat();
    let previous_dual_msm = verify_prepare_poseidon_ivc(
        context.recursive_verifying_key.as_ref(),
        chain_state.ivc_proof.as_bytes(),
        &previous_public_inputs,
    );
    assert!(
        previous_dual_msm.clone().check(&context.universal_verifier_params),
        "previous chain state proof verification failed"
    );
    let mut previous_proof_accumulator: Accumulator<RecursiveEmulation> =
        Accumulator::from_dual_msm(
            previous_dual_msm,
            IVC_FIXED_BASES_PREFIX,
            &recursive_fixed_bases,
        );
    previous_proof_accumulator.collapse();

    let mut next_accumulator = Accumulator::accumulate(&[
        chain_state.accumulator.clone(),
        certificate_accumulator,
        previous_proof_accumulator,
    ]);
    next_accumulator.collapse();
    assert!(
        next_accumulator.check(
            &context.universal_kzg_parameters.verifier_params(),
            &combined_fixed_bases,
        ),
        "same-epoch next accumulator check failed"
    );

    let ivc_circuit_data = IvcCircuitData::try_new(
        global.clone(),
        chain_state.state.clone(),
        ivc_witness.clone(),
        certificate_proof.clone(),
        chain_state.ivc_proof.clone(),
        chain_state.accumulator.clone(),
        &context.certificate_verifying_key,
        &context.recursive_verifying_key,
    )
    .expect("valid IvcCircuitData construction");

    let public_inputs = [
        global.as_public_input(),
        next_state.as_public_input(),
        AssignedAccumulator::as_public_input(&next_accumulator),
    ]
    .concat();

    println!("generate_same_epoch_step_output: proving Blake2b");
    let proof_start = Instant::now();
    let proof = prove_blake2b_ivc(
        &context.recursive_commitment_parameters,
        &recursive_proving_key,
        &ivc_circuit_data,
        &public_inputs,
        &mut rng,
    );
    let dual_msm = verify_prepare_blake2b_ivc(
        context.recursive_verifying_key.as_ref(),
        &proof,
        &public_inputs,
    );
    assert!(
        dual_msm.check(&context.universal_verifier_params),
        "same-epoch step proof verification failed"
    );
    println!(
        "generate_same_epoch_step_output: proven in {:?}",
        proof_start.elapsed()
    );

    println!(
        "generate_same_epoch_step_output: writing asset -> {}",
        paths.same_epoch_step_output.display()
    );
    let message_preimage = ivc_witness.message_preimage.into_inner();
    let message: [u8; 32] = Sha256::digest(message_preimage.as_slice()).into();
    let aggregate_verification_key_merkle_root: [u8; 32] = ivc_witness
        .certificate_merkle_tree_commitment
        .as_field()
        .to_bytes_le();
    let asset = FollowingCertificateInEpochAsset {
        ivc_proof: IvcProofBytes::new(proof),
        next_accumulator,
        next_state,
        certificate_proof,
        message,
        message_preimage,
        aggregate_verification_key_merkle_root,
    };
    store_following_certificate_in_epoch_asset(&paths.same_epoch_step_output, &asset)
        .expect("failed to write following-certificate-in-epoch asset");
    println!(
        "generate_same_epoch_step_output: done in {:?}",
        total_start.elapsed()
    );
}

/// Generates and writes the first-step certificate asset. The certificate is produced
/// against `previous_state = build_genesis_base_case_next_state()` (`step_counter == 1`),
/// so the asset captures the first real certificate after the genesis IVC step — the input
/// scenario for `IvcProverInput::prepare` at `step_counter == 1`.
pub(crate) fn generate_first_step_cert_asset(setup: &AssetGenerationSetup, paths: &AssetPaths) {
    println!(
        "generate_first_step_cert: start -> {}",
        paths.first_step_cert.display()
    );
    let total_start = Instant::now();
    let context = build_shared_recursive_context(setup);
    println!("generate_first_step_cert: shared recursive context ready");

    let mut rng = OsRng;
    println!("generate_first_step_cert: building first certificate from genesis-base-case state");
    let cert_start = Instant::now();
    // Use the genesis-base-case next-state as the cert's "previous state": this is the same
    // starting point the main asset chain uses for its first cert, and its
    // `next_merkle_tree_commitment` field equals the deterministic AVK root the cert proof
    // commits to.
    let previous_state = build_genesis_base_case_next_state(setup, GENESIS_EPOCH);
    let (certificate_proof, _certificate_accumulator, next_state, ivc_witness) =
        build_next_certificate_asset_data(
            setup,
            &context.certificate_commitment_parameters,
            &setup.certificate_relation,
            &context.certificate_verifying_key,
            &previous_state,
            &mut rng,
        );
    println!(
        "generate_first_step_cert: certificate done in {:?}",
        cert_start.elapsed()
    );

    let message_preimage = ivc_witness.message_preimage.into_inner();
    let message: [u8; 32] = Sha256::digest(message_preimage.as_slice()).into();
    let aggregate_verification_key_merkle_root: [u8; 32] = ivc_witness
        .certificate_merkle_tree_commitment
        .as_field()
        .to_bytes_le();

    let asset = FirstCertificateInEpochAsset {
        certificate_proof,
        next_state,
        message,
        message_preimage,
        aggregate_verification_key_merkle_root,
    };

    println!(
        "generate_first_step_cert: writing asset -> {}",
        paths.first_step_cert.display()
    );
    store_first_certificate_in_epoch_asset(&paths.first_step_cert, &asset)
        .expect("failed to write first-certificate-in-epoch asset");
    println!(
        "generate_first_step_cert: done in {:?}",
        total_start.elapsed()
    );
}

/// Generates and writes the additive genesis benchmark fixture asset — the genesis proving
/// inputs (raw message, verification key, signature, protocol-message preimage) the IVC
/// benchmarks need to build a `Global` and run a genesis proving step. Deterministic and
/// additive: existing golden assets are unaffected.
pub(crate) fn generate_genesis_benchmark_fixture_asset(
    setup: &AssetGenerationSetup,
    paths: &AssetPaths,
) {
    println!(
        "generate_genesis_benchmark_fixture: start -> {}",
        paths.genesis_benchmark_fixture.display()
    );
    let genesis_protocol_message_preimage: [u8; PREIMAGE_SIZE] =
        build_genesis_protocol_message_preimage(setup)
            .try_into()
            .expect("genesis protocol message preimage should be PREIMAGE_SIZE bytes");
    let genesis_message: [u8; 32] = Sha256::digest(genesis_protocol_message_preimage).into();
    let fixture = GenesisBenchmarkFixture {
        genesis_message,
        genesis_verification_key: setup.genesis_verification_key,
        genesis_signature: setup.genesis_signature,
        genesis_protocol_message_preimage,
    };
    store_genesis_benchmark_fixture(&paths.genesis_benchmark_fixture, &fixture)
        .expect("failed to write genesis benchmark fixture asset");
    println!(
        "generate_genesis_benchmark_fixture: done -> {}",
        paths.genesis_benchmark_fixture.display()
    );
}

// These ignored tests are manual asset-generation entrypoints for the committed
// golden assets. They are intentionally excluded from normal test runs because
// they rewrite binary files rather than asserting behavior.
//
// Committed assets:
//   verification_context.bin               — VKs, combined fixed bases, verifier params
//   recursive_chain_state.bin              — chain checkpoint: Poseidon IVC proof, state, folded accumulator
//   recursive_step_output.bin              — next-epoch step: IVC proof, next_state, next_accumulator, certificate proof
//   genesis_step_output.bin                — genesis step output
//   same_epoch_step_output.bin             — same-epoch step output
//   recursive_step_output_accumulator_bytes.bin — raw serialized bytes of recursive_step_output.next_accumulator
//                                            (golden anchor for the encoding stability test; derived from
//                                             recursive_step_output.bin, regenerate with
//                                             generate_recursive_step_output_accumulator_bytes_only)
#[test]
#[ignore]
fn generate_verification_context_only() {
    use super::setup::{AssetPaths, build_asset_generation_setup};
    generate_verification_context_asset(&build_asset_generation_setup(), &AssetPaths::default());
}

#[test]
#[ignore]
fn generate_recursive_chain_state_only() {
    use super::setup::{AssetPaths, build_asset_generation_setup};
    generate_recursive_chain_state_asset(&build_asset_generation_setup(), &AssetPaths::default());
}

#[test]
#[ignore]
fn generate_recursive_step_output_only() {
    use super::setup::{AssetPaths, build_asset_generation_setup};
    generate_recursive_step_output_asset(&build_asset_generation_setup(), &AssetPaths::default());
}

#[test]
#[ignore]
fn generate_genesis_step_output_only() {
    use super::setup::{AssetPaths, build_asset_generation_setup};
    generate_genesis_step_output_asset(&build_asset_generation_setup(), &AssetPaths::default());
}

#[test]
#[ignore]
fn generate_same_epoch_step_output_only() {
    use super::setup::{AssetPaths, build_asset_generation_setup};
    generate_same_epoch_step_output_asset(&build_asset_generation_setup(), &AssetPaths::default());
}

#[test]
#[ignore]
fn generate_first_step_cert_only() {
    use super::setup::{AssetPaths, build_asset_generation_setup};
    generate_first_step_cert_asset(&build_asset_generation_setup(), &AssetPaths::default());
}

#[test]
#[ignore]
fn generate_genesis_benchmark_fixture_only() {
    use super::setup::{AssetPaths, build_asset_generation_setup};
    generate_genesis_benchmark_fixture_asset(
        &build_asset_generation_setup(),
        &AssetPaths::default(),
    );
}

#[test]
#[ignore]
fn generate_recursive_step_output_accumulator_bytes_only() {
    use crate::circuits::halo2_ivc::{
        io::Write as IvcWrite,
        tests::common::asset_readers::load_embedded_next_epoch_step_output_asset,
    };
    use midnight_proofs::utils::SerdeFormat;
    let step_output = load_embedded_next_epoch_step_output_asset()
        .expect("recursive step output asset should load");
    let mut bytes = Vec::new();
    step_output
        .next_accumulator
        .write(&mut bytes, SerdeFormat::RawBytesUnchecked)
        .expect("accumulator serialization should succeed");
    let path = AssetPaths::default()
        .recursive_step_output
        .with_file_name("recursive_step_output_accumulator_bytes.bin");
    std::fs::write(&path, &bytes)
        .unwrap_or_else(|e| panic!("failed to write accumulator bytes to {path:?}: {e}"));
    println!("wrote {} bytes to {path:?}", bytes.len());
}

#[test]
#[ignore]
fn generate_recursive_proof_accumulator_bytes_only() {
    use crate::circuits::halo2_ivc::{
        io::Write as IvcWrite,
        tests::common::helpers::build_recursive_proof_accumulator_from_assets,
    };
    use midnight_proofs::utils::SerdeFormat;

    let (accumulator, _) = build_recursive_proof_accumulator_from_assets();
    let mut bytes = Vec::new();
    accumulator
        .write(&mut bytes, SerdeFormat::RawBytesUnchecked)
        .expect("accumulator serialization should succeed");
    let path = AssetPaths::default()
        .verification_context
        .with_file_name("recursive_proof_accumulator_bytes.bin");
    std::fs::write(&path, &bytes)
        .unwrap_or_else(|e| panic!("failed to write accumulator bytes to {path:?}: {e}"));
    println!("wrote {} bytes to {path:?}", bytes.len());
}
