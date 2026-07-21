//! Benchmark façade for the recursive IVC circuit.
//!
//! Exposes [`IvcBenchEnv`], a thin `benchmark-internals`-gated wrapper that delegates to the
//! production IVC proof-system code so the benchmarks measure the same code paths run in
//! production: setup (`IvcSnarkProverSetup::load`), preparation (`IvcProverInput`), recursive
//! proving (`IvcProof::prove_with_transcript`), verification (`IvcProof::verify` and the KZG
//! opening), and off-circuit accumulator folding.
//!
//! Fixtures are the committed golden assets plus the additive genesis fixture, so no proving
//! witness is fabricated here. Each prepared fixture is validated once (outside the timed loops).
//!
//! Note on the SRS: the benchmarks use a deterministic *unsafe* SRS, which
//! `TrustedSetupProvider::with_unsafe_srs` generates on construction. Its timing is representative
//! of one-time SRS generation; production instead loads a downloaded trusted SRS. The cold/warm
//! distinction is therefore measured on the circuit **keys** (the disk-cached artifact and the
//! dominant setup cost), with SRS generation reported as a separate one-off.

use std::path::Path;

use anyhow::{anyhow, ensure};
use group::Group;
use midnight_circuits::{
    hash::poseidon::PoseidonState,
    types::Instantiable,
    verifier::{Accumulator, AssignedAccumulator, BlstrsEmulation},
};
use midnight_curves::{Bls12, G1Projective};
use midnight_proofs::{
    plonk::prepare,
    poly::kzg::{KZGCommitmentScheme, params::ParamsKZG},
    transcript::{Blake2b256, CircuitTranscript, Transcript},
};
use rand_core::OsRng;

use crate::{
    AggregateVerificationKeyForSnark, MithrilMembershipDigest, Parameters, SnarkProof, StmResult,
    circuits::{
        halo2::{circuit::StmCertificateCircuit, types::CircuitBase},
        halo2_ivc::{
            RECURSIVE_CIRCUIT_DEGREE,
            circuit::IvcCircuitData,
            embedded_assets::{
                load_embedded_following_certificate_in_epoch_asset,
                load_embedded_genesis_benchmark_fixture, load_embedded_genesis_step_output_asset,
                load_embedded_next_epoch_step_output_asset,
                load_embedded_recursive_chain_state_asset,
            },
            keys::RecursiveCircuitKeyGenerator,
            state::{Global, State},
            types::{CertificateProofBytes, IvcProofBytes, ProtocolMessagePreimage},
        },
        key_provider::KeyProvider,
        trusted_setup::TrustedSetupProvider,
    },
    proof_system::ivc_halo2_snark::{
        IvcProverInput, IvcSnarkProverSetup, proof::IvcProof, rolling_state::IvcRollingState,
        verifier_setup::IvcVerifierSetup,
    },
};

/// Deterministic certificate parameters matching the committed golden assets
/// (`tests::common::generators::setup` + `tests::common::CERTIFICATE_CIRCUIT_DEGREE`). If these
/// drift from the asset generators, `IvcSnarkProverSetup::load` derives a certificate verifying
/// key that does not match the committed certificate proofs, and fixture preparation fails its
/// validity assert — so a mismatch surfaces loudly rather than producing bogus numbers.
const QUORUM_SIZE: u64 = 2;
const NUMBER_OF_LOTTERIES: u64 = QUORUM_SIZE * 10;
const SIGNER_COUNT: usize = 3000;
const TOTAL_STAKE: u64 = 1_000_000;
const PHI_F: f64 = 0.2;

/// A transition path benchmarked across prove / verify / accumulator-fold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionPath {
    /// Genesis base case: no certificate, trivial accumulator passthrough.
    Genesis,
    /// Same-epoch step: certificate extends the current epoch.
    SameEpoch,
    /// Next-epoch step: certificate starts a new epoch.
    NextEpoch,
}

/// Everything one path needs across the measured operations, built untimed and validated once.
pub struct PreparedStep {
    path: TransitionPath,
    // Recursive prove inputs (item 5): `create_proof` over prebuilt circuit data.
    circuit_data: IvcCircuitData,
    public_inputs: Vec<CircuitBase>,
    // Verification inputs (item 6): the committed step proof.
    proof_bytes: IvcProofBytes,
    proof_state: State,
    proof_accumulator: Accumulator<BlstrsEmulation>,
    message: Vec<u8>,
    // Accumulator-fold inputs (item 7): two already-collapsed accumulators + the rolling one.
    // `None` for genesis (passthrough — no certificate or previous-IVC accumulator).
    fold: Option<FoldInputs>,
}

/// Pre-collapsed accumulators for the fold measurement (folding only, no proof verification).
struct FoldInputs {
    rolling_accumulator: Accumulator<BlstrsEmulation>,
    certificate_collapsed_accumulator: Accumulator<BlstrsEmulation>,
    previous_ivc_proof_collapsed_accumulator: Accumulator<BlstrsEmulation>,
}

impl PreparedStep {
    /// Returns the transition path this fixture represents.
    pub fn path(&self) -> TransitionPath {
        self.path
    }

    /// Byte length of the committed step proof used for verification.
    pub fn proof_size(&self) -> usize {
        self.proof_bytes.as_bytes().len()
    }
}

/// Deterministic certificate parameters used to derive the recursive setup.
fn benchmark_parameters() -> Parameters {
    Parameters {
        k: QUORUM_SIZE,
        m: NUMBER_OF_LOTTERIES,
        phi_f: PHI_F,
    }
}

/// Merkle-tree depth for the committed signer set.
fn merkle_tree_depth() -> u32 {
    SIGNER_COUNT.next_power_of_two().trailing_zeros()
}

/// Builds the unsafe-SRS trusted-setup provider rooted at `cache_dir`.
///
/// `with_unsafe_srs` generates and stores the SRS on construction (there is no generate-on-miss
/// path), so constructing this provider is the SRS-generation cost.
fn trusted_setup_provider(cache_dir: &Path) -> TrustedSetupProvider {
    TrustedSetupProvider::with_unsafe_srs(cache_dir, RECURSIVE_CIRCUIT_DEGREE + 1)
}

/// Builds the recursive key provider (wrapping the certificate key provider) rooted at `cache_dir`.
fn recursive_key_provider(
    cache_dir: &Path,
) -> StmResult<KeyProvider<RecursiveCircuitKeyGenerator>> {
    let certificate_provider = KeyProvider::new(
        cache_dir.join("certificate"),
        "non-recursive",
        &[],
        StmCertificateCircuit::try_new(&benchmark_parameters(), merkle_tree_depth())?,
    );
    Ok(KeyProvider::new(
        cache_dir.join("recursive"),
        "recursive",
        &[],
        RecursiveCircuitKeyGenerator::new(certificate_provider),
    ))
}

impl IvcBenchEnv {
    /// Builds the shared benchmark environment: the full IVC setup (SRS + verifying/proving keys +
    /// fixed bases), the verifier setup derived from the same unsafe SRS, and the `Global` built
    /// from the committed genesis fixture. Rooted at `cache_dir` (a caller-managed directory).
    pub fn new(cache_dir: &Path) -> StmResult<Self> {
        let setup = IvcSnarkProverSetup::load(
            &trusted_setup_provider(cache_dir),
            &recursive_key_provider(cache_dir)?,
        )?;
        let verifier_setup = IvcVerifierSetup::from_ivc_setup_with_srs(&setup);

        let genesis_fixture = load_embedded_genesis_benchmark_fixture()?;
        let global = Global::new(
            genesis_fixture.genesis_message_hash(),
            genesis_fixture.genesis_verification_key,
            &setup.certificate_verifying_key,
            &setup.ivc_verifying_key,
        );

        Ok(Self {
            setup,
            verifier_setup,
            global,
        })
    }

    /// Prepares the fixture for `path` (item 4). Untimed; the resulting proof is validated once.
    pub fn prepare_step(&self, path: TransitionPath) -> StmResult<PreparedStep> {
        let prepared = match path {
            TransitionPath::Genesis => self.prepare_genesis_step()?,
            TransitionPath::SameEpoch => self.prepare_certificate_step(path)?,
            TransitionPath::NextEpoch => self.prepare_certificate_step(path)?,
        };
        // Validate once, outside any timed loop: the committed step proof must verify.
        IvcProof::<Blake2b256>::new(
            prepared.proof_bytes.clone(),
            prepared.proof_state.clone(),
            prepared.proof_accumulator.clone(),
        )
        .verify(&prepared.message, &self.global, &self.verifier_setup)?;
        Ok(prepared)
    }

    /// Builds the genesis base-case fixture from the additive genesis fixture and the committed
    /// genesis step output (used for verification).
    fn prepare_genesis_step(&self) -> StmResult<PreparedStep> {
        let genesis_fixture = load_embedded_genesis_benchmark_fixture()?;
        let genesis_output = load_embedded_genesis_step_output_asset()?;
        let preimage = ProtocolMessagePreimage(genesis_fixture.genesis_protocol_message_preimage);

        let combined_fixed_base_names: Vec<String> =
            self.setup.combined_fixed_bases.keys().cloned().collect();
        let rolling_state = IvcRollingState::genesis(
            genesis_fixture.genesis_signature,
            &combined_fixed_base_names,
        );
        let prover_input =
            IvcProverInput::prepare_genesis(&rolling_state, &preimage, &self.global)?;

        let circuit_data = IvcCircuitData::try_new(
            self.global.clone(),
            rolling_state.state().clone(),
            prover_input.witness,
            CertificateProofBytes::empty(),
            rolling_state.ivc_proof().clone(),
            rolling_state.accumulator().clone(),
            &self.setup.certificate_verifying_key,
            &self.setup.ivc_verifying_key,
        )?;
        let public_inputs =
            self.public_inputs_for(&prover_input.next_state, &prover_input.next_accumulator);

        // Untimed equivalence: the freshly prepared proving relation must be the same transition
        // as the committed genesis step output that verification measures.
        ensure!(
            prover_input.next_state == genesis_output.next_state,
            "prepared genesis next_state does not match the committed genesis step output"
        );
        ensure!(
            AssignedAccumulator::as_public_input(&prover_input.next_accumulator)
                == AssignedAccumulator::as_public_input(&genesis_output.next_accumulator),
            "prepared genesis next_accumulator does not match the committed genesis step output"
        );

        Ok(PreparedStep {
            path: TransitionPath::Genesis,
            circuit_data,
            public_inputs,
            proof_bytes: genesis_output.ivc_proof,
            proof_state: genesis_output.next_state,
            proof_accumulator: genesis_output.next_accumulator,
            message: genesis_fixture.genesis_message.to_vec(),
            fold: None,
        })
    }

    /// Builds a same-epoch or next-epoch fixture from the committed recursive chain state and the
    /// matching step output asset, mirroring the production `IvcProverInput::prepare` flow.
    fn prepare_certificate_step(&self, path: TransitionPath) -> StmResult<PreparedStep> {
        let chain_state = load_embedded_recursive_chain_state_asset()?;
        let (
            certificate_proof,
            next_state,
            next_accumulator,
            ivc_proof,
            message,
            message_preimage,
            avk_root,
        ) = match path {
            TransitionPath::SameEpoch => {
                let step = load_embedded_following_certificate_in_epoch_asset()?;
                (
                    step.certificate_proof,
                    step.next_state,
                    step.next_accumulator,
                    step.ivc_proof,
                    step.message,
                    step.message_preimage,
                    step.aggregate_verification_key_merkle_root,
                )
            }
            TransitionPath::NextEpoch => {
                let step = load_embedded_next_epoch_step_output_asset()?;
                (
                    step.certificate_proof,
                    step.next_state,
                    step.next_accumulator,
                    step.ivc_proof,
                    step.message,
                    step.message_preimage,
                    step.aggregate_verification_key_merkle_root,
                )
            }
            TransitionPath::Genesis => unreachable!("genesis handled by prepare_genesis_step"),
        };

        let snark_proof: SnarkProof<MithrilMembershipDigest> = SnarkProof::new(
            certificate_proof.clone().into_vec(),
            benchmark_parameters(),
            merkle_tree_depth(),
        );
        let aggregate_verification_key = aggregate_verification_key_for_root(&avk_root)?;
        let preimage = ProtocolMessagePreimage(message_preimage);
        let rolling_state = IvcRollingState::new(
            chain_state.state,
            chain_state.ivc_proof,
            chain_state.accumulator,
            chain_state.genesis_signature,
        );

        let prover_input = IvcProverInput::prepare(
            &snark_proof,
            &message,
            &aggregate_verification_key,
            &self.global,
            &preimage,
            &rolling_state,
            &self.setup,
        )?;

        let circuit_data = IvcCircuitData::try_new(
            self.global.clone(),
            rolling_state.state().clone(),
            prover_input.witness,
            certificate_proof,
            rolling_state.ivc_proof().clone(),
            rolling_state.accumulator().clone(),
            &self.setup.certificate_verifying_key,
            &self.setup.ivc_verifying_key,
        )?;
        let public_inputs =
            self.public_inputs_for(&prover_input.next_state, &prover_input.next_accumulator);

        // Fold inputs: the two source accumulators, collapsed, plus the rolling accumulator.
        let certificate_dual_msm = snark_proof.prepare_and_check(
            &message,
            &aggregate_verification_key,
            &self.setup.certificate_verifying_key,
            &self.setup.srs.verifier_params(),
        )?;
        let certificate_collapsed_accumulator =
            self.setup.certificate_collapsed_accumulator(certificate_dual_msm)?;
        let previous_ivc_proof_collapsed_accumulator =
            self.setup.previous_ivc_proof_collapsed_accumulator(
                rolling_state.ivc_proof().as_bytes(),
                &rolling_state.previous_ivc_proof_public_inputs(&self.global),
            )?;
        let fold_inputs = FoldInputs {
            rolling_accumulator: rolling_state.accumulator().clone(),
            certificate_collapsed_accumulator,
            previous_ivc_proof_collapsed_accumulator,
        };

        // Untimed equivalence checks. The freshly prepared proving relation must be the same
        // transition as the committed step output that verification measures, and folding the
        // reconstructed accumulator inputs must reproduce the production-prepared accumulator —
        // otherwise the façade would benchmark one transition while verifying/folding another.
        ensure!(
            prover_input.next_state == next_state,
            "prepared next_state does not match the committed step asset"
        );
        ensure!(
            AssignedAccumulator::as_public_input(&prover_input.next_accumulator)
                == AssignedAccumulator::as_public_input(&next_accumulator),
            "prepared next_accumulator does not match the committed step asset"
        );
        let mut reproduced_fold = Accumulator::accumulate(&[
            fold_inputs.rolling_accumulator.clone(),
            fold_inputs.certificate_collapsed_accumulator.clone(),
            fold_inputs.previous_ivc_proof_collapsed_accumulator.clone(),
        ]);
        reproduced_fold.collapse();
        ensure!(
            AssignedAccumulator::as_public_input(&reproduced_fold)
                == AssignedAccumulator::as_public_input(&prover_input.next_accumulator),
            "reconstructed accumulator fold does not match the production-prepared accumulator"
        );

        Ok(PreparedStep {
            path,
            circuit_data,
            public_inputs,
            proof_bytes: ivc_proof,
            proof_state: next_state,
            proof_accumulator: next_accumulator,
            message: message.to_vec(),
            fold: Some(fold_inputs),
        })
    }

    /// Concatenates the public inputs `[global | next_state | next_accumulator]`.
    fn public_inputs_for(
        &self,
        next_state: &State,
        next_accumulator: &Accumulator<BlstrsEmulation>,
    ) -> Vec<CircuitBase> {
        [
            self.global.as_public_input(),
            next_state.as_public_input(),
            AssignedAccumulator::as_public_input(next_accumulator),
        ]
        .concat()
    }

    /// Recursive prover with the Poseidon transcript (item 5): `create_proof` over prebuilt
    /// circuit data. Excludes the inner certificate prover and the preparation step.
    pub fn prove_poseidon(&self, prepared: &PreparedStep) -> StmResult<Vec<u8>> {
        IvcProof::<PoseidonState<CircuitBase>>::prove_with_transcript(
            &self.setup.srs,
            &self.setup.ivc_proving_key,
            &prepared.circuit_data,
            &prepared.public_inputs,
            &mut OsRng,
        )
    }

    /// Recursive prover with the Blake2b transcript (item 5).
    pub fn prove_blake2b(&self, prepared: &PreparedStep) -> StmResult<Vec<u8>> {
        IvcProof::<Blake2b256>::prove_with_transcript(
            &self.setup.srs,
            &self.setup.ivc_proving_key,
            &prepared.circuit_data,
            &prepared.public_inputs,
            &mut OsRng,
        )
    }

    /// Full recursive verification (item 6): KZG opening plus the folded-accumulator pairing check.
    pub fn verify_full(&self, prepared: &PreparedStep) -> StmResult<()> {
        IvcProof::<Blake2b256>::new(
            prepared.proof_bytes.clone(),
            prepared.proof_state.clone(),
            prepared.proof_accumulator.clone(),
        )
        .verify(&prepared.message, &self.global, &self.verifier_setup)
    }

    /// Recursive KZG-opening verification only (item 6). Bench-local replication of the opening
    /// half of `IvcProof::verify` (prepare + `dual_msm.check`), kept here to avoid a production
    /// refactor; the full-verification path above exercises the production code.
    pub fn verify_kzg_opening(&self, prepared: &PreparedStep) -> StmResult<()> {
        let public_inputs: Vec<CircuitBase> = [
            self.global.as_public_input(),
            prepared.proof_state.as_public_input(),
            AssignedAccumulator::as_public_input(&prepared.proof_accumulator),
        ]
        .concat();

        let mut transcript =
            CircuitTranscript::<Blake2b256>::init_from_bytes(prepared.proof_bytes.as_bytes());
        let dual_msm =
            prepare::<CircuitBase, KZGCommitmentScheme<Bls12>, CircuitTranscript<Blake2b256>>(
                self.verifier_setup.ivc_verifying_key().verifying_key(),
                &[&[G1Projective::identity()]],
                &[&[&public_inputs]],
                &mut transcript,
            )
            .map_err(|_| anyhow!("bench: recursive KZG opening transcript preparation failed"))?;
        transcript
            .assert_empty()
            .map_err(|_| anyhow!("bench: recursive KZG opening transcript not fully consumed"))?;
        if !dual_msm.check(self.verifier_setup.verifier_params()) {
            return Err(anyhow!("bench: recursive KZG opening check failed"));
        }
        Ok(())
    }

    /// Off-circuit accumulator fold (item 7): `accumulate` + `collapse` from the two already-
    /// collapsed source accumulators and the rolling accumulator. Returns `None` for genesis
    /// (passthrough — nothing to fold).
    pub fn fold_accumulators(
        &self,
        prepared: &PreparedStep,
    ) -> Option<Accumulator<BlstrsEmulation>> {
        let fold = prepared.fold.as_ref()?;
        let mut accumulator = Accumulator::accumulate(&[
            fold.rolling_accumulator.clone(),
            fold.certificate_collapsed_accumulator.clone(),
            fold.previous_ivc_proof_collapsed_accumulator.clone(),
        ]);
        accumulator.collapse();
        Some(accumulator)
    }

    // --- Setup cold/warm measurements (item 8) ---

    /// Generates and stores the unsafe SRS at `cache_dir` (cold, one-off). Reads it back so the
    /// returned value is the downsized proving SRS used by the keys measurements.
    pub fn measure_srs_generation(cache_dir: &Path) -> StmResult<ParamsKZG<Bls12>> {
        let mut srs = trusted_setup_provider(cache_dir).get_trusted_setup_parameters()?;
        srs.downsize(RECURSIVE_CIRCUIT_DEGREE);
        Ok(srs)
    }

    /// Derives (cold) or loads (warm) the recursive circuit keys from `cache_dir`, depending on
    /// whether the key cache is populated. The recursive provider wraps the certificate provider,
    /// so both key layers are covered.
    pub fn measure_keys(cache_dir: &Path, srs: &ParamsKZG<Bls12>) -> StmResult<()> {
        let _keys = recursive_key_provider(cache_dir)?.key_pair(srs)?;
        Ok(())
    }

    /// Full setup load (item 8): SRS + certificate/IVC keys + fixed bases.
    ///
    /// `with_unsafe_srs` regenerates and rewrites the SRS on every call, so **both** the empty-cache
    /// and populated-cache runs include unsafe SRS regeneration + serialization. The only difference
    /// is the circuit keys: derived (empty key cache) vs loaded (populated key cache). This is
    /// therefore `full_setup/cold_keys` vs `full_setup/cached_keys` — not a warm-SRS measurement.
    /// Slice 5 labels the two bench groups accordingly.
    pub fn measure_full_setup(cache_dir: &Path) -> StmResult<()> {
        let _setup = IvcSnarkProverSetup::load(
            &trusted_setup_provider(cache_dir),
            &recursive_key_provider(cache_dir)?,
        )?;
        Ok(())
    }
}

/// Shared benchmark environment delegating to the production IVC proof-system code.
pub struct IvcBenchEnv {
    setup: IvcSnarkProverSetup,
    verifier_setup: IvcVerifierSetup,
    global: Global,
}

/// Rebuilds the deterministic aggregate verification key from a committed 32-byte Merkle root and
/// the fixed total stake, matching the format the committed certificate proofs commit to.
fn aggregate_verification_key_for_root(
    aggregate_verification_key_merkle_root: &[u8; 32],
) -> StmResult<AggregateVerificationKeyForSnark<MithrilMembershipDigest>> {
    let mut avk_bytes = [0u8; 40];
    avk_bytes[0..32].copy_from_slice(aggregate_verification_key_merkle_root);
    avk_bytes[32..40].copy_from_slice(&TOTAL_STAKE.to_be_bytes());
    AggregateVerificationKeyForSnark::<MithrilMembershipDigest>::from_bytes(&avk_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Slow runtime smoke: builds the full IVC setup (recursive keygen) once and exercises every
    // façade operation on all three transition paths, confirming fixture assembly, proving,
    // verification, and folding all succeed. Opt-in — run with `--ignored`.
    #[test]
    #[ignore = "slow: builds the full IVC setup via recursive keygen"]
    fn facade_prepares_proves_and_verifies_all_paths() {
        let cache_dir = std::env::temp_dir().join("mithril_ivc_bench_facade_smoke");
        println!("[smoke] building IVC setup (recursive keygen); this dominates the runtime...");
        let env = IvcBenchEnv::new(&cache_dir).expect("bench env should build");
        println!("[smoke] setup ready");

        for path in [
            TransitionPath::Genesis,
            TransitionPath::SameEpoch,
            TransitionPath::NextEpoch,
        ] {
            println!("[smoke] {path:?}: preparing fixture (untimed equivalence checks)...");
            let prepared = env.prepare_step(path).expect("prepare should succeed");

            println!("[smoke] {path:?}: proving (Poseidon)...");
            let poseidon_bytes =
                env.prove_poseidon(&prepared).expect("poseidon prove should succeed");
            println!("[smoke] {path:?}: proving (Blake2b)...");
            let blake2b_bytes = env.prove_blake2b(&prepared).expect("blake2b prove should succeed");

            // Verify the freshly generated proofs against the prepared public inputs, each with its
            // matching transcript — not just the committed proof.
            println!("[smoke] {path:?}: verifying generated Poseidon proof...");
            IvcProof::<PoseidonState<CircuitBase>>::new(
                IvcProofBytes::new(poseidon_bytes),
                prepared.proof_state.clone(),
                prepared.proof_accumulator.clone(),
            )
            .verify(&prepared.message, &env.global, &env.verifier_setup)
            .expect("generated Poseidon proof should verify");
            println!("[smoke] {path:?}: verifying generated Blake2b proof...");
            IvcProof::<Blake2b256>::new(
                IvcProofBytes::new(blake2b_bytes),
                prepared.proof_state.clone(),
                prepared.proof_accumulator.clone(),
            )
            .verify(&prepared.message, &env.global, &env.verifier_setup)
            .expect("generated Blake2b proof should verify");

            println!("[smoke] {path:?}: verifying committed proof (full + KZG opening)...");
            env.verify_full(&prepared).expect("full verification should succeed");
            env.verify_kzg_opening(&prepared).expect("kzg opening should succeed");

            println!("[smoke] {path:?}: folding accumulators...");
            let folded = env.fold_accumulators(&prepared);
            match path {
                TransitionPath::Genesis => {
                    assert!(folded.is_none(), "genesis fold is a passthrough");
                }
                TransitionPath::SameEpoch | TransitionPath::NextEpoch => {
                    assert!(
                        folded.is_some(),
                        "non-genesis fold should produce an accumulator"
                    );
                }
            }
            println!("[smoke] {path:?}: done");
        }
        println!("[smoke] all paths passed");
    }
}
