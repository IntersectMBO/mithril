//! Load-once, deployment-constant artifacts shared by every step of an IVC proving session.

use std::collections::BTreeMap;

use midnight_circuits::verifier::{Accumulator, BlstrsEmulation};
use midnight_curves::{Bls12, G1Projective};
use midnight_proofs::poly::kzg::{msm::DualMSM, params::ParamsKZG};

#[cfg(test)]
use crate::circuits::{
    halo2::{
        NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION, circuit::StmCertificateCircuit,
    },
    halo2_ivc::RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
    test_utils::file_mutex::FileMutex,
    trusted_setup::UNSAFE_SRS_SEED,
};
use crate::{
    StmResult,
    circuits::{
        halo2::{keys::NonRecursiveCircuitVerifyingKey, types::CircuitBase},
        halo2_ivc::{
            CERTIFICATE_FIXED_BASES_PREFIX, IVC_FIXED_BASES_PREFIX, RECURSIVE_CIRCUIT_DEGREE,
            accumulator::{
                check_dual_msm_matches_fixed_bases, fixed_bases_and_names_from_verifying_key,
            },
            certificate_proof::verify_and_prepare_accumulator,
            keys::{
                RecursiveCircuitKeyGenerator, RecursiveCircuitProvingKey,
                RecursiveCircuitVerifyingKey,
            },
        },
        key_provider::KeyProvider,
        trusted_setup::TrustedSetupProvider,
    },
};

/// Load-once, deployment-constant artifacts shared by every step of an IVC proving session.
///
/// # Invariants
///
/// The three fixed-base maps are not independent. The constructor must enforce:
///
/// `combined_fixed_bases.keys() == certificate_fixed_bases.keys() ∪ ivc_fixed_bases.keys()`
///
/// and values must agree across the three maps for any shared key. The in-circuit IVC
/// verifier gadget builds a single merged fixed-base list from these names; any mismatch
/// here produces folded accumulators the circuit will reject.
pub(crate) struct IvcSnarkProverSetup {
    /// KZG parameters used during proof generation, downsized to `RECURSIVE_CIRCUIT_DEGREE`.
    ///
    /// `create_proof` commits in the Lagrange basis of the circuit domain, so the SRS must match
    /// that domain: a larger SRS carries a different basis and yields an unverifiable proof.
    /// Verifier params are derived on demand via `self.srs.verifier_params()`.
    pub(crate) srs: ParamsKZG<Bls12>,
    /// Verifying key of the certificate circuit.
    pub(crate) certificate_verifying_key: NonRecursiveCircuitVerifyingKey,
    /// Verifying key of the IVC circuit.
    pub(crate) ivc_verifying_key: RecursiveCircuitVerifyingKey,
    /// Proving key of the IVC circuit.
    pub(crate) ivc_proving_key: RecursiveCircuitProvingKey,
    /// Fixed-base map used to normalize the certificate accumulator.
    pub(crate) certificate_fixed_bases: BTreeMap<String, G1Projective>,
    /// Fixed-base map used to normalize the IVC proof accumulator.
    pub(crate) ivc_fixed_bases: BTreeMap<String, G1Projective>,
    /// Fixed-base map used when folding the certificate and IVC proof accumulators
    /// into the new IVC folded accumulator.
    pub(crate) combined_fixed_bases: BTreeMap<String, G1Projective>,
}

impl IvcSnarkProverSetup {
    /// Derives the full IVC setup around a single SRS loaded once.
    ///
    /// Loads the SRS and downsizes it in place to [`RECURSIVE_CIRCUIT_DEGREE`] (stored for
    /// `IvcProver::prove`'s `create_proof`). Derives the certificate verifying key through the
    /// recursive key provider's wrapped non-recursive provider (the recursive circuit recursively
    /// verifies certificate proofs), derives the IVC verifying/proving keys against the downsized SRS,
    /// and builds the three fixed-base maps from the two verifying keys.
    pub(crate) fn load(
        trusted_setup_provider: &TrustedSetupProvider,
        recursive_key_provider: &KeyProvider<RecursiveCircuitKeyGenerator>,
    ) -> StmResult<Self> {
        let mut srs = trusted_setup_provider.get_trusted_setup_parameters()?;
        srs.downsize(RECURSIVE_CIRCUIT_DEGREE);
        let certificate_verifying_key =
            recursive_key_provider.generator().certificate_verifying_key(&srs)?;
        let (ivc_verifying_key, ivc_proving_key) = recursive_key_provider.key_pair(&srs)?;

        let (certificate_fixed_bases, _) = fixed_bases_and_names_from_verifying_key(
            CERTIFICATE_FIXED_BASES_PREFIX,
            certificate_verifying_key.as_ref(),
        );
        let (ivc_fixed_bases, _) = fixed_bases_and_names_from_verifying_key(
            IVC_FIXED_BASES_PREFIX,
            ivc_verifying_key.as_ref(),
        );
        let mut combined_fixed_bases = certificate_fixed_bases.clone();
        combined_fixed_bases.extend(ivc_fixed_bases.clone());

        Ok(Self {
            srs,
            certificate_verifying_key,
            ivc_verifying_key,
            ivc_proving_key,
            certificate_fixed_bases,
            ivc_fixed_bases,
            combined_fixed_bases,
        })
    }

    /// Wrap the certificate proof's prepared `DualMSM` into a collapsed accumulator on
    /// the certificate circuit's fixed bases.
    pub(crate) fn certificate_collapsed_accumulator(
        &self,
        dual_msm: DualMSM<Bls12>,
    ) -> StmResult<Accumulator<BlstrsEmulation>> {
        check_dual_msm_matches_fixed_bases(
            &dual_msm,
            CERTIFICATE_FIXED_BASES_PREFIX,
            &self.certificate_fixed_bases,
        )?;
        let mut accumulator: Accumulator<BlstrsEmulation> = Accumulator::from_dual_msm(
            dual_msm,
            CERTIFICATE_FIXED_BASES_PREFIX,
            &self.certificate_fixed_bases,
        );
        accumulator.collapse();
        Ok(accumulator)
    }

    /// Off-circuit verify of the previous step's IVC proof, returning the collapsed
    /// accumulator the in-circuit IVC verifier gadget would have produced on the same
    /// proof. Used at every non-genesis step.
    pub(crate) fn previous_ivc_proof_collapsed_accumulator(
        &self,
        ivc_proof_bytes: &[u8],
        public_inputs: &[CircuitBase],
    ) -> StmResult<Accumulator<BlstrsEmulation>> {
        let verifier_params = self.srs.verifier_params();
        let dual_msm = verify_and_prepare_accumulator(
            ivc_proof_bytes,
            public_inputs,
            self.ivc_verifying_key.as_ref(),
            &verifier_params,
        )?;
        check_dual_msm_matches_fixed_bases(
            &dual_msm,
            IVC_FIXED_BASES_PREFIX,
            &self.ivc_fixed_bases,
        )?;
        let mut accumulator: Accumulator<BlstrsEmulation> =
            Accumulator::from_dual_msm(dual_msm, IVC_FIXED_BASES_PREFIX, &self.ivc_fixed_bases);
        accumulator.collapse();
        Ok(accumulator)
    }

    /// Builds an [`IvcSnarkProverSetup`] from a deterministic, oversized unsafe SRS, exercising the
    /// real `load` path without the production SRS. Shared by the slow IVC tests through a
    /// content-keyed cache keyed by the protocol parameters, Merkle-tree depth, the unsafe SRS seed,
    /// and the production verifying keys as a circuit-version salt — not the SRS degree, since `load`
    /// always downsizes to `RECURSIVE_CIRCUIT_DEGREE` before deriving keys, so any `unsafe_srs_degree`
    /// reproduces the same recursive keys — the dominant cost — letting calls at different degrees
    /// share one already-computed key cache instead of each paying for keygen separately.
    #[cfg(test)]
    pub(crate) fn build_for_test(
        parameters: &crate::Parameters,
        merkle_tree_depth: u32,
    ) -> StmResult<Self> {
        Self::build_for_test_with_unsafe_srs_degree(
            parameters,
            merkle_tree_depth,
            RECURSIVE_CIRCUIT_DEGREE,
        )
    }

    /// As [`Self::build_for_test`], but generates the unsafe SRS at `unsafe_srs_degree` instead of
    /// exactly [`RECURSIVE_CIRCUIT_DEGREE`].  This removes the need to downsize in [`Self::load`] if
    /// the input degree matches the circuit one.
    #[cfg(test)]
    pub(crate) fn build_for_test_with_unsafe_srs_degree(
        parameters: &crate::Parameters,
        merkle_tree_depth: u32,
        unsafe_srs_degree: u32,
    ) -> StmResult<Self> {
        let parameters_bytes = parameters.to_bytes()?;
        let depth_bytes = merkle_tree_depth.to_le_bytes();
        let seed_bytes = UNSAFE_SRS_SEED.to_le_bytes();

        // The unsafe SRS depends only on its degree and seed, never on the circuit parameters, so it
        // is cached independently of them and shared by every parameter set that needs the same degree
        // (`TrustedSetupProvider::with_unsafe_srs` itself nests its file by degree under this directory).
        let srs_cache = FileMutex::for_shared_cache("unsafe-srs", &[&seed_bytes]);
        let srs_directory = srs_cache.directory().to_path_buf();
        let _srs_cache_lock = srs_cache.lock()?;
        let trusted_setup_provider =
            TrustedSetupProvider::with_unsafe_srs(&srs_directory, unsafe_srs_degree);

        let key_cache = FileMutex::for_shared_cache(
            "ivc-setup",
            &[
                NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
                RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
                &parameters_bytes,
                &depth_bytes,
                &seed_bytes,
            ],
        );
        let cache_directory = key_cache.directory().to_path_buf();
        // Serialize cold-start keygen across the parallel slow-test processes.
        let _key_cache_lock = key_cache.lock()?;

        let certificate_provider = KeyProvider::new(
            cache_directory.join("certificate"),
            "non-recursive",
            &[],
            StmCertificateCircuit::try_new(parameters, merkle_tree_depth)?,
        );
        let recursive_key_provider = KeyProvider::new(
            cache_directory.join("recursive"),
            "recursive",
            &[],
            RecursiveCircuitKeyGenerator::new(certificate_provider),
        );
        Self::load(&trusted_setup_provider, &recursive_key_provider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Parameters;

    mod slow {
        use midnight_proofs::poly::commitment::Params;

        use super::*;
        use crate::circuits::halo2_ivc::tests::common::{
            asset_readers::load_embedded_verification_context_asset,
            generators::setup::{QUORUM_SIZE, SIGNER_COUNT},
        };

        // Runs the real `load` path against an oversized unsafe SRS; runs in the `slow` tier.
        #[test]
        fn load_succeeds_with_unsafe_srs() {
            let setup = IvcSnarkProverSetup::build_for_test(
                &Parameters {
                    k: 3,
                    m: 10,
                    phi_f: 0.2,
                },
                4,
            )
            .expect("IvcSnarkProverSetup::load should succeed");

            assert!(
                !setup.certificate_fixed_bases.is_empty(),
                "certificate fixed bases should be populated"
            );
            assert!(
                !setup.ivc_fixed_bases.is_empty(),
                "IVC fixed bases should be populated"
            );

            for (key, value) in &setup.certificate_fixed_bases {
                assert_eq!(
                    setup.combined_fixed_bases.get(key),
                    Some(value),
                    "combined map should preserve every certificate base"
                );
            }
            for (key, value) in &setup.ivc_fixed_bases {
                assert_eq!(
                    setup.combined_fixed_bases.get(key),
                    Some(value),
                    "combined map should preserve every IVC base"
                );
            }
        }

        // `IvcSnarkProverSetup::build_for_test` loads from an oversized unsafe SRS that shares the production
        // SRS's tau, so the keys and stored SRS must both downsize to `RECURSIVE_CIRCUIT_DEGREE` to
        // reproduce the embedded production assets exactly.
        #[test]
        fn ivc_setup_downsizes_keys_and_srs_to_the_circuit_degree() {
            let parameters = Parameters {
                k: QUORUM_SIZE as u64,
                m: (QUORUM_SIZE * 10) as u64,
                phi_f: 0.2,
            };
            let merkle_tree_depth = SIGNER_COUNT.next_power_of_two().trailing_zeros();
            let ivc_setup = IvcSnarkProverSetup::build_for_test_with_unsafe_srs_degree(
                &parameters,
                merkle_tree_depth,
                RECURSIVE_CIRCUIT_DEGREE + 1,
            )
            .expect("IvcSnarkProverSetup::load should succeed");

            let verification_context = load_embedded_verification_context_asset()
                .expect("verification context asset should load");

            assert_eq!(
                verification_context
                    .certificate_verifying_key
                    .midnight_vk()
                    .vk()
                    .transcript_repr(),
                ivc_setup
                    .certificate_verifying_key
                    .midnight_vk()
                    .vk()
                    .transcript_repr(),
                "cert VK must be independent of the SRS degree (downsized at keygen)"
            );
            assert_eq!(
                verification_context
                    .recursive_verifying_key
                    .verifying_key()
                    .transcript_repr(),
                ivc_setup.ivc_verifying_key.verifying_key().transcript_repr(),
                "IVC VK must be independent of the SRS degree (downsized at keygen)"
            );
            assert_eq!(
                ivc_setup.srs.max_k(),
                RECURSIVE_CIRCUIT_DEGREE,
                "the proving SRS stored in IvcSnarkProverSetup must be downsized to the IVC circuit degree"
            );
        }
    }
}
