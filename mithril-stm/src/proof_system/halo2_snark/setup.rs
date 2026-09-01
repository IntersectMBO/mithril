//! SNARK setup for the STM certificate circuit.
//!
//! Bundles circuit compilation and key derivation into [`SnarkProverSetup`], backed by the on-disk
//! [`KeyProvider`] so derived keys are reused across process restarts.
use anyhow::Context;
use midnight_curves::Bls12;
use midnight_proofs::{
    poly::kzg::params::{ParamsKZG, ParamsVerifierKZG},
    utils::SerdeFormat,
};
use midnight_zk_stdlib::MidnightCircuit;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::circuits::{
    halo2::NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
    halo2_ivc::RECURSIVE_CIRCUIT_DEGREE, test_utils::file_mutex::FileMutex,
    trusted_setup::UNSAFE_SRS_SEED,
};
use crate::{
    Parameters, StmResult,
    circuits::{
        halo2::{
            circuit::CertificateCircuit,
            keys::{NonRecursiveCircuitProvingKey, NonRecursiveCircuitVerifyingKey},
        },
        key_provider::KeyProvider,
        trusted_setup::TrustedSetupProvider,
    },
    proof_system::KZG_VERIFIER_PARAMS,
};

/// Bundles the one-time setup artifacts needed to prove and verify SNARK proofs.
///
/// This includes the Structured Reference String (SRS), the compiled circuit, and the
/// proving and verification keys derived from them.
pub struct SnarkProverSetup {
    /// KZG Structured Reference String.
    pub(crate) srs: ParamsKZG<Bls12>,
    /// Compiled STM circuit.
    pub(crate) circuit: CertificateCircuit,
    /// Verification key for the SNARK proof.
    pub(crate) verification_key: NonRecursiveCircuitVerifyingKey,
    /// Proving key for the SNARK proof.
    pub(crate) proving_key: NonRecursiveCircuitProvingKey,
}

impl SnarkProverSetup {
    /// Builds the production trusted setup provider and certificate key provider, then delegates to
    /// [`Self::load`].
    pub(crate) fn try_new(params: &Parameters, merkle_tree_depth: u32) -> StmResult<Self> {
        let trusted_setup_provider = TrustedSetupProvider::default();
        let provider = KeyProvider::for_non_recursive_circuit(params, merkle_tree_depth)?;
        Self::load(&trusted_setup_provider, &provider)
    }

    /// Derives the certificate setup from a trusted setup provider and a certificate key provider,
    /// mirroring `IvcSnarkProverSetup::load` on the recursive side.
    ///
    /// Loads the SRS from the trusted setup provider, takes the circuit from the key provider (single
    /// source), downsizes the SRS to that circuit's degree and stores it for proving, and reads or
    /// derives the key pair through the key provider.
    pub(crate) fn load(
        trusted_setup_provider: &TrustedSetupProvider,
        provider: &KeyProvider<CertificateCircuit>,
    ) -> StmResult<Self> {
        let mut srs = trusted_setup_provider.get_trusted_setup_parameters()?;
        let circuit = provider.generator().clone();
        let circuit_degree = MidnightCircuit::from_relation(&circuit, None).k();
        srs.downsize(circuit_degree);

        let (verification_key, proving_key) = provider.key_pair(&srs)?;

        Ok(Self {
            srs,
            circuit,
            verification_key,
            proving_key,
        })
    }

    /// Builds a [`SnarkProverSetup`] from a deterministic unsafe SRS with degree `RECURSIVE_CIRCUIT_DEGREE`
    /// using [`Self::build_for_test_degree`].
    #[cfg(test)]
    pub(crate) fn build_for_test(
        parameters: &Parameters,
        merkle_tree_depth: u32,
    ) -> StmResult<Self> {
        Self::build_for_test_degree(parameters, merkle_tree_depth, RECURSIVE_CIRCUIT_DEGREE)
    }

    /// Builds a [`SnarkProverSetup`] from a deterministic unsafe SRS with degree determined by the input
    /// `unsafe_srs_degree`.
    /// Uses a cache for the unsafe SRS to avoid regenerating it when a SRS of the correct degree already exists
    #[cfg(test)]
    pub(crate) fn build_for_test_degree(
        parameters: &crate::Parameters,
        merkle_tree_depth: u32,
        unsafe_srs_degree: u32,
    ) -> StmResult<Self> {
        let parameters_bytes = parameters.to_bytes()?;
        let depth_bytes = merkle_tree_depth.to_le_bytes();
        let seed_bytes = UNSAFE_SRS_SEED.to_le_bytes();
        let cache = FileMutex::for_shared_cache(
            "non-recursive",
            &[
                NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
                &parameters_bytes,
                &depth_bytes,
                &seed_bytes,
            ],
        );
        let cache_directory = cache.directory().to_path_buf();
        // Serialize cold-start keygen across the parallel slow-test processes.
        let _key_cache_lock = cache.lock()?;

        let trusted_setup_provider =
            TrustedSetupProvider::with_unsafe_srs(&cache_directory, unsafe_srs_degree);
        let circuit = CertificateCircuit::try_new(parameters, merkle_tree_depth)?;
        let provider = KeyProvider::new(cache_directory, "non-recursive", &[], circuit);
        Self::load(&trusted_setup_provider, &provider)
    }
}

/// Bundles the minimal setup artifacts needed to verify SNARK proofs.
pub(crate) struct SnarkVerifierSetup {
    /// KZG verifier parameters derived from `s_g2`.
    pub(crate) verifier_params: ParamsVerifierKZG<Bls12>,
}

impl SnarkVerifierSetup {
    /// Build the verifier setup from the embedded constant verifier params bytes.
    pub(crate) fn try_new() -> StmResult<Self> {
        let verifier_params = ParamsVerifierKZG::<Bls12>::read(
            &mut &KZG_VERIFIER_PARAMS[..],
            SerdeFormat::RawBytesUnchecked,
        )
        .with_context(|| "Failed to read embedded SNARK verifier params bytes")?;

        Ok(Self { verifier_params })
    }
}

/// Verifier data for the non-recursive SNARK: the certificate circuit verifying key, which is
/// fixed for a given circuit configuration and shared across the proofs it verifies.
///
/// The verifying key is the per-circuit newtype so its serialization preserves the circuit
/// architecture needed to deserialize it against the correct constraint system. Mirrors
/// `IvcVerifierData` on the recursive side.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnarkVerifierData {
    certificate_circuit_verification_key: NonRecursiveCircuitVerifyingKey,
}

impl SnarkVerifierData {
    /// Build the verifier data from the certificate circuit verifying key used to produce the proof.
    pub(crate) fn new(
        certificate_circuit_verification_key: NonRecursiveCircuitVerifyingKey,
    ) -> Self {
        Self {
            certificate_circuit_verification_key,
        }
    }

    /// Returns the certificate circuit verifying key stored in the SnarkVerifierData.
    pub(crate) fn certificate_circuit_verification_key(&self) -> &NonRecursiveCircuitVerifyingKey {
        &self.certificate_circuit_verification_key
    }
}

#[cfg(test)]
mod test {
    use std::fs;

    use midnight_proofs::utils::SerdeFormat;
    use midnight_zk_stdlib::MidnightCircuit;

    use crate::{
        Parameters,
        circuits::{
            halo2::circuit::CertificateCircuit, key_provider::KeyProvider,
            trusted_setup::TrustedSetupProvider,
        },
        codec::TryToBytes,
        proof_system::halo2_snark::SnarkProverSetup,
    };

    fn default_params() -> Parameters {
        Parameters {
            k: 3,
            m: 10,
            phi_f: 0.2,
        }
    }

    #[test]
    fn load_succeeds_with_valid_parameters() {
        let params = default_params();
        let circuit = CertificateCircuit::try_new(&params, 4).unwrap();
        let degree = MidnightCircuit::from_relation(&circuit, None).k();
        let base_dir = std::env::temp_dir().join(current_function!());
        fs::remove_dir_all(&base_dir).ok();
        let trusted_setup_provider = TrustedSetupProvider::with_unsafe_srs(&base_dir, degree);
        let provider = KeyProvider::new(base_dir.clone(), "non-recursive", b"test-vk", circuit);
        let result = SnarkProverSetup::load(&trusted_setup_provider, &provider);
        assert!(result.is_ok());
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn load_returns_same_verification_key_for_same_parameters() {
        let params = default_params();
        let circuit = CertificateCircuit::try_new(&params, 4).unwrap();
        let degree = MidnightCircuit::from_relation(&circuit, None).k();
        let base_dir = std::env::temp_dir().join(current_function!());
        fs::remove_dir_all(&base_dir).ok();
        let trusted_setup_provider = TrustedSetupProvider::with_unsafe_srs(&base_dir, degree);
        let provider = KeyProvider::new(base_dir.clone(), "non-recursive", b"test-vk", circuit);
        let setup1 = SnarkProverSetup::load(&trusted_setup_provider, &provider).unwrap();
        let setup2 = SnarkProverSetup::load(&trusted_setup_provider, &provider).unwrap();

        let vk_bytes1 = setup1.verification_key.to_bytes_vec().unwrap();
        let vk_bytes2 = setup2.verification_key.to_bytes_vec().unwrap();

        assert_eq!(
            vk_bytes1, vk_bytes2,
            "same parameters must produce the same verification key"
        );
        fs::remove_dir_all(&base_dir).ok();
    }

    mod verifier_setup {
        use super::*;
        use crate::circuits::trusted_setup::TrustedSetupProvider;
        use crate::proof_system::halo2_snark::SnarkVerifierSetup;

        #[test]
        #[ignore = "requires SRS download from the internet"]
        fn verifier_setup_matches_trusted_srs() {
            let setup = SnarkVerifierSetup::try_new().unwrap();
            let srs = TrustedSetupProvider::default()
                .get_trusted_setup_parameters()
                .unwrap();
            let expected = srs.verifier_params();
            let mut expected_bytes = vec![];
            expected
                .write(&mut expected_bytes, SerdeFormat::RawBytesUnchecked)
                .unwrap();
            let mut actual_bytes = vec![];
            setup
                .verifier_params
                .write(&mut actual_bytes, SerdeFormat::RawBytesUnchecked)
                .unwrap();
            assert_eq!(
                expected_bytes, actual_bytes,
                "verifier params must match the Midnight trusted SRS"
            );
        }
    }
}
