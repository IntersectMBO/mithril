//! A module used to validate the Certificate Chain created by an aggregator
//!
use anyhow::{Context, anyhow};
use async_trait::async_trait;
use hex::ToHex;
use slog::{Logger, debug};
use std::sync::Arc;
use thiserror::Error;

use mithril_stm::{AggregateSignatureType, AncillaryVerifierData};

use crate::StdResult;
#[cfg(feature = "future_snark")]
use crate::crypto_helper::{
    CircuitVerificationKeyCertifier, ProtocolAggregateVerificationKeyForSnark,
};
use crate::crypto_helper::{
    GenesisEd25519Error, GenesisVerifier, ProtocolAggregateVerificationKey,
    ProtocolAggregateVerificationKeyForConcatenation, ProtocolMultiSignature,
};
use crate::entities::{
    Certificate, CertificateSignature, ProtocolMessagePartKey, ProtocolParameters,
};
use crate::logging::LoggerExtensions;
#[cfg(feature = "future_snark")]
use mithril_stm::GenesisVerificationKeyBundle as StmGenesisVerificationKeyBundle;

use super::CertificateRetriever;

#[cfg(test)]
use mockall::automock;

/// [CertificateVerifier] related errors.
#[derive(Error, Debug)]
pub enum CertificateVerifierError {
    /// Error raised when the multi signatures verification fails.
    #[error("multi signature verification failed: '{0}'")]
    VerifyMultiSignature(String),

    /// Error raised when the Genesis Signature stored in a [Certificate] is invalid.
    #[error("certificate genesis error")]
    CertificateGenesis(#[from] GenesisEd25519Error),

    /// Error raised when the hash stored in a [Certificate] doesn't match a recomputed hash.
    #[error("certificate hash unmatch error")]
    CertificateHashUnmatch,

    /// Error raised when validating the certificate chain if a previous [Certificate] hash isn't
    /// equal to the current certificate `previous_hash`.
    #[error("certificate chain previous hash unmatch error")]
    CertificateChainPreviousHashUnmatch,

    /// Error raised when validating the certificate chain if the current [Certificate]
    /// `signed_message` doesn't match the hash of the `protocol_message` of the current certificate
    #[error("certificate protocol message unmatch error")]
    CertificateProtocolMessageUnmatch,

    /// Error raised when validating the certificate chain if the current [Certificate]
    /// `aggregate_verification_key` doesn't match the signed `next_aggregate_verification_key` of the previous certificate
    /// (if the certificates are on different epoch) or the `aggregate_verification_key` of the previous certificate
    /// (if the certificates are on the same epoch).
    #[error("certificate chain AVK unmatch error")]
    CertificateChainAVKUnmatch,

    /// Error raised when validating the certificate chain if the current [Certificate]
    /// `protocol_parameters` don't match the signed `next_protocol_parameters` of the previous certificate
    /// (if the certificates are on different epoch) or the `protocol_parameters` of the previous certificate
    /// (if the certificates are on the same epoch).
    #[error("certificate chain protocol parameters unmatch error")]
    CertificateChainProtocolParametersUnmatch,

    /// Error raised when validating the certificate chain if the current [Certificate]
    /// `epoch` doesn't match the signed `current_epoch` of the current certificate
    #[error("certificate epoch unmatch error")]
    CertificateEpochUnmatch,

    /// Error raised when validating the certificate chain if the current [Certificate]
    /// `epoch` is neither equal to the previous certificate `epoch` nor to the previous certificate `epoch - 1`
    #[error("certificate chain missing epoch error")]
    CertificateChainMissingEpoch,

    /// Error raised when validating the certificate chain if the chain loops.
    #[error("certificate chain infinite loop error")]
    CertificateChainInfiniteLoop,

    /// Error raised when [CertificateVerifier::verify_genesis_certificate] was called with a
    /// certificate that's not a genesis certificate.
    #[error("can't validate genesis certificate: given certificate isn't a genesis certificate")]
    InvalidGenesisCertificateProvided,

    /// Error raised when [CertificateVerifier::verify_standard_certificate] was called with a
    /// certificate that's not a standard certificate.
    #[error("can't validate standard certificate: given certificate isn't a standard certificate")]
    InvalidStandardCertificateProvided,

    /// Error raised when a certificate whose aggregate signature type requires certified circuit
    /// verification keys carries no ancillary verifier data.
    #[cfg(feature = "future_snark")]
    #[error(
        "certificate is missing the ancillary verifier data carrying its circuit verification keys"
    )]
    MissingAncillaryVerifierData,

    /// Error raised when a certificate requires certified circuit verification keys while no
    /// circuit verification key certifier is configured.
    #[cfg(feature = "future_snark")]
    #[error(
        "no circuit verification key certifier is configured while the certificate requires certified circuit verification keys"
    )]
    MissingCircuitVerificationKeyCertifier,
}

/// CertificateVerifier is the cryptographic engine in charge of verifying multi signatures and
/// [certificates](Certificate)
#[cfg_attr(test, automock)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait CertificateVerifier: Send + Sync {
    /// Verify Genesis certificate
    async fn verify_genesis_certificate(&self, genesis_certificate: &Certificate) -> StdResult<()>;

    /// Verify Standard certificate
    async fn verify_standard_certificate(
        &self,
        certificate: &Certificate,
        previous_certificate: &Certificate,
    ) -> StdResult<()>;

    /// Verify if a Certificate is valid and returns the previous Certificate in the chain if exists
    async fn verify_certificate(&self, certificate: &Certificate)
    -> StdResult<Option<Certificate>>;

    /// Verify that the Certificate Chain associated to a Certificate is valid
    async fn verify_certificate_chain(&self, certificate: Certificate) -> StdResult<()> {
        let mut certificate = certificate;
        while let Some(previous_certificate) = self.verify_certificate(&certificate).await? {
            certificate = previous_certificate;
        }

        Ok(())
    }
}

/// MithrilCertificateVerifier is an implementation of the CertificateVerifier
pub struct MithrilCertificateVerifier {
    logger: Logger,
    certificate_retriever: Arc<dyn CertificateRetriever>,
    genesis_verifier: Arc<GenesisVerifier>,
    #[cfg(feature = "future_snark")]
    circuit_verification_key_certifier: Option<Arc<dyn CircuitVerificationKeyCertifier>>,
}

impl MithrilCertificateVerifier {
    /// MithrilCertificateVerifier factory
    ///
    /// The circuit verification key certifier enforces the circuit verification key registry on
    /// the certificates whose aggregate signature type requires it.
    pub fn new(
        logger: Logger,
        certificate_retriever: Arc<dyn CertificateRetriever>,
        genesis_verifier: Arc<GenesisVerifier>,
        #[cfg(feature = "future_snark")] circuit_verification_key_certifier: Option<
            Arc<dyn CircuitVerificationKeyCertifier>,
        >,
    ) -> Self {
        debug!(logger, "New MithrilCertificateVerifier created");
        Self {
            logger: logger.new_with_component_name::<Self>(),
            certificate_retriever,
            genesis_verifier,
            #[cfg(feature = "future_snark")]
            circuit_verification_key_certifier,
        }
    }

    async fn fetch_previous_certificate(
        &self,
        certificate: &Certificate,
    ) -> StdResult<Certificate> {
        self.certificate_retriever
            .get_certificate_details(&certificate.previous_hash)
            .await
            .with_context(|| "Can not retrieve previous certificate during verification")
    }

    fn verify_multi_signature(
        &self,
        message: &[u8],
        multi_signature: &ProtocolMultiSignature,
        aggregate_verification_key: &ProtocolAggregateVerificationKey,
        protocol_parameters: &ProtocolParameters,
        ancillary_verifier_data: Option<AncillaryVerifierData>,
    ) -> Result<(), CertificateVerifierError> {
        debug!(
            self.logger,
            "Verify multi signature for {:?}",
            message.encode_hex::<String>()
        );

        #[cfg(not(feature = "future_snark"))]
        let genesis_verification_key_bundle = None;
        #[cfg(feature = "future_snark")]
        let genesis_verification_key_bundle = self
            .genesis_verifier
            .to_schnorr_verification_key()
            .map(StmGenesisVerificationKeyBundle::new);

        multi_signature
            .verify(
                message,
                aggregate_verification_key,
                &protocol_parameters.to_owned().into(),
                ancillary_verifier_data,
                genesis_verification_key_bundle,
            )
            .map_err(|e| CertificateVerifierError::VerifyMultiSignature(e.to_string()))
    }

    /// Verify that the circuit verification keys carried by the certificate are certified by the
    /// genesis-signed registry, for the aggregate signature types that require it.
    ///
    /// The digests are taken from the ancillary verifier data the aggregate signature is verified
    /// against, so certifying them certifies the circuits used to produce the signature.
    #[cfg(feature = "future_snark")]
    async fn verify_certified_circuit_verification_keys(
        &self,
        certificate: &Certificate,
    ) -> StdResult<()> {
        let requires_certification = certificate.signature.aggregate_signature_type().is_some_and(
            |aggregate_signature_type| {
                aggregate_signature_type.requires_certified_circuit_verification_keys()
            },
        );
        if !requires_certification {
            return Ok(());
        }

        let circuit_verification_key_certifier =
            self.circuit_verification_key_certifier
                .as_ref()
                .ok_or(CertificateVerifierError::MissingCircuitVerificationKeyCertifier)?;
        let ancillary_verifier_data = certificate
            .ancillary_verifier_data
            .as_ref()
            .ok_or(CertificateVerifierError::MissingAncillaryVerifierData)?;
        let digests = ancillary_verifier_data.circuit_verification_key_digests()?;

        circuit_verification_key_certifier
            .check(&digests, certificate.epoch)
            .await
            .with_context(|| {
                format!(
                    "Certificate verifier failed certifying the circuit verification keys of certificate '{}'",
                    certificate.hash
                )
            })
    }

    /// Verify the parts of a standard certificate that do not depend on its predecessor: its hash,
    /// signed message, multi-signature and epoch.
    fn verify_standard_certificate_integrity(&self, certificate: &Certificate) -> StdResult<()> {
        let multi_signature = match &certificate.signature {
            CertificateSignature::MultiSignature(_, signature) => Ok(signature),
            _ => Err(CertificateVerifierError::InvalidStandardCertificateProvided),
        }?;
        self.verify_is_not_in_infinite_loop(certificate)?;
        self.verify_hash_matches_content(certificate)?;
        self.verify_signed_message_matches_hashed_protocol_message(certificate)?;
        self.verify_multi_signature(
            certificate.signed_message.as_bytes(),
            multi_signature,
            &certificate.create_aggregate_verification_key(),
            &certificate.metadata.protocol_parameters,
            certificate
                .ancillary_verifier_data
                .clone()
                .map(|ancillary_verifier_data| ancillary_verifier_data.into_inner()),
        )?;
        self.verify_epoch_matches_protocol_message(certificate)?;

        Ok(())
    }

    fn verify_is_not_in_infinite_loop(&self, certificate: &Certificate) -> StdResult<()> {
        if certificate.is_chaining_to_itself() {
            return Err(anyhow!(
                CertificateVerifierError::CertificateChainInfiniteLoop
            ));
        }

        Ok(())
    }

    fn verify_hash_matches_content(&self, certificate: &Certificate) -> StdResult<()> {
        if certificate.try_compute_hash()? != certificate.hash {
            return Err(anyhow!(CertificateVerifierError::CertificateHashUnmatch));
        }

        Ok(())
    }

    fn verify_previous_hash_matches_previous_certificate_hash(
        &self,
        certificate: &Certificate,
        previous_certificate: &Certificate,
    ) -> StdResult<()> {
        if previous_certificate.hash != certificate.previous_hash {
            return Err(anyhow!(
                CertificateVerifierError::CertificateChainPreviousHashUnmatch
            ));
        }

        Ok(())
    }

    fn verify_signed_message_matches_hashed_protocol_message(
        &self,
        certificate: &Certificate,
    ) -> StdResult<()> {
        if certificate.protocol_message.compute_hash() != certificate.signed_message {
            return Err(anyhow!(
                CertificateVerifierError::CertificateProtocolMessageUnmatch
            ));
        }

        Ok(())
    }

    fn verify_epoch_matches_protocol_message(&self, certificate: &Certificate) -> StdResult<()> {
        if let Some(signed_epoch) = &certificate
            .protocol_message
            .get_message_part(&ProtocolMessagePartKey::CurrentEpoch)
            && **signed_epoch == certificate.epoch.to_string()
        {
            return Ok(());
        }

        Err(anyhow!(CertificateVerifierError::CertificateEpochUnmatch))
    }

    fn verify_epoch_chaining(
        &self,
        certificate: &Certificate,
        previous_certificate: &Certificate,
    ) -> StdResult<()> {
        if certificate.epoch.has_gap_with(&previous_certificate.epoch) {
            return Err(anyhow!(
                CertificateVerifierError::CertificateChainMissingEpoch
            ));
        }

        Ok(())
    }

    fn verify_aggregate_verification_key_chaining(
        &self,
        certificate: &Certificate,
        previous_certificate: &Certificate,
    ) -> StdResult<()> {
        let aggregate_signature_type = certificate
            .signature
            .aggregate_signature_type()
            .ok_or(CertificateVerifierError::InvalidStandardCertificateProvided)?;

        match aggregate_signature_type {
            AggregateSignatureType::Concatenation => self
                .verify_concatenation_aggregate_verification_key_chaining(
                    certificate,
                    previous_certificate,
                ),
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::Snark => self.verify_snark_aggregate_verification_key_chaining(
                certificate,
                previous_certificate,
            ),
            #[cfg(feature = "future_snark")]
            AggregateSignatureType::IvcSnark => self
                .verify_snark_aggregate_verification_key_chaining(
                    certificate,
                    previous_certificate,
                ),
        }
    }

    fn verify_concatenation_aggregate_verification_key_chaining(
        &self,
        certificate: &Certificate,
        previous_certificate: &Certificate,
    ) -> StdResult<()> {
        let previous_certificate_has_same_epoch = previous_certificate.epoch == certificate.epoch;
        let certificate_has_valid_aggregate_verification_key =
            if previous_certificate_has_same_epoch {
                previous_certificate.aggregate_verification_key
                    == certificate.aggregate_verification_key
            } else {
                previous_certificate
                    .protocol_message
                    .get_message_part(&ProtocolMessagePartKey::NextAggregateVerificationKey)
                    .and_then(|encoded_next_avk| {
                        ProtocolAggregateVerificationKeyForConcatenation::try_from(
                            encoded_next_avk.as_str(),
                        )
                        .ok()
                    })
                    .is_some_and(|decoded_next_avk| {
                        decoded_next_avk == certificate.aggregate_verification_key
                    })
            };
        if !certificate_has_valid_aggregate_verification_key {
            debug!(
                self.logger,
                "Previous certificate {:#?}", previous_certificate
            );
            return Err(anyhow!(
                CertificateVerifierError::CertificateChainAVKUnmatch
            ));
        }

        Ok(())
    }

    #[cfg(feature = "future_snark")]
    fn verify_snark_aggregate_verification_key_chaining(
        &self,
        certificate: &Certificate,
        previous_certificate: &Certificate,
    ) -> StdResult<()> {
        let previous_certificate_has_same_epoch = previous_certificate.epoch == certificate.epoch;
        let certificate_has_valid_snark_avk = if previous_certificate_has_same_epoch {
            match (
                &certificate.aggregate_verification_key_snark,
                &previous_certificate.aggregate_verification_key_snark,
            ) {
                (Some(current), Some(previous)) => current == previous,
                _ => false,
            }
        } else {
            previous_certificate
                .protocol_message
                .get_message_part(&ProtocolMessagePartKey::NextSnarkAggregateVerificationKey)
                .and_then(|encoded_next_snark_avk| {
                    ProtocolAggregateVerificationKeyForSnark::try_from(
                        encoded_next_snark_avk.as_str(),
                    )
                    .ok()
                })
                .is_some_and(|decoded_next_snark_avk| {
                    certificate.aggregate_verification_key_snark.as_ref().is_some_and(
                        |current_snark_avk| *current_snark_avk == decoded_next_snark_avk,
                    )
                })
        };
        if !certificate_has_valid_snark_avk {
            debug!(
                self.logger,
                "Previous certificate {:#?}", previous_certificate
            );
            return Err(anyhow!(
                CertificateVerifierError::CertificateChainAVKUnmatch
            ));
        }

        Ok(())
    }

    fn verify_protocol_parameters_chaining(
        &self,
        certificate: &Certificate,
        previous_certificate: &Certificate,
    ) -> StdResult<()> {
        let previous_certificate_has_same_epoch = previous_certificate.epoch == certificate.epoch;
        let certificate_has_valid_protocol_parameters = if previous_certificate_has_same_epoch {
            previous_certificate.metadata.protocol_parameters
                == certificate.metadata.protocol_parameters
        } else {
            match &previous_certificate
                .protocol_message
                .get_message_part(&ProtocolMessagePartKey::NextProtocolParameters)
            {
                Some(previous_certificate_next_protocol_parameters) => {
                    **previous_certificate_next_protocol_parameters
                        == certificate.metadata.protocol_parameters.compute_hash()
                }
                None => false,
            }
        };
        if !certificate_has_valid_protocol_parameters {
            debug!(
                self.logger,
                "Previous certificate {:#?}", previous_certificate
            );
            return Err(anyhow!(
                CertificateVerifierError::CertificateChainProtocolParametersUnmatch
            ));
        }

        Ok(())
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CertificateVerifier for MithrilCertificateVerifier {
    async fn verify_genesis_certificate(&self, genesis_certificate: &Certificate) -> StdResult<()> {
        let genesis_signature = match &genesis_certificate.signature {
            CertificateSignature::GenesisSignature(signature) => Ok(signature),
            // The Schnorr half is intentionally not verified here as it is needed for IVC SNARK only
            #[cfg(feature = "future_snark")]
            CertificateSignature::GenesisDualSignature(signature, _) => Ok(signature),
            CertificateSignature::MultiSignature(_, _) => {
                Err(CertificateVerifierError::InvalidGenesisCertificateProvided)
            }
        }?;
        self.verify_hash_matches_content(genesis_certificate)?;
        self.verify_signed_message_matches_hashed_protocol_message(genesis_certificate)?;
        self.genesis_verifier
            .to_ed25519_verification_key()
            .verify(
                genesis_certificate.signed_message.as_bytes(),
                genesis_signature,
            )
            .with_context(|| "Certificate verifier failed verifying a genesis certificate")?;
        self.verify_epoch_matches_protocol_message(genesis_certificate)?;

        Ok(())
    }

    async fn verify_standard_certificate(
        &self,
        certificate: &Certificate,
        previous_certificate: &Certificate,
    ) -> StdResult<()> {
        #[cfg(feature = "future_snark")]
        self.verify_certified_circuit_verification_keys(certificate).await?;
        self.verify_standard_certificate_integrity(certificate)?;
        self.verify_epoch_chaining(certificate, previous_certificate)?;
        self.verify_previous_hash_matches_previous_certificate_hash(
            certificate,
            previous_certificate,
        )?;
        self.verify_aggregate_verification_key_chaining(certificate, previous_certificate)?;
        self.verify_protocol_parameters_chaining(certificate, previous_certificate)?;

        Ok(())
    }

    /// Verify a certificate
    async fn verify_certificate(
        &self,
        certificate: &Certificate,
    ) -> StdResult<Option<Certificate>> {
        debug!(
            self.logger, "Verifying certificate";
            "certificate_hash" => &certificate.hash,
            "certificate_previous_hash" => &certificate.previous_hash,
            "certificate_epoch" => ?certificate.epoch,
            "certificate_signed_entity_type" => ?certificate.signed_entity_type(),
        );

        if certificate.is_genesis() {
            self.verify_genesis_certificate(certificate).await?;

            return Ok(None);
        }

        // Stopping here is sound only because such a signature's verification attests to the whole
        // certificate chain back to the genesis certificate, so the integrity checks alone suffice.
        if certificate.signature.aggregate_signature_type().is_some_and(
            |aggregate_signature_type| aggregate_signature_type.certifies_full_certificate_chain(),
        ) {
            #[cfg(feature = "future_snark")]
            self.verify_certified_circuit_verification_keys(certificate).await?;
            self.verify_standard_certificate_integrity(certificate)?;

            return Ok(None);
        }

        let previous_certificate = self.fetch_previous_certificate(certificate).await?;
        self.verify_standard_certificate(certificate, &previous_certificate)
            .await?;

        Ok(Some(previous_certificate))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use tokio::sync::Mutex;

    use mithril_stm::{AggregateSignatureType, AncillaryProofInput};

    use crate::test::{
        TestLogger,
        builder::{CertificateChainBuilder, CertificateChainBuilderContext, MithrilFixtureBuilder},
        crypto_helper::{setup_certificate_chain, setup_message, setup_protocol_parameters},
        double::{Dummy, FakeCertificaterRetriever},
    };
    use crate::{
        certificate_chain::certificate_retriever::MockCertificateRetriever,
        crypto_helper::ProtocolClerk,
    };

    use super::*;

    #[cfg(feature = "future_snark")]
    use crate::crypto_helper::GenesisSchnorrSigner;
    #[cfg(feature = "future_snark")]
    use rand_chacha::ChaCha20Rng;
    #[cfg(feature = "future_snark")]
    use rand_core::SeedableRng;

    macro_rules! assert_error_matches {
        ( $expected_error:path, $error:expr ) => {{
            let error = $error
                .downcast_ref::<CertificateVerifierError>()
                .expect("Can not downcast to `CertificateVerifierError`.");
            let expected_error = $expected_error;

            assert!(
                matches!(error, $expected_error),
                "unexpected error type: got {error:?}, want {expected_error:?}"
            );
        }};
    }

    struct MockDependencyInjector {
        mock_certificate_retriever: MockCertificateRetriever,
    }

    impl MockDependencyInjector {
        fn new() -> MockDependencyInjector {
            MockDependencyInjector {
                mock_certificate_retriever: MockCertificateRetriever::new(),
            }
        }

        fn build_certificate_verifier(
            self,
            genesis_verifier: Arc<GenesisVerifier>,
        ) -> MithrilCertificateVerifier {
            MithrilCertificateVerifier::new(
                TestLogger::stdout(),
                Arc::new(self.mock_certificate_retriever),
                genesis_verifier,
                #[cfg(feature = "future_snark")]
                None,
            )
        }
    }

    #[cfg(feature = "future_snark")]
    fn fake_genesis_verifier() -> Arc<GenesisVerifier> {
        Arc::new(setup_certificate_chain(1, 1).genesis_verifier)
    }

    #[test]
    fn verify_multi_signature_success() {
        let protocol_parameters = setup_protocol_parameters();
        let fixture = MithrilFixtureBuilder::default()
            .with_signers(5)
            .with_protocol_parameters(protocol_parameters.into())
            .build();
        let signers = fixture.signers_fixture();
        let message_hash = setup_message().compute_hash().as_bytes().to_vec();

        let single_signatures = signers
            .iter()
            .filter_map(|s| s.protocol_signer.sign(&message_hash))
            .collect::<Vec<_>>();

        let first_signer = &signers[0].protocol_signer;
        let clerk = ProtocolClerk::new_clerk_from_signer(first_signer);
        let aggregate_verification_key = clerk.compute_aggregate_verification_key();
        let (aggregate_signature, ancillary_proof_output) = clerk
            .aggregate_signatures_with_type(
                &single_signatures,
                &message_hash,
                AggregateSignatureType::default(),
                AncillaryProofInput::dummy(),
            )
            .unwrap();
        let ancillary_verifier_data = ancillary_proof_output.verifier_data().cloned();
        let multi_signature = aggregate_signature.into();
        let genesis_verifier = setup_certificate_chain(1, 1).genesis_verifier;

        let verifier = MithrilCertificateVerifier::new(
            TestLogger::stdout(),
            Arc::new(MockCertificateRetriever::new()),
            Arc::new(genesis_verifier),
            #[cfg(feature = "future_snark")]
            None,
        );
        let message_tampered = message_hash[1..].to_vec();
        assert!(
            verifier
                .verify_multi_signature(
                    &message_tampered,
                    &multi_signature,
                    &aggregate_verification_key,
                    &fixture.protocol_parameters(),
                    ancillary_verifier_data.clone(),
                )
                .is_err(),
            "multi signature verification should have failed"
        );
        verifier
            .verify_multi_signature(
                &message_hash,
                &multi_signature,
                &aggregate_verification_key,
                &fixture.protocol_parameters(),
                ancillary_verifier_data,
            )
            .expect("multi signature verification should have succeeded");
    }

    #[tokio::test]
    async fn verify_genesis_certificate_success() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let genesis_certificate = fake_certificates.genesis_certificate();

        let verify = verifier.verify_genesis_certificate(genesis_certificate).await;

        verify.expect("verify_genesis_certificate should not fail");
    }

    #[cfg(feature = "future_snark")]
    #[tokio::test]
    async fn verify_genesis_certificate_ignores_the_schnorr_half_of_a_dual_signature() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let ed_signature = match &fake_certificates.genesis_certificate().signature {
            CertificateSignature::GenesisSignature(signature) => *signature,
            other => panic!("expected a legacy genesis signature, got {other:?}"),
        };

        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let schnorr_signer = GenesisSchnorrSigner::generate(&mut rng);

        for digest in [[1u8; 32], [2u8; 32]] {
            let schnorr_signature = schnorr_signer.sign(&digest, &mut rng).unwrap();
            let mut genesis_certificate = fake_certificates.genesis_certificate().clone();
            genesis_certificate.signature =
                CertificateSignature::GenesisDualSignature(ed_signature, schnorr_signature);
            genesis_certificate.hash = genesis_certificate.try_compute_hash().unwrap();

            verifier
                .verify_genesis_certificate(&genesis_certificate)
                .await
                .expect("the Schnorr half is intentionally not verified, so this must succeed");
        }
    }

    #[tokio::test]
    async fn verify_genesis_certificate_fails_if_is_not_genesis() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let standard_certificate = fake_certificates[0].clone();
        let mut genesis_certificate = fake_certificates.genesis_certificate().clone();
        genesis_certificate.signature = standard_certificate.signature.clone();
        genesis_certificate.hash = genesis_certificate.try_compute_hash().unwrap();

        let error = verifier
            .verify_genesis_certificate(&genesis_certificate)
            .await
            .expect_err("verify_genesis_certificate should fail");

        assert_error_matches!(
            CertificateVerifierError::InvalidGenesisCertificateProvided,
            error
        )
    }

    #[tokio::test]
    async fn verify_genesis_certificate_fails_if_hash_unmatch() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let mut genesis_certificate = fake_certificates.genesis_certificate().clone();
        genesis_certificate.hash = "another-hash".to_string();

        let error = verifier
            .verify_genesis_certificate(&genesis_certificate)
            .await
            .expect_err("verify_genesis_certificate should fail");

        assert_error_matches!(CertificateVerifierError::CertificateHashUnmatch, error)
    }

    #[tokio::test]
    async fn verify_genesis_certificate_fails_if_protocol_message_unmatch() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let mut genesis_certificate = fake_certificates.genesis_certificate().clone();
        genesis_certificate.protocol_message.set_message_part(
            ProtocolMessagePartKey::CurrentEpoch,
            "another-value".to_string(),
        );
        genesis_certificate.hash = genesis_certificate.try_compute_hash().unwrap();

        let error = verifier
            .verify_genesis_certificate(&genesis_certificate)
            .await
            .expect_err("verify_genesis_certificate should fail");

        assert_error_matches!(
            CertificateVerifierError::CertificateProtocolMessageUnmatch,
            error
        )
    }

    #[tokio::test]
    async fn verify_genesis_certificate_fails_if_epoch_unmatch() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let mut genesis_certificate = fake_certificates.genesis_certificate().clone();
        genesis_certificate.epoch -= 1;
        genesis_certificate.hash = genesis_certificate.try_compute_hash().unwrap();

        let error = verifier
            .verify_genesis_certificate(&genesis_certificate)
            .await
            .expect_err("verify_genesis_certificate should fail");

        assert_error_matches!(CertificateVerifierError::CertificateEpochUnmatch, error)
    }

    #[tokio::test]
    async fn verify_standard_certificate_success_with_different_epochs_as_previous() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let certificate = fake_certificates[0].clone();
        let previous_certificate = fake_certificates[1].clone();

        let verify = verifier
            .verify_standard_certificate(&certificate, &previous_certificate)
            .await;

        verify.expect("verify_standard_certificate should not fail");
    }

    #[tokio::test]
    async fn verify_standard_certificate_success_with_same_epoch_as_previous() {
        let (total_certificates, certificates_per_epoch) = (5, 2);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let certificate = fake_certificates[0].clone();
        let previous_certificate = fake_certificates[1].clone();

        let verify = verifier
            .verify_standard_certificate(&certificate, &previous_certificate)
            .await;

        verify.expect("verify_standard_certificate should not fail");
    }

    #[test]
    fn verify_certificate_integrity_succeeds_for_a_valid_standard_certificate() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let certificate = fake_certificates[0].clone();

        verifier
            .verify_standard_certificate_integrity(&certificate)
            .expect("verify_certificate_integrity should not fail for a valid certificate");
    }

    #[test]
    fn verify_certificate_integrity_fails_for_a_tampered_certificate() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let mut certificate = fake_certificates[0].clone();
        certificate.hash = "another-hash".to_string();

        let error = verifier
            .verify_standard_certificate_integrity(&certificate)
            .expect_err("verify_certificate_integrity should fail for a tampered certificate");

        assert_error_matches!(CertificateVerifierError::CertificateHashUnmatch, error)
    }

    #[test]
    fn verify_certificate_integrity_does_not_check_the_previous_certificate_link() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let mut certificate = fake_certificates[0].clone();

        // Break the link to the previous certificate while keeping the certificate self-consistent.
        certificate.previous_hash = "unrelated-previous-hash".to_string();
        certificate.hash = certificate.try_compute_hash().unwrap();

        // The self-contained checks accept it because they never look at the previous certificate,
        // which is exactly what lets a full-chain-certifying certificate stop the chain walk early.
        verifier
            .verify_standard_certificate_integrity(&certificate)
            .expect("integrity verification must ignore the previous certificate link");
    }

    #[tokio::test]
    async fn verify_standard_certificate_fails_if_is_not_genesis() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let genesis_certificate = fake_certificates.genesis_certificate();
        let mut standard_certificate = fake_certificates[0].clone();
        standard_certificate.signature = genesis_certificate.signature.clone();
        standard_certificate.hash = standard_certificate.try_compute_hash().unwrap();
        let standard_previous_certificate = fake_certificates[1].clone();

        let error = verifier
            .verify_standard_certificate(&standard_certificate, &standard_previous_certificate)
            .await
            .expect_err("verify_standard_certificate should fail");

        assert_error_matches!(
            CertificateVerifierError::InvalidStandardCertificateProvided,
            error
        )
    }

    #[tokio::test]
    async fn verify_standard_certificate_fails_if_infinite_loop() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let mut certificate = fake_certificates[0].clone();
        certificate.previous_hash = certificate.hash.clone();
        let previous_certificate = fake_certificates[1].clone();

        let error = verifier
            .verify_standard_certificate(&certificate, &previous_certificate)
            .await
            .expect_err("verify_standard_certificate should fail");

        assert_error_matches!(
            CertificateVerifierError::CertificateChainInfiniteLoop,
            error
        )
    }

    #[tokio::test]
    async fn verify_standard_certificate_fails_if_hash_unmatch() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let mut certificate = fake_certificates[0].clone();
        certificate.hash = "another-hash".to_string();
        let previous_certificate = fake_certificates[1].clone();

        let error = verifier
            .verify_standard_certificate(&certificate, &previous_certificate)
            .await
            .expect_err("verify_standard_certificate should fail");

        assert_error_matches!(CertificateVerifierError::CertificateHashUnmatch, error)
    }

    #[tokio::test]
    async fn verify_standard_certificate_fails_if_protocol_message_unmatch() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let mut certificate = fake_certificates[0].clone();
        certificate.protocol_message.set_message_part(
            ProtocolMessagePartKey::CurrentEpoch,
            "another-value".to_string(),
        );
        certificate.hash = certificate.try_compute_hash().unwrap();
        let previous_certificate = fake_certificates[1].clone();

        let error = verifier
            .verify_standard_certificate(&certificate, &previous_certificate)
            .await
            .expect_err("verify_standard_certificate should fail");

        assert_error_matches!(
            CertificateVerifierError::CertificateProtocolMessageUnmatch,
            error
        )
    }

    #[tokio::test]
    async fn verify_standard_certificate_fails_if_epoch_unmatch() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let mut certificate = fake_certificates[0].clone();
        certificate.epoch -= 1;
        certificate.hash = certificate.try_compute_hash().unwrap();
        let previous_certificate = fake_certificates[1].clone();

        let error = verifier
            .verify_standard_certificate(&certificate, &previous_certificate)
            .await
            .expect_err("verify_standard_certificate should fail");

        assert_error_matches!(CertificateVerifierError::CertificateEpochUnmatch, error)
    }

    #[tokio::test]
    async fn verify_standard_certificate_fails_if_has_missing_epoch() {
        fn create_epoch_gap_certificate(
            certificate: Certificate,
            context: &CertificateChainBuilderContext,
        ) -> Certificate {
            let fixture = context.fixture;
            let modified_epoch = certificate.epoch + 1;
            let mut protocol_message = certificate.protocol_message.to_owned();
            protocol_message.set_message_part(
                ProtocolMessagePartKey::CurrentEpoch,
                modified_epoch.to_string(),
            );
            let signed_message = protocol_message.compute_hash();
            let mut modified_certificate = certificate;
            modified_certificate.epoch = modified_epoch;
            modified_certificate.protocol_message = protocol_message;
            modified_certificate.signed_message = signed_message.clone();
            let single_signatures = fixture
                .signers_fixture()
                .iter()
                .filter_map(|s| s.protocol_signer.sign(signed_message.as_bytes()))
                .collect::<Vec<_>>();
            let clerk =
                ProtocolClerk::new_clerk_from_signer(&fixture.signers_fixture()[0].protocol_signer);
            let (modified_multi_signature, _ancillary_proof_output) = clerk
                .aggregate_signatures_with_type(
                    &single_signatures,
                    signed_message.as_bytes(),
                    AggregateSignatureType::default(),
                    AncillaryProofInput::dummy(),
                )
                .unwrap();
            modified_certificate.signature = CertificateSignature::MultiSignature(
                modified_certificate.signed_entity_type(),
                modified_multi_signature.into(),
            );

            modified_certificate
        }

        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = CertificateChainBuilder::new()
            .with_total_certificates(total_certificates)
            .with_certificates_per_epoch(certificates_per_epoch)
            .with_standard_certificate_processor(&|certificate, context| {
                if context.is_last_certificate() {
                    create_epoch_gap_certificate(certificate, context)
                } else {
                    certificate
                }
            })
            .build();
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let certificate = fake_certificates[0].clone();
        let previous_certificate = fake_certificates[1].clone();

        let error = verifier
            .verify_standard_certificate(&certificate, &previous_certificate)
            .await
            .expect_err("verify_standard_certificate should fail");

        assert_error_matches!(
            CertificateVerifierError::CertificateChainMissingEpoch,
            error
        )
    }

    #[tokio::test]
    async fn verify_standard_certificate_fails_if_certificate_previous_hash_unmatch() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let certificate = fake_certificates[0].clone();
        let mut previous_certificate = fake_certificates[1].clone();
        previous_certificate.previous_hash = "another-hash".to_string();
        previous_certificate.hash = previous_certificate.try_compute_hash().unwrap();

        let error = verifier
            .verify_standard_certificate(&certificate, &previous_certificate)
            .await
            .expect_err("verify_standard_certificate should fail");

        assert_error_matches!(
            CertificateVerifierError::CertificateChainPreviousHashUnmatch,
            error
        )
    }

    #[tokio::test]
    async fn verify_standard_certificate_fails_if_certificate_chain_avk_unmatch() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let mut certificate = fake_certificates[0].clone();
        let mut previous_certificate = fake_certificates[1].clone();
        previous_certificate.protocol_message.set_message_part(
            ProtocolMessagePartKey::NextAggregateVerificationKey,
            "another-avk".to_string(),
        );
        previous_certificate.hash = previous_certificate.try_compute_hash().unwrap();
        certificate.previous_hash.clone_from(&previous_certificate.hash);
        certificate.hash = certificate.try_compute_hash().unwrap();

        let error = verifier
            .verify_standard_certificate(&certificate, &previous_certificate)
            .await
            .expect_err("verify_standard_certificate should fail");

        assert_error_matches!(CertificateVerifierError::CertificateChainAVKUnmatch, error)
    }

    #[tokio::test]
    async fn verify_standard_certificate_fails_if_certificate_chain_protocol_parameters_unmatch() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let verifier = MockDependencyInjector::new()
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        let mut certificate = fake_certificates[0].clone();
        let mut previous_certificate = fake_certificates[1].clone();
        previous_certificate.protocol_message.set_message_part(
            ProtocolMessagePartKey::NextProtocolParameters,
            "protocol-params-hash-123".to_string(),
        );
        previous_certificate.hash = previous_certificate.try_compute_hash().unwrap();
        certificate.previous_hash.clone_from(&previous_certificate.hash);
        certificate.hash = certificate.try_compute_hash().unwrap();

        let error = verifier
            .verify_standard_certificate(&certificate, &previous_certificate)
            .await
            .expect_err("verify_standard_certificate should fail");

        assert_error_matches!(
            CertificateVerifierError::CertificateChainProtocolParametersUnmatch,
            error
        )
    }

    #[tokio::test]
    async fn verify_certificate_success_when_certificate_is_genesis_and_valid() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let genesis_certificate = fake_certificates.genesis_certificate();
        let mock_container = MockDependencyInjector::new();
        let verifier = mock_container
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));

        let verify = verifier.verify_certificate(genesis_certificate).await;

        verify.expect("verify_certificate should not fail");
    }

    #[tokio::test]
    async fn verify_certificate_success_when_certificate_is_standard_and_valid() {
        let (total_certificates, certificates_per_epoch) = (5, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let certificate = fake_certificates[0].clone();
        let previous_certificate = fake_certificates[1].clone();
        let mut mock_container = MockDependencyInjector::new();
        mock_container
            .mock_certificate_retriever
            .expect_get_certificate_details()
            .returning(move |_| Ok(previous_certificate.clone()))
            .times(1);
        let verifier = mock_container
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));

        let verify = verifier.verify_certificate(&certificate).await;

        verify.expect("verify_certificate should not fail");
    }

    #[tokio::test]
    async fn verify_certificate_chain_verifies_all_chained_certificates() {
        struct CertificateVerifierTest {
            certificates_unverified: Mutex<HashMap<String, Certificate>>,
        }

        impl CertificateVerifierTest {
            fn from_certificates(certificates: &[Certificate]) -> Self {
                Self {
                    certificates_unverified: Mutex::new(HashMap::from_iter(
                        certificates.iter().map(|c| (c.hash.to_owned(), c.to_owned())),
                    )),
                }
            }

            async fn has_unverified_certificates(&self) -> bool {
                !self.certificates_unverified.lock().await.is_empty()
            }
        }

        #[async_trait]
        impl CertificateVerifier for CertificateVerifierTest {
            async fn verify_genesis_certificate(
                &self,
                _genesis_certificate: &Certificate,
            ) -> StdResult<()> {
                unimplemented!()
            }

            async fn verify_standard_certificate(
                &self,
                _certificate: &Certificate,
                _previous_certificate: &Certificate,
            ) -> StdResult<()> {
                unimplemented!()
            }

            async fn verify_certificate(
                &self,
                certificate: &Certificate,
            ) -> StdResult<Option<Certificate>> {
                let mut certificates_unverified = self.certificates_unverified.lock().await;
                let _verified_certificate = (*certificates_unverified).remove(&certificate.hash);
                let previous_certificate =
                    (*certificates_unverified).get(&certificate.previous_hash).cloned();

                Ok(previous_certificate)
            }
        }

        let (total_certificates, certificates_per_epoch) = (10, 1);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let fake_certificate_to_verify = fake_certificates[0].clone();
        let verifier = CertificateVerifierTest::from_certificates(&fake_certificates);
        assert!(verifier.has_unverified_certificates().await);

        let verify = verifier.verify_certificate_chain(fake_certificate_to_verify).await;

        verify.expect("verify_certificate_chain should not fail");
        assert!(!verifier.has_unverified_certificates().await);
    }

    #[tokio::test]
    async fn verify_certificate_chain_success_when_chain_is_valid() {
        let (total_certificates, certificates_per_epoch) = (7, 2);
        let fake_certificates = setup_certificate_chain(total_certificates, certificates_per_epoch);
        let certificate_retriever =
            FakeCertificaterRetriever::from_certificates(&fake_certificates);
        let verifier = MithrilCertificateVerifier::new(
            TestLogger::stdout(),
            Arc::new(certificate_retriever),
            Arc::new(fake_certificates.genesis_verifier.clone()),
            #[cfg(feature = "future_snark")]
            None,
        );
        let certificate_to_verify = fake_certificates[0].clone();

        let verify = verifier.verify_certificate_chain(certificate_to_verify).await;
        verify.expect("verify_certificate_chain should not fail");
    }

    #[tokio::test]
    async fn verify_certificate_chain_fails_when_chain_is_tampered() {
        let (total_certificates, certificates_per_epoch) = (7, 2);
        let mut fake_certificates =
            setup_certificate_chain(total_certificates, certificates_per_epoch);
        let index_certificate_fail = (total_certificates / 2) as usize;
        fake_certificates[index_certificate_fail].signed_message = "tampered-message".to_string();
        let certificate_retriever =
            FakeCertificaterRetriever::from_certificates(&fake_certificates);
        let verifier = MithrilCertificateVerifier::new(
            TestLogger::stdout(),
            Arc::new(certificate_retriever),
            Arc::new(fake_certificates.genesis_verifier.clone()),
            #[cfg(feature = "future_snark")]
            None,
        );
        let certificate_to_verify = fake_certificates[0].clone();

        let error = verifier
            .verify_certificate_chain(certificate_to_verify)
            .await
            .expect_err("verify_certificate_chain should fail");

        assert_error_matches!(CertificateVerifierError::CertificateHashUnmatch, error)
    }

    // This implementation of SNARKs fixes this problem by default as if the adversary
    // changes its value of phi_f, its lottery target won't match the one in the merkle tree
    /// Note: Check if this test is still necessary when enabling `future_snark` as default
    #[cfg(not(feature = "future_snark"))]
    #[tokio::test]
    async fn verify_certificate_chain_fails_when_adversarial_with_registered_signer_forgery_through_protocol_parameters()
     {
        // Create an adversarial certificate with a forged multi signature:
        // - with the valid signed message
        // - with the valid aggregate verification key (valid stake distribution)
        // - by a legit adversarial registered signer in the signing stake distribution
        // - with adversarial protocol parameters (phi_f = 1.0, i.e. all lotteries are won by the adversarial signer and quorum is reached)
        fn forge_certificate(
            certificate: Certificate,
            context: &CertificateChainBuilderContext,
        ) -> Certificate {
            assert_ne!(
                1.0, certificate.metadata.protocol_parameters.phi_f,
                "Adversarial protocol parameters phi_f should be different from 1.0"
            );
            let fixture = context.fixture;
            let signed_message = certificate.signed_message.to_owned();
            let mut forged_certificate = certificate;
            let mut forged_protocol_parameters = fixture.protocol_parameters();
            forged_protocol_parameters.phi_f = 1.0;
            let forged_single_signatures = fixture
                .signers_fixture()
                .iter()
                .take(1)
                .filter_map(|s| {
                    let s_adversary = s
                        .to_owned()
                        .try_new_with_protocol_parameters(forged_protocol_parameters.clone())
                        .unwrap();

                    s_adversary.protocol_signer.sign(signed_message.as_bytes())
                })
                .collect::<Vec<_>>();
            let forged_clerk = ProtocolClerk::new_clerk_from_closed_key_registration(
                &forged_protocol_parameters.clone().into(),
                &fixture.signers_fixture()[0].protocol_closed_key_registration,
            );
            let (forged_multi_signature, _ancillary_proof_output) = forged_clerk
                .aggregate_signatures_with_type(
                    &forged_single_signatures,
                    signed_message.as_bytes(),
                    AggregateSignatureType::default(),
                    AncillaryProofInput::dummy(),
                )
                .unwrap();
            forged_certificate.signature = CertificateSignature::MultiSignature(
                forged_certificate.signed_entity_type(),
                forged_multi_signature.into(),
            );
            forged_certificate.metadata.protocol_parameters = forged_protocol_parameters;

            forged_certificate
        }

        let (total_certificates, certificates_per_epoch) = (7, 2);
        let fake_certificates = CertificateChainBuilder::new()
            .with_total_certificates(total_certificates)
            .with_certificates_per_epoch(certificates_per_epoch)
            .with_standard_certificate_processor(&|certificate, context| {
                if context.is_last_certificate() {
                    forge_certificate(certificate, context)
                } else {
                    certificate
                }
            })
            .build();
        let certificate_to_verify = fake_certificates[0].clone();
        let mock_container = MockDependencyInjector::new();
        let mut verifier = mock_container
            .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
        verifier.certificate_retriever = Arc::new(FakeCertificaterRetriever::from_certificates(
            &fake_certificates,
        ));

        let error = verifier
            .verify_certificate(&certificate_to_verify)
            .await
            .expect_err("verify_certificate_chain should fail");

        assert_error_matches!(
            CertificateVerifierError::CertificateChainProtocolParametersUnmatch,
            error
        )
    }

    #[cfg(feature = "future_snark")]
    mod snark_avk_chaining {
        use super::*;

        use crate::entities::SupportedEra;
        use crate::test::builder::{CertificateChainBuilder, CertificateChainFixture};
        use crate::test::double::fake_data::snark_aggregate_signature;

        fn setup_certificate_chain_with_lagrange_era(
            total_certificates: u64,
            certificates_per_epoch: u64,
        ) -> CertificateChainFixture {
            CertificateChainBuilder::new()
                .with_total_certificates(total_certificates)
                .with_certificates_per_epoch(certificates_per_epoch)
                .with_protocol_parameters(setup_protocol_parameters())
                .with_mithril_era(SupportedEra::Lagrange)
                .build()
        }

        fn with_snark_proof_type(mut certificate: Certificate) -> Certificate {
            if let CertificateSignature::MultiSignature(entity_type, _) =
                certificate.signature.clone()
            {
                let snark_signature = snark_aggregate_signature();
                certificate.signature =
                    CertificateSignature::MultiSignature(entity_type, snark_signature);
                certificate.hash = certificate.try_compute_hash().unwrap();
            } else {
                panic!("Certificate signature should be a multi signature");
            }
            certificate
        }

        #[test]
        fn snark_avk_chaining_succeeds_with_different_epochs() {
            let (total_certificates, certificates_per_epoch) = (5, 1);
            let fake_certificates = setup_certificate_chain_with_lagrange_era(
                total_certificates,
                certificates_per_epoch,
            );
            let verifier = MockDependencyInjector::new()
                .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
            let mut certificate = with_snark_proof_type(fake_certificates[0].clone());
            let previous_certificate = fake_certificates[1].clone();
            certificate.previous_hash.clone_from(&previous_certificate.hash);
            certificate.hash = certificate.try_compute_hash().unwrap();

            verifier
                .verify_snark_aggregate_verification_key_chaining(
                    &certificate,
                    &previous_certificate,
                )
                .expect("SNARK AVK chaining verification should not fail");
        }

        #[test]
        fn snark_avk_chaining_succeeds_with_same_epoch() {
            let (total_certificates, certificates_per_epoch) = (5, 2);
            let fake_certificates = setup_certificate_chain_with_lagrange_era(
                total_certificates,
                certificates_per_epoch,
            );
            let verifier = MockDependencyInjector::new()
                .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
            let certificate = with_snark_proof_type(fake_certificates[0].clone());
            let previous_certificate = fake_certificates[1].clone();

            verifier
                .verify_snark_aggregate_verification_key_chaining(
                    &certificate,
                    &previous_certificate,
                )
                .expect("SNARK AVK chaining verification should not fail");
        }

        #[test]
        fn snark_avk_chaining_fails_with_same_epoch_when_current_has_snark_avk_but_previous_does_not()
         {
            let (total_certificates, certificates_per_epoch) = (5, 2);
            let fake_certificates = setup_certificate_chain_with_lagrange_era(
                total_certificates,
                certificates_per_epoch,
            );
            let verifier = MockDependencyInjector::new()
                .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
            let certificate = with_snark_proof_type(fake_certificates[0].clone());
            let mut previous_certificate = fake_certificates[1].clone();
            previous_certificate.aggregate_verification_key_snark = None;

            let error = verifier
                .verify_snark_aggregate_verification_key_chaining(
                    &certificate,
                    &previous_certificate,
                )
                .expect_err("SNARK AVK chaining verification should fail");

            assert_error_matches!(CertificateVerifierError::CertificateChainAVKUnmatch, error)
        }

        #[test]
        fn snark_avk_chaining_fails_with_same_epoch_when_previous_has_snark_avk_but_current_does_not()
         {
            let (total_certificates, certificates_per_epoch) = (5, 2);
            let fake_certificates = setup_certificate_chain_with_lagrange_era(
                total_certificates,
                certificates_per_epoch,
            );
            let verifier = MockDependencyInjector::new()
                .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
            let mut certificate = with_snark_proof_type(fake_certificates[0].clone());
            certificate.aggregate_verification_key_snark = None;
            certificate.hash = certificate.try_compute_hash().unwrap();
            let previous_certificate = fake_certificates[1].clone();

            let error = verifier
                .verify_snark_aggregate_verification_key_chaining(
                    &certificate,
                    &previous_certificate,
                )
                .expect_err("SNARK AVK chaining verification should fail");

            assert_error_matches!(CertificateVerifierError::CertificateChainAVKUnmatch, error)
        }

        #[test]
        fn snark_avk_chaining_fails_with_same_epoch_when_both_lack_snark_avk() {
            let (total_certificates, certificates_per_epoch) = (5, 2);
            let fake_certificates = setup_certificate_chain_with_lagrange_era(
                total_certificates,
                certificates_per_epoch,
            );
            let verifier = MockDependencyInjector::new()
                .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
            let mut certificate = with_snark_proof_type(fake_certificates[0].clone());
            certificate.aggregate_verification_key_snark = None;
            certificate.hash = certificate.try_compute_hash().unwrap();
            let mut previous_certificate = fake_certificates[1].clone();
            previous_certificate.aggregate_verification_key_snark = None;

            let error = verifier
                .verify_snark_aggregate_verification_key_chaining(
                    &certificate,
                    &previous_certificate,
                )
                .expect_err("SNARK AVK chaining verification should fail");

            assert_error_matches!(CertificateVerifierError::CertificateChainAVKUnmatch, error)
        }

        #[test]
        fn snark_avk_chaining_fails_when_next_snark_avk_is_tampered() {
            let (total_certificates, certificates_per_epoch) = (5, 1);
            let fake_certificates = setup_certificate_chain_with_lagrange_era(
                total_certificates,
                certificates_per_epoch,
            );
            let verifier = MockDependencyInjector::new()
                .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
            let certificate = with_snark_proof_type(fake_certificates[0].clone());
            let mut previous_certificate = fake_certificates[1].clone();
            previous_certificate.protocol_message.set_message_part(
                ProtocolMessagePartKey::NextSnarkAggregateVerificationKey,
                "tampered-snark-avk".to_string(),
            );

            let error = verifier
                .verify_snark_aggregate_verification_key_chaining(
                    &certificate,
                    &previous_certificate,
                )
                .expect_err("SNARK AVK chaining verification should fail");

            assert_error_matches!(CertificateVerifierError::CertificateChainAVKUnmatch, error)
        }

        #[test]
        fn snark_avk_chaining_fails_when_next_snark_avk_is_missing() {
            let (total_certificates, certificates_per_epoch) = (5, 1);
            let fake_certificates = setup_certificate_chain_with_lagrange_era(
                total_certificates,
                certificates_per_epoch,
            );
            let verifier = MockDependencyInjector::new()
                .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
            let certificate = with_snark_proof_type(fake_certificates[0].clone());
            let mut previous_certificate = fake_certificates[1].clone();
            previous_certificate
                .protocol_message
                .message_parts
                .remove(&ProtocolMessagePartKey::NextSnarkAggregateVerificationKey);

            let error = verifier
                .verify_snark_aggregate_verification_key_chaining(
                    &certificate,
                    &previous_certificate,
                )
                .expect_err("SNARK AVK chaining verification should fail");

            assert_error_matches!(CertificateVerifierError::CertificateChainAVKUnmatch, error)
        }

        #[test]
        fn avk_chaining_dispatches_to_snark_when_current_is_future_and_previous_is_concatenation() {
            let (total_certificates, certificates_per_epoch) = (5, 1);
            let fake_certificates = setup_certificate_chain_with_lagrange_era(
                total_certificates,
                certificates_per_epoch,
            );
            let verifier = MockDependencyInjector::new()
                .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
            let mut certificate = with_snark_proof_type(fake_certificates[0].clone());
            let previous_certificate = fake_certificates[1].clone();
            certificate.previous_hash.clone_from(&previous_certificate.hash);
            certificate.hash = certificate.try_compute_hash().unwrap();

            verifier
                .verify_aggregate_verification_key_chaining(&certificate, &previous_certificate)
                .expect(
                    "AVK chaining from concatenation to Snark should succeed via SNARK dispatch",
                );
        }

        #[test]
        fn snark_avk_chaining_succeeds_when_previous_is_genesis_certificate() {
            let (total_certificates, certificates_per_epoch) = (5, 1);
            let fake_certificates = setup_certificate_chain_with_lagrange_era(
                total_certificates,
                certificates_per_epoch,
            );
            let verifier = MockDependencyInjector::new()
                .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));
            let genesis_certificate = fake_certificates.genesis_certificate().clone();
            let mut certificate = with_snark_proof_type(fake_certificates[3].clone());
            certificate.previous_hash.clone_from(&genesis_certificate.hash);
            certificate.hash = certificate.try_compute_hash().unwrap();

            verifier
                .verify_snark_aggregate_verification_key_chaining(
                    &certificate,
                    &genesis_certificate,
                )
                .expect("SNARK AVK chaining from genesis to SNARK certificate should succeed");
        }
    }

    #[cfg(feature = "future_snark")]
    mod rigid_protocol_message_dispatch {
        use super::*;

        use crate::entities::{Epoch, ProtocolMessage, ProtocolMessagePartKey};
        use crate::test::double::fake_data;

        fn build_certificate(epoch: Epoch, rigid: ProtocolMessage) -> Certificate {
            let mut certificate = fake_data::certificate("cert-rigid");
            certificate.epoch = epoch;
            certificate.protocol_message = rigid;
            certificate.signed_message = certificate.protocol_message.compute_hash();
            certificate.hash = certificate.try_compute_hash().unwrap();
            certificate
        }

        fn rigid_protocol_message_for_epoch(
            epoch: Epoch,
            protocol_parameters: &ProtocolParameters,
        ) -> ProtocolMessage {
            let mut rigid = ProtocolMessage::new_rigid();
            rigid.set_message_part(
                ProtocolMessagePartKey::CardanoStakeDistributionMerkleRoot,
                "cardano-stake-distribution-merkle-root".to_string(),
            );
            rigid.set_message_part(
                ProtocolMessagePartKey::NextProtocolParameters,
                protocol_parameters.compute_hash(),
            );
            rigid.set_message_part(ProtocolMessagePartKey::CurrentEpoch, epoch.to_string());
            rigid
        }

        #[test]
        fn verify_epoch_matches_protocol_message_accepts_rigid_variant_when_epoch_matches() {
            let epoch = Epoch(42);
            let protocol_parameters = ProtocolParameters::new(5, 10, 0.7);
            let certificate = build_certificate(
                epoch,
                rigid_protocol_message_for_epoch(epoch, &protocol_parameters),
            );
            let verifier =
                MockDependencyInjector::new().build_certificate_verifier(fake_genesis_verifier());

            verifier
                .verify_epoch_matches_protocol_message(&certificate)
                .expect("rigid protocol message with matching epoch should pass");
        }

        #[test]
        fn verify_epoch_matches_protocol_message_rejects_rigid_variant_when_epoch_mismatches() {
            let protocol_parameters = ProtocolParameters::new(5, 10, 0.7);
            let certificate = build_certificate(
                Epoch(43),
                rigid_protocol_message_for_epoch(Epoch(42), &protocol_parameters),
            );
            let verifier =
                MockDependencyInjector::new().build_certificate_verifier(fake_genesis_verifier());

            let error = verifier
                .verify_epoch_matches_protocol_message(&certificate)
                .expect_err("rigid protocol message with mismatching epoch should fail");

            assert_error_matches!(CertificateVerifierError::CertificateEpochUnmatch, error);
        }

        #[test]
        fn verify_protocol_parameters_chaining_accepts_rigid_previous_when_hash_matches() {
            let current_certificate = fake_data::certificate("cert-current");
            let previous_epoch = current_certificate.epoch - 1;
            let rigid = rigid_protocol_message_for_epoch(
                previous_epoch,
                &current_certificate.metadata.protocol_parameters,
            );
            let previous_certificate = build_certificate(previous_epoch, rigid);
            let verifier =
                MockDependencyInjector::new().build_certificate_verifier(fake_genesis_verifier());

            verifier
                .verify_protocol_parameters_chaining(&current_certificate, &previous_certificate)
                .expect(
                    "rigid previous protocol message carrying the right parameters hash must pass",
                );
        }

        #[test]
        fn verify_protocol_parameters_chaining_rejects_rigid_previous_when_hash_mismatches() {
            let current_certificate = fake_data::certificate("cert-current");
            let previous_epoch = current_certificate.epoch - 1;
            let protocol_parameters = ProtocolParameters::new(5, 10, 0.7);
            let mut rigid = rigid_protocol_message_for_epoch(previous_epoch, &protocol_parameters);
            rigid.set_message_part(
                ProtocolMessagePartKey::NextProtocolParameters,
                hex::encode([0u8; 32]),
            );
            let previous_certificate = build_certificate(previous_epoch, rigid);
            let verifier =
                MockDependencyInjector::new().build_certificate_verifier(fake_genesis_verifier());

            let error = verifier
                .verify_protocol_parameters_chaining(&current_certificate, &previous_certificate)
                .expect_err("rigid previous protocol message with wrong parameters hash must fail");

            assert_error_matches!(
                CertificateVerifierError::CertificateChainProtocolParametersUnmatch,
                error
            );
        }
    }

    #[cfg(feature = "future_snark")]
    mod era_transition_chain_linkage {
        use super::*;

        use crate::entities::{ProtocolMessageHashScheme, SupportedEra};

        fn pythagoras_to_lagrange_era_transition_pair() -> (Certificate, Certificate) {
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(5)
                .with_certificates_per_epoch(1)
                .with_protocol_parameters(setup_protocol_parameters())
                .with_mithril_era(SupportedEra::Pythagoras)
                .build();

            let predecessor = chain[1].clone();
            let mut successor = chain[0].clone();

            successor.epoch = predecessor.epoch + 1;
            successor.protocol_message.hash_scheme = ProtocolMessageHashScheme::Rigid;
            successor.signed_message = successor.protocol_message.compute_hash();
            successor.previous_hash.clone_from(&predecessor.hash);
            successor.hash = successor.try_compute_hash().unwrap();

            (predecessor, successor)
        }

        #[test]
        fn predecessor_uses_legacy_hash_scheme_and_successor_uses_rigid_hash_scheme() {
            let (predecessor, successor) = pythagoras_to_lagrange_era_transition_pair();

            assert_eq!(
                predecessor.protocol_message.hash_scheme,
                ProtocolMessageHashScheme::Legacy,
                "the Pythagoras predecessor must keep the Legacy hash scheme",
            );
            assert_eq!(
                successor.protocol_message.hash_scheme,
                ProtocolMessageHashScheme::Rigid,
                "the Lagrange successor must carry the Rigid hash scheme",
            );
            assert_eq!(
                successor.epoch,
                predecessor.epoch + 1,
                "the successor must sit exactly one epoch after the predecessor to exercise cross-epoch chaining",
            );
        }

        #[test]
        fn concatenation_aggregate_verification_key_chains_at_era_transition() {
            let (predecessor, successor) = pythagoras_to_lagrange_era_transition_pair();
            let verifier =
                MockDependencyInjector::new().build_certificate_verifier(fake_genesis_verifier());

            verifier
                .verify_concatenation_aggregate_verification_key_chaining(
                    &successor,
                    &predecessor,
                )
                .expect(
                    "concatenation AVK chaining must hold across the Pythagoras to Lagrange era transition",
                );
        }

        #[test]
        fn protocol_parameters_chain_at_era_transition() {
            let (predecessor, successor) = pythagoras_to_lagrange_era_transition_pair();
            let verifier =
                MockDependencyInjector::new().build_certificate_verifier(fake_genesis_verifier());

            verifier
                .verify_protocol_parameters_chaining(&successor, &predecessor)
                .expect(
                    "protocol parameters chaining must hold across the Pythagoras to Lagrange era transition",
                );
        }

        #[test]
        fn epoch_chain_at_era_transition() {
            let (predecessor, successor) = pythagoras_to_lagrange_era_transition_pair();
            let verifier =
                MockDependencyInjector::new().build_certificate_verifier(fake_genesis_verifier());

            verifier.verify_epoch_chaining(&successor, &predecessor).expect(
                "epoch chaining must hold across the Pythagoras to Lagrange era transition",
            );
        }

        #[test]
        fn previous_hash_chain_at_era_transition() {
            let (predecessor, successor) = pythagoras_to_lagrange_era_transition_pair();
            let verifier =
                MockDependencyInjector::new().build_certificate_verifier(fake_genesis_verifier());

            verifier
                .verify_previous_hash_matches_previous_certificate_hash(&successor, &predecessor)
                .expect(
                    "previous-hash chaining must hold across the Pythagoras to Lagrange era transition",
                );
        }

        #[test]
        fn aggregate_verification_key_chain_dispatches_to_concatenation_at_era_transition() {
            let (predecessor, successor) = pythagoras_to_lagrange_era_transition_pair();
            let verifier =
                MockDependencyInjector::new().build_certificate_verifier(fake_genesis_verifier());

            verifier
                .verify_aggregate_verification_key_chaining(&successor, &predecessor)
                .expect(
                    "AVK chaining dispatch (Concatenation) must succeed across the Pythagoras to Lagrange era transition",
                );
        }

        #[cfg(feature = "future_snark")]
        mod snark_signature_dispatch {
            use super::*;

            use crate::test::double::fake_data::snark_aggregate_signature;

            fn promote_to_snark_aggregate_signature(mut certificate: Certificate) -> Certificate {
                let CertificateSignature::MultiSignature(entity_type, _) =
                    certificate.signature.clone()
                else {
                    panic!("certificate signature must be a multi signature");
                };
                certificate.signature =
                    CertificateSignature::MultiSignature(entity_type, snark_aggregate_signature());
                certificate.hash = certificate.try_compute_hash().unwrap();
                certificate
            }

            #[test]
            fn snark_aggregate_verification_key_chains_at_era_transition() {
                let (predecessor, successor) = pythagoras_to_lagrange_era_transition_pair();
                let successor = promote_to_snark_aggregate_signature(successor);
                let verifier = MockDependencyInjector::new()
                    .build_certificate_verifier(fake_genesis_verifier());

                verifier
                    .verify_snark_aggregate_verification_key_chaining(&successor, &predecessor)
                    .expect(
                        "SNARK AVK chaining must hold across the Pythagoras to Lagrange era transition",
                    );
            }

            #[test]
            fn aggregate_verification_key_chain_dispatches_to_snark_at_era_transition() {
                let (predecessor, successor) = pythagoras_to_lagrange_era_transition_pair();
                let successor = promote_to_snark_aggregate_signature(successor);
                let verifier = MockDependencyInjector::new()
                    .build_certificate_verifier(fake_genesis_verifier());

                verifier
                    .verify_aggregate_verification_key_chaining(&successor, &predecessor)
                    .expect(
                        "AVK chaining dispatch (SNARK) must succeed across the Pythagoras to Lagrange era transition",
                    );
            }
        }
    }

    #[cfg(feature = "future_snark")]
    mod certified_circuit_verification_keys {
        use crate::crypto_helper::{
            CircuitVerificationKeyCertifier, MithrilCircuitVerificationKeyCertifier,
        };
        use crate::test::double::{
            FakeCircuitVerificationKeyRegistryRetriever, fake_data::snark_aggregate_signature,
        };

        use super::*;

        fn promote_to_snark_aggregate_signature_without_ancillary_data(
            mut certificate: Certificate,
        ) -> Certificate {
            let CertificateSignature::MultiSignature(entity_type, _) =
                certificate.signature.clone()
            else {
                panic!("certificate signature must be a multi signature");
            };
            certificate.signature =
                CertificateSignature::MultiSignature(entity_type, snark_aggregate_signature());
            certificate.ancillary_verifier_data = None;
            certificate
        }

        fn failing_certifier() -> Arc<dyn CircuitVerificationKeyCertifier> {
            Arc::new(MithrilCircuitVerificationKeyCertifier::new(
                Arc::new(FakeCircuitVerificationKeyRegistryRetriever::that_fails()),
                fake_genesis_verifier(),
            ))
        }

        #[tokio::test]
        async fn skips_the_check_for_a_concatenation_certificate_without_certifier() {
            let fake_certificates = setup_certificate_chain(2, 1);
            let verifier = MockDependencyInjector::new()
                .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));

            verifier
                .verify_certified_circuit_verification_keys(&fake_certificates[0])
                .await
                .expect("a concatenation certificate must not require a certifier");
        }

        #[tokio::test]
        async fn rejects_a_snark_certificate_when_no_certifier_is_configured() {
            let fake_certificates = setup_certificate_chain(2, 1);
            let certificate = promote_to_snark_aggregate_signature_without_ancillary_data(
                fake_certificates[0].clone(),
            );
            let verifier = MockDependencyInjector::new()
                .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));

            let error = verifier
                .verify_certified_circuit_verification_keys(&certificate)
                .await
                .expect_err("a SNARK certificate must be rejected without a certifier");

            assert_error_matches!(
                CertificateVerifierError::MissingCircuitVerificationKeyCertifier,
                error
            );
        }

        #[tokio::test]
        async fn rejects_a_snark_certificate_without_ancillary_verifier_data() {
            let fake_certificates = setup_certificate_chain(2, 1);
            let certificate = promote_to_snark_aggregate_signature_without_ancillary_data(
                fake_certificates[0].clone(),
            );
            let verifier = MithrilCertificateVerifier::new(
                TestLogger::stdout(),
                Arc::new(MockCertificateRetriever::new()),
                Arc::new(fake_certificates.genesis_verifier.clone()),
                Some(failing_certifier()),
            );

            let error = verifier
                .verify_certified_circuit_verification_keys(&certificate)
                .await
                .expect_err("a SNARK certificate without ancillary verifier data must be rejected");

            assert_error_matches!(
                CertificateVerifierError::MissingAncillaryVerifierData,
                error
            );
        }

        #[tokio::test]
        async fn verify_standard_certificate_enforces_the_check_before_any_other_verification() {
            let fake_certificates = setup_certificate_chain(2, 1);
            let certificate = promote_to_snark_aggregate_signature_without_ancillary_data(
                fake_certificates[0].clone(),
            );
            let verifier = MockDependencyInjector::new()
                .build_certificate_verifier(Arc::new(fake_certificates.genesis_verifier.clone()));

            let error = verifier
                .verify_standard_certificate(&certificate, &fake_certificates[1])
                .await
                .expect_err("standard certificate verification must enforce the check");

            assert_error_matches!(
                CertificateVerifierError::MissingCircuitVerificationKeyCertifier,
                error
            );
        }
    }
}
