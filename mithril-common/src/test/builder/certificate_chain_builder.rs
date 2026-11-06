use std::cmp::min;
use std::collections::{BTreeSet, HashMap};
use std::iter::repeat_n;
use std::ops::{Deref, DerefMut};

use mithril_stm::{AggregateSignatureType, AncillaryProofInput};

use crate::{
    certificate_chain::CertificateGenesisProducer,
    crypto_helper::{GenesisSigner, GenesisVerifier, ProtocolClerk, ProtocolParameters},
    entities::{
        CardanoDbBeacon, Certificate, CertificateMetadata, CertificateSignature, Epoch,
        ProtocolMessage, ProtocolMessagePartKey, SignedEntityType, SupportedEra,
    },
    test::{
        builder::{MithrilFixture, MithrilFixtureBuilder, SignerFixture},
        double::{Dummy, fake_data},
    },
};

/// Genesis certificate processor function type. For tests only.
type GenesisCertificateProcessorFunc =
    dyn Fn(Certificate, &CertificateChainBuilderContext, &GenesisSigner) -> Certificate;

/// Standard certificate processor function type. For tests only.
type StandardCertificateProcessorFunc =
    dyn Fn(Certificate, &CertificateChainBuilderContext) -> Certificate;

/// Total signers per epoch processor function type. For tests only.
type TotalSignersPerEpochProcessorFunc = dyn Fn(Epoch) -> usize;

/// Context used while building a certificate chain. For tests only.
pub struct CertificateChainBuilderContext<'a> {
    /// The index of the certificate in the chain.
    pub index_certificate: usize,
    /// The total number of certificates in the chain.
    #[allow(dead_code)]
    pub total_certificates: usize,
    /// The epoch of the certificate.
    pub epoch: Epoch,
    /// The fixture of the epoch.
    pub fixture: &'a MithrilFixture,
    /// The fixture of the next epoch.
    pub next_fixture: &'a MithrilFixture,
}

impl<'a> CertificateChainBuilderContext<'a> {
    fn new(
        index_certificate: usize,
        total_certificates: usize,
        epoch: Epoch,
        fixture: &'a MithrilFixture,
        next_fixture: &'a MithrilFixture,
    ) -> Self {
        Self {
            index_certificate,
            total_certificates,
            epoch,
            fixture,
            next_fixture,
        }
    }

    /// Computes the protocol message seed.
    pub fn compute_protocol_message_seed(&self) -> ProtocolMessage {
        let mut protocol_message = ProtocolMessage::new();
        protocol_message.set_message_part(
            ProtocolMessagePartKey::NextAggregateVerificationKey,
            self.next_fixture
                .compute_and_encode_concatenation_aggregate_verification_key(),
        );

        #[cfg(feature = "snark")]
        if let Some(snark_avk) = self
            .next_fixture
            .compute_and_encode_snark_aggregate_verification_key()
        {
            protocol_message.set_message_part(
                ProtocolMessagePartKey::NextSnarkAggregateVerificationKey,
                snark_avk,
            );
        }

        protocol_message.set_message_part(
            ProtocolMessagePartKey::NextProtocolParameters,
            self.next_fixture.protocol_parameters().compute_hash(),
        );
        protocol_message
            .set_message_part(ProtocolMessagePartKey::CurrentEpoch, self.epoch.to_string());

        protocol_message
    }

    /// Checks if the current certificate is the last one.
    pub fn is_last_certificate(&self) -> bool {
        self.index_certificate == self.total_certificates - 1
    }
}

/// Chaining method to use when building a certificate chain with the [CertificateChainBuilder]. For tests only.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum CertificateChainingMethod {
    /// `default` Chain certificates to the 'master' certificate of the epoch or if it's the 'master'
    /// certificate, chain it to the 'master' certificate of the previous epoch.
    ///
    /// The 'master' certificate of an epoch is the first certificate of the epoch.
    #[default]
    ToMasterCertificate,

    /// Chain certificates sequentially.
    Sequential,
}

/// Fixture built from a [CertificateChainBuilder], certificates are ordered from latest to genesis
#[derive(Debug, Clone)]
pub struct CertificateChainFixture {
    /// The full certificates list, ordered from latest to genesis
    pub certificates_chained: Vec<Certificate>,
    /// The genesis verifier associated with this chain genesis certificate
    pub genesis_verifier: GenesisVerifier,
}

impl Deref for CertificateChainFixture {
    type Target = [Certificate];

    fn deref(&self) -> &Self::Target {
        &self.certificates_chained
    }
}

impl DerefMut for CertificateChainFixture {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.certificates_chained
    }
}

impl<C: TryFrom<Certificate>> TryFrom<CertificateChainFixture> for Vec<C> {
    type Error = C::Error;

    fn try_from(fixture: CertificateChainFixture) -> Result<Self, Self::Error> {
        fixture.certificates_chained.into_iter().map(C::try_from).collect()
    }
}

impl CertificateChainFixture {
    /// Return the genesis certificate of this chain
    pub fn genesis_certificate(&self) -> &Certificate {
        &self.certificates_chained[self.certificates_chained.len() - 1]
    }

    /// Return the latest certificate of this chain
    pub fn latest_certificate(&self) -> &Certificate {
        &self.certificates_chained[0]
    }

    /// Return a copy of the chain but with reversed order (from genesis to last)
    pub fn reversed_chain(&self) -> Vec<Certificate> {
        self.certificates_chained.iter().rev().cloned().collect()
    }

    /// Extract the chain starting from the certificate with the given hash and all its parents
    /// until the genesis certificate.
    pub fn certificate_path_to_genesis<H: AsRef<str>>(
        &self,
        certificate_hash: H,
    ) -> Vec<Certificate> {
        let mut subchain = Vec::new();
        let mut hash_to_search = certificate_hash.as_ref().to_string();

        // takes advantage of the fact that chained certificates are ordered from last to genesis
        for certificate in &self.certificates_chained {
            if certificate.hash == hash_to_search {
                subchain.push(certificate.clone());
                hash_to_search = certificate.previous_hash.clone();
            }
        }

        subchain
    }
}

/// A builder for creating a certificate chain. For tests only.
///
/// # Simple example usage for building a fully valid certificate chain
///
/// ```
///     use mithril_common::crypto_helper::ProtocolParameters;
///     use mithril_common::test::builder::CertificateChainBuilder;
///
///     let certificate_chain_fixture = CertificateChainBuilder::new()
///         .with_total_certificates(5)
///         .with_certificates_per_epoch(2)
///         .build();
///
///     assert_eq!(5, certificate_chain_fixture.len());
/// ```
///
/// # More complex example usage for building a fully valid certificate chain
///
/// ```
///     use std::cmp::min;
///     use mithril_common::crypto_helper::ProtocolParameters;
///     use mithril_common::test::builder::CertificateChainBuilder;
///
///     let certificate_chain_fixture = CertificateChainBuilder::new()
///         .with_total_certificates(5)
///         .with_certificates_per_epoch(2)
///         .with_protocol_parameters(ProtocolParameters {
///             m: 100,
///             k: 5,
///             phi_f: 0.65,
///         })
///         .with_total_signers_per_epoch_processor(&|epoch| min(1 + *epoch as usize, 10))
///         .build();
///
///     assert_eq!(5, certificate_chain_fixture.len());
/// ```
///
/// # Advanced example usage for building an adversarial certificate chain
///
/// ```
///     use mithril_common::entities::Epoch;
///     use mithril_common::crypto_helper::ProtocolParameters;
///     use mithril_common::test::builder::CertificateChainBuilder;
///
///     let certificate_chain_fixture = CertificateChainBuilder::new()
///         .with_total_certificates(5)
///         .with_certificates_per_epoch(2)
///         .with_standard_certificate_processor(&|certificate, context| {
///             let mut certificate = certificate;
///             // Alter the epoch of the last certificate
///             if context.is_last_certificate() {
///                 certificate.epoch = Epoch(123);
///             }
///
///             certificate
///        })
///        .build();
///
///     assert_eq!(5, certificate_chain_fixture.len());
/// ```
pub struct CertificateChainBuilder<'a> {
    total_certificates: u64,
    certificates_per_epoch: u64,
    protocol_parameters: ProtocolParameters,
    total_signers_per_epoch_processor: &'a TotalSignersPerEpochProcessorFunc,
    genesis_certificate_processor: &'a GenesisCertificateProcessorFunc,
    standard_certificate_processor: &'a StandardCertificateProcessorFunc,
    certificate_chaining_method: CertificateChainingMethod,
    aggregate_signature_type: AggregateSignatureType,
    mithril_era: SupportedEra,
}

impl<'a> CertificateChainBuilder<'a> {
    /// Create a new [CertificateChainBuilder] instance.
    pub fn new() -> Self {
        let protocol_parameters = ProtocolParameters {
            m: 100,
            k: 5,
            phi_f: 0.65,
        };
        Self {
            total_certificates: 5,
            certificates_per_epoch: 1,
            protocol_parameters,
            total_signers_per_epoch_processor: &|epoch| min(2 + *epoch as usize, 5),
            genesis_certificate_processor: &|certificate, _, _| certificate,
            standard_certificate_processor: &|certificate, _| certificate,
            certificate_chaining_method: CertificateChainingMethod::default(),
            aggregate_signature_type: AggregateSignatureType::default(),
            mithril_era: *SupportedEra::eras().first().unwrap(),
        }
    }

    /// Set the total number of certificates to generate.
    pub fn with_total_certificates(mut self, total_certificates: u64) -> Self {
        self.total_certificates = total_certificates;

        self
    }

    /// Set the number of certificates per epoch.
    pub fn with_certificates_per_epoch(mut self, certificates_per_epoch: u64) -> Self {
        self.certificates_per_epoch = certificates_per_epoch;

        self
    }

    /// Set the protocol parameters.
    pub fn with_protocol_parameters(mut self, protocol_parameters: ProtocolParameters) -> Self {
        self.protocol_parameters = protocol_parameters;

        self
    }

    /// Set the total signers per epoch processor.
    pub fn with_total_signers_per_epoch_processor(
        mut self,
        total_signers_per_epoch_processor: &'a TotalSignersPerEpochProcessorFunc,
    ) -> Self {
        self.total_signers_per_epoch_processor = total_signers_per_epoch_processor;

        self
    }

    /// Set the genesis certificate processor.
    pub fn with_genesis_certificate_processor(
        mut self,
        genesis_certificate_processor: &'a GenesisCertificateProcessorFunc,
    ) -> Self {
        self.genesis_certificate_processor = genesis_certificate_processor;

        self
    }

    /// Set the standard certificate processor.
    pub fn with_standard_certificate_processor(
        mut self,
        standard_certificate_processor: &'a StandardCertificateProcessorFunc,
    ) -> Self {
        self.standard_certificate_processor = standard_certificate_processor;

        self
    }

    /// Set the chaining method to use when building the certificate chain.
    pub fn with_certificate_chaining_method(
        mut self,
        certificate_chaining_method: CertificateChainingMethod,
    ) -> Self {
        self.certificate_chaining_method = certificate_chaining_method;

        self
    }

    /// Set the aggregate signature type to use when building the certificate chain.
    pub fn with_aggregate_signature_type(
        mut self,
        aggregate_signature_type: AggregateSignatureType,
    ) -> Self {
        self.aggregate_signature_type = aggregate_signature_type;

        self
    }

    /// Set the Mithril era to use for genesis certificate creation.
    pub fn with_mithril_era(mut self, mithril_era: SupportedEra) -> Self {
        self.mithril_era = mithril_era;

        self
    }

    /// Build the certificate chain.
    pub fn build(self) -> CertificateChainFixture {
        let (genesis_signer, genesis_verifier) = CertificateChainBuilder::setup_genesis();
        let genesis_certificate_processor = self.genesis_certificate_processor;
        let standard_certificate_processor = self.standard_certificate_processor;
        let total_certificates = self.total_certificates as usize;
        let fixtures_per_epoch = self.build_fixtures_for_epochs();
        let certificates = self.build_certificate_index_and_epoch_sequence()
            .map(|(index_certificate, epoch)| {
                let fixture = fixtures_per_epoch.get(&epoch).unwrap_or_else(|| panic!("Fixture not found at epoch {epoch:?} with {} total certificates and {} certificates per epoch", self.total_certificates, self.certificates_per_epoch));
                let next_fixture = fixtures_per_epoch.get(&epoch.next()).unwrap_or_else(|| panic!("Next fixture not found at epoch {epoch:?} with {} total certificates and {} certificates per epoch", self.total_certificates, self.certificates_per_epoch));
                let context = CertificateChainBuilderContext::new(
                    index_certificate,
                    total_certificates,
                    epoch,
                    fixture,
                    next_fixture,
                );
                match index_certificate {
                    0 => genesis_certificate_processor(
                        self.build_genesis_certificate(&context, &genesis_signer, self.mithril_era),
                        &context,
                        &genesis_signer,
                    ),
                    _ => standard_certificate_processor(
                        self.build_standard_certificate(&context),
                        &context,
                    ),
                }
            })
            .collect::<Vec<Certificate>>();
        let certificates_chained = self.compute_chained_certificates(certificates);

        CertificateChainFixture {
            certificates_chained,
            genesis_verifier,
        }
    }

    fn compute_clerk_for_signers(signers: &[SignerFixture]) -> ProtocolClerk {
        let first_signer = &signers[0].protocol_signer;

        ProtocolClerk::new_clerk_from_signer(first_signer)
    }

    fn setup_genesis() -> (GenesisSigner, GenesisVerifier) {
        let genesis_signer = GenesisSigner::create_deterministic_signer();
        let genesis_verifier = genesis_signer.create_verifier();

        (genesis_signer, genesis_verifier)
    }

    fn build_epochs_sequence(&self) -> impl Iterator<Item = Epoch> + use<> {
        let total_certificates = self.total_certificates;
        let certificates_per_epoch = self.certificates_per_epoch;
        assert!(
            certificates_per_epoch > 0,
            "Certificates per epoch must be greater than 0"
        );
        assert!(
            total_certificates >= certificates_per_epoch,
            "Total certificates must be greater or equal to certificates per epoch"
        );
        // The total number of epochs in the sequence is the total number of standard certificates (total number of certificates minus one genesis certificate)
        // divided by the number of certificates per epoch plus two (one for the genesis epoch and one to compute the next fixtures of the last epoch)
        const TOTAL_GENESIS_CERTIFICATES: u64 = 1;
        const TOTAL_EXTRA_EPOCHS_FOR_FIXTURES_COMPUTATION: u64 = 1;
        let total_epochs_in_sequence = (total_certificates - TOTAL_GENESIS_CERTIFICATES)
            .div_ceil(certificates_per_epoch)
            + TOTAL_GENESIS_CERTIFICATES
            + TOTAL_EXTRA_EPOCHS_FOR_FIXTURES_COMPUTATION;
        (1..=total_epochs_in_sequence).map(Epoch)
    }

    fn build_certificate_index_and_epoch_sequence(
        &self,
    ) -> impl Iterator<Item = (usize, Epoch)> + use<> {
        let total_certificates = self.total_certificates as usize;
        let certificates_per_epoch = self.certificates_per_epoch as usize;

        self.build_epochs_sequence()
            .flat_map(move |epoch| {
                let repeat_epoch = if epoch == 1 {
                    // No need to repeat with the genesis epoch
                    1
                } else {
                    certificates_per_epoch
                };
                repeat_n(Epoch(*epoch), repeat_epoch)
            })
            .take(total_certificates)
            .enumerate()
    }

    fn build_fixtures_for_epochs(&self) -> HashMap<Epoch, MithrilFixture> {
        self.build_epochs_sequence()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|epoch| {
                let total_signers = (self.total_signers_per_epoch_processor)(epoch);
                let protocol_parameters = self.protocol_parameters.to_owned().into();
                (
                    epoch,
                    MithrilFixtureBuilder::default()
                        .with_protocol_parameters(protocol_parameters)
                        .with_signers(total_signers)
                        .build(),
                )
            })
            .collect::<HashMap<_, _>>()
    }

    fn build_base_certificate(&self, context: &CertificateChainBuilderContext) -> Certificate {
        let index_certificate = context.index_certificate;
        let epoch = context.epoch;
        let certificate_hash = format!("certificate_hash-{index_certificate}");
        let avk = context.fixture.compute_aggregate_verification_key();
        let protocol_parameters = context.fixture.protocol_parameters().to_owned();
        let base_certificate = fake_data::certificate(certificate_hash);
        let protocol_message = context.compute_protocol_message_seed();
        let signed_message = protocol_message.compute_hash();

        Certificate {
            epoch,
            aggregate_verification_key: avk
                .to_concatenation_aggregate_verification_key()
                .to_owned()
                .into(),
            #[cfg(feature = "snark")]
            aggregate_verification_key_snark: avk
                .to_snark_aggregate_verification_key()
                .map(|snark_avk| snark_avk.to_owned().into()),
            previous_hash: "".to_string(),
            protocol_message,
            signed_message,
            metadata: CertificateMetadata {
                protocol_parameters,
                ..base_certificate.metadata
            },
            ..base_certificate
        }
    }

    fn build_genesis_certificate(
        &self,
        context: &CertificateChainBuilderContext,
        genesis_signer: &GenesisSigner,
        mithril_era: SupportedEra,
    ) -> Certificate {
        let epoch = context.epoch;
        let certificate = self.build_base_certificate(context);
        let next_avk = context.next_fixture.compute_aggregate_verification_key();
        let next_protocol_parameters = &context.next_fixture.protocol_parameters();
        let genesis_producer = CertificateGenesisProducer::new();

        let genesis_protocol_message = genesis_producer
            .create_genesis_protocol_message(
                next_protocol_parameters,
                &next_avk,
                &epoch,
                mithril_era,
            )
            .unwrap();
        let signature = genesis_signer
            .sign_deterministic(&genesis_protocol_message, mithril_era)
            .unwrap();

        match signature {
            CertificateSignature::GenesisSignature(genesis_signature) => genesis_producer
                .create_legacy_genesis_certificate(
                    certificate.metadata.protocol_parameters,
                    certificate.metadata.network,
                    certificate.epoch,
                    next_avk,
                    genesis_signature,
                    mithril_era,
                ),
            #[cfg(feature = "snark")]
            CertificateSignature::GenesisDualSignature(
                genesis_signature,
                genesis_signature_snark,
            ) => genesis_producer.create_genesis_certificate(
                certificate.metadata.protocol_parameters,
                certificate.metadata.network,
                certificate.epoch,
                next_avk,
                genesis_signature,
                genesis_signature_snark,
                mithril_era,
            ),
            CertificateSignature::MultiSignature(..) => {
                unreachable!("the genesis signer never produces a multi-signature")
            }
        }
        .unwrap()
    }

    fn build_standard_certificate(&self, context: &CertificateChainBuilderContext) -> Certificate {
        let fixture = context.fixture;
        let mut certificate = self.build_base_certificate(context);
        certificate.metadata.signers = fixture.stake_distribution_parties();
        let mut protocol_message = certificate.protocol_message.clone();
        protocol_message.set_message_part(
            ProtocolMessagePartKey::SnapshotDigest,
            format!("digest-{}", context.index_certificate),
        );
        certificate.protocol_message = protocol_message;
        certificate.signed_message = certificate.protocol_message.compute_hash();
        let single_signatures = fixture
            .signers_fixture()
            .iter()
            .filter_map(|s| s.protocol_signer.sign(certificate.signed_message.as_bytes()))
            .collect::<Vec<_>>();
        let clerk = CertificateChainBuilder::compute_clerk_for_signers(&fixture.signers_fixture());
        let (multi_signature, _ancillary_proof_output) = clerk
            .aggregate_signatures_with_type(
                &single_signatures,
                certificate.signed_message.as_bytes(),
                self.aggregate_signature_type,
                AncillaryProofInput::dummy(),
            )
            .unwrap();
        certificate.signature = CertificateSignature::MultiSignature(
            SignedEntityType::CardanoDatabase(CardanoDbBeacon::new(
                *context.epoch,
                context.index_certificate as u64,
            )),
            multi_signature.into(),
        );

        certificate
    }

    fn update_certificate_previous_hash(
        &self,
        certificate: Certificate,
        previous_certificate: Option<&Certificate>,
    ) -> Certificate {
        let mut certificate = certificate;
        certificate.previous_hash =
            previous_certificate.map(|c| c.hash.to_string()).unwrap_or_default();
        certificate.hash = certificate.try_compute_hash().unwrap();

        certificate
    }

    fn fetch_previous_certificate_from_chain<'b>(
        &self,
        certificate: &Certificate,
        certificates_chained: &'b [Certificate],
    ) -> Option<&'b Certificate> {
        match self.certificate_chaining_method {
            CertificateChainingMethod::ToMasterCertificate => {
                let is_certificate_first_of_epoch = certificates_chained
                    .last()
                    .map(|c| c.epoch != certificate.epoch)
                    .unwrap_or(true);

                certificates_chained.iter().rev().rfind(|c| {
                    if is_certificate_first_of_epoch {
                        // The previous certificate of the first certificate of an epoch
                        // is the first certificate of the previous epoch
                        c.epoch == certificate.epoch.previous().unwrap()
                    } else {
                        // The previous certificate of not the first certificate of an epoch
                        // is the first certificate of the epoch
                        c.epoch == certificate.epoch
                    }
                })
            }
            CertificateChainingMethod::Sequential => certificates_chained.last(),
        }
    }

    // Returns the chained certificates in reverse order
    // The latest certificate of the chain is the first in the vector
    fn compute_chained_certificates(&self, certificates: Vec<Certificate>) -> Vec<Certificate> {
        let mut certificates_chained: Vec<Certificate> =
            certificates
                .into_iter()
                .fold(Vec::new(), |mut certificates_chained, certificate| {
                    let previous_certificate_maybe = self
                        .fetch_previous_certificate_from_chain(&certificate, &certificates_chained);
                    let certificate = self
                        .update_certificate_previous_hash(certificate, previous_certificate_maybe);
                    certificates_chained.push(certificate);

                    certificates_chained
                });
        certificates_chained.reverse();

        certificates_chained
    }
}

impl Default for CertificateChainBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use super::*;

    fn build_epoch_numbers_sequence(
        total_certificates: u64,
        certificates_per_epoch: u64,
    ) -> Vec<u64> {
        CertificateChainBuilder::default()
            .with_total_certificates(total_certificates)
            .with_certificates_per_epoch(certificates_per_epoch)
            .build_epochs_sequence()
            .map(|epoch| *epoch)
            .collect()
    }

    fn build_certificate_index_and_epoch_numbers_sequence(
        total_certificates: u64,
        certificates_per_epoch: u64,
    ) -> Vec<(usize, u64)> {
        CertificateChainBuilder::default()
            .with_total_certificates(total_certificates)
            .with_certificates_per_epoch(certificates_per_epoch)
            .build_certificate_index_and_epoch_sequence()
            .map(|(certificate_index, epoch)| (certificate_index, *epoch))
            .collect()
    }

    fn build_epoch_numbers_sequence_in_certificate_chain(
        total_certificates: u64,
        certificates_per_epoch: u64,
    ) -> Vec<u64> {
        build_certificate_index_and_epoch_numbers_sequence(
            total_certificates,
            certificates_per_epoch,
        )
        .iter()
        .map(|(_certificate_index, epoch)| *epoch)
        .collect()
    }

    #[test]
    fn certificate_chain_builder_context_computes_correct_protocol_message_seed() {
        let protocol_parameters = ProtocolParameters {
            m: 123,
            k: 45,
            phi_f: 0.67,
        };
        let next_protocol_parameters = ProtocolParameters {
            m: 100,
            k: 10,
            phi_f: 0.10,
        };
        let fixture = MithrilFixtureBuilder::default()
            .with_protocol_parameters(protocol_parameters.into())
            .with_signers(2)
            .build();
        let next_fixture = MithrilFixtureBuilder::default()
            .with_protocol_parameters(next_protocol_parameters.into())
            .with_signers(3)
            .build();
        let context = CertificateChainBuilderContext {
            index_certificate: 2,
            total_certificates: 5,
            epoch: Epoch(1),
            fixture: &fixture,
            next_fixture: &next_fixture,
        };
        let expected_next_avk_part_value =
            next_fixture.compute_and_encode_concatenation_aggregate_verification_key();
        let expected_next_protocol_parameters_part_value =
            next_fixture.protocol_parameters().compute_hash();

        let expected_current_epoch_part_value = context.epoch.to_string();

        let protocol_message = context.compute_protocol_message_seed();

        let mut expected_protocol_message = ProtocolMessage::new();
        expected_protocol_message.set_message_part(
            ProtocolMessagePartKey::NextAggregateVerificationKey,
            expected_next_avk_part_value,
        );
        #[cfg(feature = "snark")]
        if let Some(snark_avk) = next_fixture.compute_and_encode_snark_aggregate_verification_key()
        {
            expected_protocol_message.set_message_part(
                ProtocolMessagePartKey::NextSnarkAggregateVerificationKey,
                snark_avk,
            );
        }
        expected_protocol_message.set_message_part(
            ProtocolMessagePartKey::NextProtocolParameters,
            expected_next_protocol_parameters_part_value,
        );
        expected_protocol_message.set_message_part(
            ProtocolMessagePartKey::CurrentEpoch,
            expected_current_epoch_part_value,
        );

        assert_eq!(expected_protocol_message, protocol_message);
    }

    #[test]
    fn certificate_chain_builder_context_checks_correctly_if_certificate_is_last() {
        let fixture = MithrilFixtureBuilder::default().with_signers(2).build();
        let context = CertificateChainBuilderContext {
            index_certificate: 4,
            total_certificates: 5,
            epoch: Epoch(1),
            fixture: &fixture,
            next_fixture: &fixture,
        };

        assert!(context.is_last_certificate());
    }

    #[test]
    fn built_chain_sequence_always_contains_exactly_the_requested_number_of_certificates() {
        assert_eq!(
            4,
            build_certificate_index_and_epoch_numbers_sequence(4, 1).len()
        );
        assert_eq!(
            4,
            build_certificate_index_and_epoch_numbers_sequence(4, 2).len()
        );
        assert_eq!(
            4,
            build_certificate_index_and_epoch_numbers_sequence(4, 3).len()
        );
        assert_eq!(
            4,
            build_certificate_index_and_epoch_numbers_sequence(4, 4).len()
        );
        assert_eq!(
            5,
            build_certificate_index_and_epoch_numbers_sequence(5, 1).len()
        );
        assert_eq!(
            5,
            build_certificate_index_and_epoch_numbers_sequence(5, 2).len()
        );
        assert_eq!(
            5,
            build_certificate_index_and_epoch_numbers_sequence(5, 3).len()
        );
        assert_eq!(
            7,
            build_certificate_index_and_epoch_numbers_sequence(7, 3).len()
        );
        assert_eq!(
            15,
            build_certificate_index_and_epoch_numbers_sequence(15, 3).len()
        );
    }

    #[test]
    fn epoch_sequence_includes_two_extra_epochs_one_for_the_genesis_certificate_and_one_for_last_next_avk_computation()
     {
        assert_eq!(vec![1, 2, 3, 4], build_epoch_numbers_sequence(3, 1));
        assert_eq!(vec![1, 2, 3, 4], build_epoch_numbers_sequence(4, 2));
        assert_eq!(vec![1, 2, 3, 4], build_epoch_numbers_sequence(5, 2));
        assert_eq!(vec![1, 2, 3, 4], build_epoch_numbers_sequence(7, 3),);
        assert_eq!(
            vec![1, 2, 3, 4, 5, 6, 7],
            build_epoch_numbers_sequence(15, 3),
        );
    }

    #[test]
    fn certificates_in_chain_are_grouped_under_the_right_epoch() {
        assert_eq!(
            vec![1, 2, 3],
            build_epoch_numbers_sequence_in_certificate_chain(3, 1)
        );
        assert_eq!(
            vec![1, 2, 2, 3],
            build_epoch_numbers_sequence_in_certificate_chain(4, 2)
        );
        assert_eq!(
            vec![1, 2, 2, 3, 3],
            build_epoch_numbers_sequence_in_certificate_chain(5, 2)
        );
        assert_eq!(
            vec![1, 2, 2, 2, 3, 3, 3],
            build_epoch_numbers_sequence_in_certificate_chain(7, 3),
        );
        assert_eq!(
            vec![1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6],
            build_epoch_numbers_sequence_in_certificate_chain(15, 3),
        );
    }

    #[test]
    #[should_panic]
    fn epoch_sequence_panics_when_certificates_per_epoch_is_zero() {
        build_epoch_numbers_sequence(3, 0);
    }

    #[test]
    #[should_panic]
    fn epoch_sequence_panics_when_certificates_per_epoch_exceeds_total_certificates() {
        build_epoch_numbers_sequence(3, 5);
    }

    #[test]
    fn builds_valid_fixtures_per_epochs() {
        let expected_total_signers = (1..=6).collect::<Vec<_>>();
        let certificate_chain_builder = CertificateChainBuilder::default()
            .with_total_certificates(5)
            .with_certificates_per_epoch(1)
            .with_total_signers_per_epoch_processor(&|epoch| *epoch as usize);

        let epoch_fixtures =
            BTreeMap::from_iter(certificate_chain_builder.build_fixtures_for_epochs());

        let total_signers = epoch_fixtures
            .into_values()
            .map(|fixture| fixture.signers().len())
            .collect::<Vec<_>>();
        assert_eq!(expected_total_signers, total_signers);
    }

    #[test]
    fn builds_valid_genesis_certificate() {
        let expected_protocol_parameters = ProtocolParameters {
            m: 123,
            k: 45,
            phi_f: 0.67,
        };
        let fixture = MithrilFixtureBuilder::default()
            .with_protocol_parameters(expected_protocol_parameters.into())
            .with_signers(2)
            .build();
        let next_fixture = MithrilFixtureBuilder::default()
            .with_protocol_parameters(expected_protocol_parameters.into())
            .with_signers(3)
            .build();
        let context = CertificateChainBuilderContext {
            index_certificate: 0,
            total_certificates: 5,
            epoch: Epoch(1),
            fixture: &fixture,
            next_fixture: &next_fixture,
        };
        let expected_protocol_message_legacy = context.compute_protocol_message_seed();
        let (protocol_genesis_signer, _) = CertificateChainBuilder::setup_genesis();

        let mithril_era = if cfg!(feature = "snark") {
            SupportedEra::Lagrange
        } else {
            SupportedEra::Pythagoras
        };
        let genesis_certificate = CertificateChainBuilder::default()
            .with_protocol_parameters(expected_protocol_parameters)
            .build_genesis_certificate(&context, &protocol_genesis_signer, mithril_era);

        let expected_protocol_message = match mithril_era {
            SupportedEra::Pythagoras => expected_protocol_message_legacy,
            #[cfg(feature = "snark")]
            SupportedEra::Lagrange => {
                let mut message = ProtocolMessage::new_rigid();
                for (key, value) in &expected_protocol_message_legacy.message_parts {
                    message.set_message_part(*key, value.clone());
                }
                message
            }
            #[cfg(not(feature = "snark"))]
            SupportedEra::Lagrange => expected_protocol_message_legacy,
        };
        let expected_signed_message = expected_protocol_message.compute_hash();

        assert!(genesis_certificate.is_genesis());
        assert_eq!(
            SignedEntityType::genesis(Epoch(1)),
            genesis_certificate.signed_entity_type()
        );
        assert_eq!(Epoch(1), genesis_certificate.epoch);
        assert_eq!(
            expected_protocol_parameters,
            genesis_certificate.metadata.protocol_parameters.into()
        );
        assert_eq!(0, genesis_certificate.metadata.signers.len());
        assert_eq!(
            expected_protocol_message,
            genesis_certificate.protocol_message
        );
        assert_eq!(expected_signed_message, genesis_certificate.signed_message);
    }

    #[test]
    fn builds_valid_standard_certificate() {
        let expected_protocol_parameters = ProtocolParameters {
            m: 123,
            k: 45,
            phi_f: 0.67,
        };
        let fixture = MithrilFixtureBuilder::default()
            .with_protocol_parameters(expected_protocol_parameters.into())
            .with_signers(2)
            .build();
        let next_fixture = MithrilFixtureBuilder::default()
            .with_protocol_parameters(expected_protocol_parameters.into())
            .with_signers(3)
            .build();
        let avk = fixture.compute_and_encode_concatenation_aggregate_verification_key();
        let context = CertificateChainBuilderContext {
            index_certificate: 2,
            total_certificates: 5,
            epoch: Epoch(1),
            fixture: &fixture,
            next_fixture: &next_fixture,
        };
        let mut expected_protocol_message = context.compute_protocol_message_seed();
        expected_protocol_message.set_message_part(
            ProtocolMessagePartKey::SnapshotDigest,
            format!("digest-{}", context.index_certificate),
        );
        let expected_signed_message = expected_protocol_message.compute_hash();

        let standard_certificate = CertificateChainBuilder::default()
            .with_protocol_parameters(expected_protocol_parameters)
            .build_standard_certificate(&context);

        assert!(!standard_certificate.is_genesis());
        assert_eq!(
            SignedEntityType::CardanoDatabase(CardanoDbBeacon::new(1, 2)),
            standard_certificate.signed_entity_type()
        );
        assert_eq!(Epoch(1), standard_certificate.epoch);
        assert_eq!(
            expected_protocol_parameters,
            standard_certificate.metadata.protocol_parameters.into()
        );
        assert_eq!(2, standard_certificate.metadata.signers.len());
        assert_eq!(
            expected_protocol_message,
            standard_certificate.protocol_message
        );
        assert_eq!(expected_signed_message, standard_certificate.signed_message);
        assert_eq!(
            avk,
            standard_certificate.aggregate_verification_key.to_json_hex().unwrap()
        );
    }

    #[test]
    fn master_chaining_links_each_certificate_to_the_first_certificate_of_its_epoch() {
        fn create_fake_certificate(epoch: Epoch, index_in_epoch: u64) -> Certificate {
            Certificate {
                epoch,
                signed_message: format!("certificate-{}-{index_in_epoch}", *epoch),
                ..fake_data::certificate("cert-fake".to_string())
            }
        }

        let certificates = vec![
            create_fake_certificate(Epoch(1), 1),
            create_fake_certificate(Epoch(2), 1),
            create_fake_certificate(Epoch(2), 2),
            create_fake_certificate(Epoch(3), 1),
            create_fake_certificate(Epoch(4), 1),
            create_fake_certificate(Epoch(4), 2),
            create_fake_certificate(Epoch(4), 3),
        ];

        let mut certificates_chained =
            CertificateChainBuilder::default().compute_chained_certificates(certificates);
        certificates_chained.reverse();

        let certificate_chained_1_1 = &certificates_chained[0];
        let certificate_chained_2_1 = &certificates_chained[1];
        let certificate_chained_2_2 = &certificates_chained[2];
        let certificate_chained_3_1 = &certificates_chained[3];
        let certificate_chained_4_1 = &certificates_chained[4];
        let certificate_chained_4_2 = &certificates_chained[5];
        let certificate_chained_4_3 = &certificates_chained[6];
        assert_eq!("", certificate_chained_1_1.previous_hash);
        assert_eq!(
            certificate_chained_2_1.previous_hash,
            certificate_chained_1_1.hash
        );
        assert_eq!(
            certificate_chained_2_2.previous_hash,
            certificate_chained_2_1.hash
        );
        assert_eq!(
            certificate_chained_3_1.previous_hash,
            certificate_chained_2_1.hash
        );
        assert_eq!(
            certificate_chained_4_1.previous_hash,
            certificate_chained_3_1.hash
        );
        assert_eq!(
            certificate_chained_4_2.previous_hash,
            certificate_chained_4_1.hash
        );
        assert_eq!(
            certificate_chained_4_3.previous_hash,
            certificate_chained_4_1.hash
        );
    }

    #[test]
    fn sequential_chaining_links_each_certificate_to_its_immediate_predecessor() {
        fn create_fake_certificate(epoch: Epoch, index_in_epoch: u64) -> Certificate {
            Certificate {
                epoch,
                signed_message: format!("certificate-{}-{index_in_epoch}", *epoch),
                ..fake_data::certificate("cert-fake".to_string())
            }
        }

        let certificates = vec![
            create_fake_certificate(Epoch(1), 1),
            create_fake_certificate(Epoch(2), 1),
            create_fake_certificate(Epoch(2), 2),
            create_fake_certificate(Epoch(3), 1),
            create_fake_certificate(Epoch(4), 1),
            create_fake_certificate(Epoch(4), 2),
            create_fake_certificate(Epoch(4), 3),
        ];

        let mut certificates_chained = CertificateChainBuilder::default()
            .with_certificate_chaining_method(CertificateChainingMethod::Sequential)
            .compute_chained_certificates(certificates);
        certificates_chained.reverse();

        let certificate_chained_1_1 = &certificates_chained[0];
        let certificate_chained_2_1 = &certificates_chained[1];
        let certificate_chained_2_2 = &certificates_chained[2];
        let certificate_chained_3_1 = &certificates_chained[3];
        let certificate_chained_4_1 = &certificates_chained[4];
        let certificate_chained_4_2 = &certificates_chained[5];
        let certificate_chained_4_3 = &certificates_chained[6];
        assert_eq!("", certificate_chained_1_1.previous_hash);
        assert_eq!(
            certificate_chained_2_1.previous_hash,
            certificate_chained_1_1.hash
        );
        assert_eq!(
            certificate_chained_2_2.previous_hash,
            certificate_chained_2_1.hash
        );
        assert_eq!(
            certificate_chained_3_1.previous_hash,
            certificate_chained_2_2.hash
        );
        assert_eq!(
            certificate_chained_4_1.previous_hash,
            certificate_chained_3_1.hash
        );
        assert_eq!(
            certificate_chained_4_2.previous_hash,
            certificate_chained_4_1.hash
        );
        assert_eq!(
            certificate_chained_4_3.previous_hash,
            certificate_chained_4_2.hash
        );
    }

    #[test]
    fn builds_certificate_chain_with_alteration_on_genesis_certificate() {
        let certificate_chain_fixture = CertificateChainBuilder::new()
            .with_total_certificates(5)
            .with_genesis_certificate_processor(&|certificate, _, _| {
                let mut certificate = certificate;
                certificate.signed_message = "altered_msg".to_string();

                certificate
            })
            .build();

        assert_eq!(
            "altered_msg".to_string(),
            certificate_chain_fixture.last().unwrap().signed_message
        );
    }

    #[test]
    fn builds_certificate_chain_with_alteration_on_standard_certificates() {
        let total_certificates = 5;
        let expected_signed_messages = (1..total_certificates)
            .rev()
            .map(|i| format!("altered-msg-{i}"))
            .collect::<Vec<_>>();

        let certificate_chain_fixture = CertificateChainBuilder::new()
            .with_total_certificates(total_certificates)
            .with_standard_certificate_processor(&|certificate, context| {
                let mut certificate = certificate;
                certificate.signed_message = format!("altered-msg-{}", context.index_certificate);

                certificate
            })
            .build();

        let signed_message = certificate_chain_fixture
            .certificates_chained
            .into_iter()
            .take(total_certificates as usize - 1)
            .map(|certificate| certificate.signed_message)
            .collect::<Vec<_>>();
        assert_eq!(expected_signed_messages, signed_message);
    }

    mod certificate_chain_fixture {
        use super::*;

        #[test]
        fn genesis_certificate_is_always_the_last_element_of_the_chain() {
            let chain_with_only_a_genesis =
                CertificateChainBuilder::new().with_total_certificates(1).build();
            assert!(chain_with_only_a_genesis.genesis_certificate().is_genesis());

            let chain_with_multiple_certificates =
                CertificateChainBuilder::new().with_total_certificates(3).build();
            assert!(chain_with_multiple_certificates.genesis_certificate().is_genesis());
        }

        #[test]
        fn latest_certificate_is_the_first_element_of_the_chain() {
            let chain_with_only_a_genesis =
                CertificateChainBuilder::new().with_total_certificates(1).build();
            assert!(chain_with_only_a_genesis.latest_certificate().is_genesis());

            let chain_with_multiple_certificates =
                CertificateChainBuilder::new().with_total_certificates(3).build();
            assert_eq!(
                chain_with_multiple_certificates.latest_certificate(),
                chain_with_multiple_certificates.first().unwrap()
            );
        }

        #[test]
        fn path_to_genesis_traverses_the_full_chain_when_one_certificate_per_epoch() {
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(5)
                .with_certificates_per_epoch(1)
                .build();

            assert_eq!(
                chain.certificate_path_to_genesis(&chain[0].hash),
                chain.certificates_chained
            );
        }

        #[test]
        fn path_to_genesis_skips_sibling_certificates_of_the_same_epoch() {
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(9)
                .with_certificates_per_epoch(3)
                .build();

            let expected_subchain =
                vec![chain[1].clone(), chain[4].clone(), chain[7].clone(), chain[8].clone()];
            assert_eq!(
                chain.certificate_path_to_genesis(&chain[1].hash),
                expected_subchain
            );
        }

        #[test]
        fn reversed_chain_returns_certificates_from_genesis_to_latest() {
            let chain = CertificateChainBuilder::new()
                .with_total_certificates(5)
                .with_certificates_per_epoch(2)
                .build();

            let expected: Vec<Certificate> =
                chain.certificates_chained.clone().into_iter().rev().collect();
            assert_eq!(chain.reversed_chain(), expected);
            assert!(chain.reversed_chain()[0].is_genesis());
        }
    }
}
