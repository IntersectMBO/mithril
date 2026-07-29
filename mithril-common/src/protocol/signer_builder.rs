use std::sync::Arc;

use anyhow::Context;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use thiserror::Error;

use crate::{
    StdResult,
    crypto_helper::{
        KesPeriod, KesSigner, ProtocolAggregateVerificationKey, ProtocolClerk,
        ProtocolClosedKeyRegistration, ProtocolInitializer, ProtocolKeyRegistration,
        ProtocolStakeDistribution, SignerRegistrationParameters,
    },
    entities::{PartyId, ProtocolParameters, SignerWithStake},
    protocol::MultiSigner,
};

use super::SingleSigner;

/// Allow to build Single Or Multi signers to generate a single signature or aggregate them
#[derive(Debug)]
pub struct SignerBuilder {
    protocol_parameters: ProtocolParameters,
    closed_key_registration: ProtocolClosedKeyRegistration,
}

/// [SignerBuilder] specific errors
#[derive(Debug, Error)]
pub enum SignerBuilderError {
    /// Error raised when the list of signers given to the builder is empty
    #[error("The list of signers must not be empty to create a signer builder.")]
    EmptySigners,
}

impl SignerBuilder {
    /// [SignerBuilder] constructor.
    pub fn new(
        registered_signers: &[SignerWithStake],
        protocol_parameters: &ProtocolParameters,
    ) -> StdResult<Self> {
        if registered_signers.is_empty() {
            return Err(SignerBuilderError::EmptySigners.into());
        }

        let stake_distribution = registered_signers
            .iter()
            .map(|s| s.into())
            .collect::<ProtocolStakeDistribution>();
        let mut key_registration = ProtocolKeyRegistration::init(&stake_distribution);

        for signer in registered_signers {
            key_registration
                .register(SignerRegistrationParameters {
                    party_id: Some(signer.party_id.to_owned()),
                    operational_certificate: signer.operational_certificate.clone(),
                    verification_key_signature_for_concatenation: signer
                        .verification_key_signature_for_concatenation,
                    kes_evolutions: signer.kes_evolutions,
                    verification_key_for_concatenation: signer.verification_key_for_concatenation,
                    #[cfg(feature = "future_snark")]
                    verification_key_for_snark: signer.verification_key_for_snark,
                    #[cfg(feature = "future_snark")]
                    verification_key_signature_for_snark: signer
                        .verification_key_signature_for_snark,
                })
                .with_context(|| {
                    format!("Registration failed for signer: '{}'", signer.party_id)
                })?;
        }

        let closed_registration = key_registration.close(&protocol_parameters.clone().into())?;

        Ok(Self {
            protocol_parameters: protocol_parameters.clone(),
            closed_key_registration: closed_registration,
        })
    }

    /// Build a [MultiSigner] based on the registered parties
    pub fn build_multi_signer(&self) -> MultiSigner {
        let stm_parameters = self.protocol_parameters.clone().into();
        let clerk = ProtocolClerk::new_clerk_from_closed_key_registration(
            &stm_parameters,
            &self.closed_key_registration,
        );

        MultiSigner::new(clerk, stm_parameters)
    }

    /// Compute aggregate verification key from stake distribution
    pub fn compute_aggregate_verification_key(&self) -> ProtocolAggregateVerificationKey {
        let stm_parameters = self.protocol_parameters.clone().into();
        let clerk = ProtocolClerk::new_clerk_from_closed_key_registration(
            &stm_parameters,
            &self.closed_key_registration,
        );

        clerk.compute_aggregate_verification_key()
    }

    fn build_single_signer_with_rng<R: RngCore + CryptoRng>(
        &self,
        signer_with_stake: SignerWithStake,
        kes_signer: Option<Arc<dyn KesSigner>>,
        rng: &mut R,
    ) -> StdResult<(SingleSigner, ProtocolInitializer)> {
        let protocol_initializer = ProtocolInitializer::setup(
            self.protocol_parameters.clone().into(),
            kes_signer,
            signer_with_stake
                .kes_evolutions
                .map(|kes_evolutions| KesPeriod(0) + kes_evolutions),
            signer_with_stake.stake,
            rng,
        )
        .with_context(|| {
            format!(
                "Could not create a protocol initializer for party: '{}'",
                signer_with_stake.party_id
            )
        })?;

        let protocol_signer = protocol_initializer
            .clone()
            .new_signer(self.closed_key_registration.clone())
            .with_context(|| {
                format!(
                    "Could not create a protocol signer for party: '{}'",
                    signer_with_stake.party_id
                )
            })?;

        Ok((
            SingleSigner::new(signer_with_stake.party_id, protocol_signer),
            protocol_initializer,
        ))
    }

    /// Build deterministic [SingleSigner] and [ProtocolInitializer] based on the registered parties.
    ///
    /// Use for **TEST ONLY**.
    pub fn build_test_single_signer(
        &self,
        signer_with_stake: SignerWithStake,
        kes_signer: Option<Arc<dyn KesSigner>>,
    ) -> StdResult<(SingleSigner, ProtocolInitializer)> {
        let protocol_initializer_seed: [u8; 32] =
            signer_with_stake.party_id.as_bytes()[..32].try_into().unwrap();

        self.build_single_signer_with_rng(
            signer_with_stake,
            kes_signer,
            &mut ChaCha20Rng::from_seed(protocol_initializer_seed),
        )
    }

    /// Restore a [SingleSigner] based on the registered parties and the given
    /// protocol_initializer.
    ///
    /// This is useful since each protocol initializer holds a unique secret key
    /// that corresponds to a registration key sent to an aggregator.
    ///
    /// The actual signing of message is done at a later epoch.
    ///
    /// The [SignerBuilder] used must be tied to the key registration, stake distribution
    /// and protocol parameters of the epoch during which the given protocol initializer
    /// was created.
    pub fn restore_signer_from_initializer(
        &self,
        party_id: PartyId,
        protocol_initializer: ProtocolInitializer,
    ) -> StdResult<SingleSigner> {
        let single_signer = protocol_initializer
            .new_signer(self.closed_key_registration.clone())
            .with_context(|| {
                "Could not create a single signer from protocol initializer".to_string()
            })?;

        Ok(SingleSigner::new(party_id, single_signer))
    }
}

#[cfg(test)]
mod test {
    use mithril_stm::RegisterError;

    use crate::{
        crypto_helper::KesSignerStandard,
        test::{builder::MithrilFixtureBuilder, double::fake_data},
    };

    use super::*;

    #[test]
    fn cant_construct_signer_builder_with_an_empty_signers_list() {
        let signers = vec![];
        let protocol_parameters = fake_data::protocol_parameters();

        let error = SignerBuilder::new(&signers, &protocol_parameters).expect_err(
            "We should not be able to construct a signer builder with an empty signers list",
        );

        match error.downcast_ref::<SignerBuilderError>() {
            Some(SignerBuilderError::EmptySigners) => (),
            _ => panic!("Expected an EmptySigners error, got: {error:?}"),
        }
    }

    #[test]
    fn cant_construct_signer_builder_if_a_signer_registration_fail() {
        // To make this test fail we try to build a SignerBuilder with signers from two
        // different stake distributions, this will pass the individual check but not the
        // register check.
        let fixture = MithrilFixtureBuilder::default().with_signers(3).build();
        let fixture_with_another_stake_distribution = MithrilFixtureBuilder::default()
            .with_signers(1)
            .with_stake_distribution(
                crate::test::builder::StakeDistributionGenerationMethod::RandomDistribution {
                    seed: [4u8; 32],
                    min_stake: 1,
                },
            )
            .build();
        let mut signers = fixture.signers_with_stake();
        signers.append(&mut fixture_with_another_stake_distribution.signers_with_stake());

        let error = SignerBuilder::new(&signers, &fixture.protocol_parameters()).expect_err(
            "We should not be able to construct a signer builder if a signer registration fail",
        );

        match error.downcast_ref::<RegisterError>() {
            Some(RegisterError::EntryAlreadyRegistered) => (),
            _ => panic!("Expected an CoreRegister error, got: {error:?}"),
        }
    }

    #[test]
    fn can_construct_signer_builder_with_valid_signers() {
        let fixture = MithrilFixtureBuilder::default().with_signers(3).build();

        SignerBuilder::new(
            &fixture.signers_with_stake(),
            &fixture.protocol_parameters(),
        )
        .expect("We should be able to construct a signer builder with valid signers");
    }

    #[test]
    fn cant_build_single_signer_for_unregistered_party() {
        let fixture = MithrilFixtureBuilder::default().with_signers(3).build();
        let signers_from_another_fixture = MithrilFixtureBuilder::default()
            .with_signers(1)
            .with_party_id_seed([4u8; 32])
            .build()
            .signers_fixture();
        let non_registered_signer = signers_from_another_fixture.first().unwrap();
        let kes_signer = Some(Arc::new(KesSignerStandard::new(
            non_registered_signer.kes_secret_key_path().unwrap().to_path_buf(),
            non_registered_signer
                .operational_certificate_path()
                .unwrap()
                .to_path_buf(),
        )) as Arc<dyn KesSigner>);

        let error = SignerBuilder::new(
            &fixture.signers_with_stake(),
            &fixture.protocol_parameters(),
        )
        .unwrap()
        .build_test_single_signer(non_registered_signer.signer_with_stake.clone(), kes_signer)
        .expect_err(
            "We should not be able to construct a single signer from a not registered party",
        );

        match error.downcast_ref::<RegisterError>() {
            Some(RegisterError::UnregisteredInitializer) => (),
            _ => panic!(
                "Expected an ProtocolRegistrationErrorWrapper::CoreRegister error, got: {error:?}"
            ),
        }
    }

    #[test]
    fn should_build_single_signer_for_registered_party() {
        let fixture = MithrilFixtureBuilder::default().with_signers(3).build();
        let signers = fixture.signers_fixture();
        let signer = signers.first().unwrap();
        let kes_signer = Some(Arc::new(KesSignerStandard::new(
            signer.kes_secret_key_path().unwrap().to_path_buf(),
            signer.operational_certificate_path().unwrap().to_path_buf(),
        )) as Arc<dyn KesSigner>);

        let builder = SignerBuilder::new(
            &fixture.signers_with_stake(),
            &fixture.protocol_parameters(),
        )
        .unwrap();

        builder
            .build_test_single_signer(signer.signer_with_stake.clone(), kes_signer)
            .expect("Should be able to build test single signer for a registered party");
    }

    #[test]
    fn should_restore_single_signer_from_previous_initializer() {
        let fixture = MithrilFixtureBuilder::default().with_signers(3).build();
        let signers = fixture.signers_fixture();
        let signer = signers.first().unwrap();
        let kes_signer = Some(Arc::new(KesSignerStandard::new(
            signer.kes_secret_key_path().unwrap().to_path_buf(),
            signer.operational_certificate_path().unwrap().to_path_buf(),
        )) as Arc<dyn KesSigner>);

        let first_builder = SignerBuilder::new(
            &fixture.signers_with_stake(),
            &fixture.protocol_parameters(),
        )
        .unwrap();

        let (_, initializer) = first_builder
            .build_test_single_signer(signer.signer_with_stake.clone(), kes_signer)
            .unwrap();

        let second_builder = SignerBuilder::new(
            &fixture.signers_with_stake(),
            &fixture.protocol_parameters(),
        )
        .unwrap();

        second_builder
            .restore_signer_from_initializer(signer.party_id(), initializer)
            .expect("Should be able to restore a single signer from a protocol initialized");
    }
}
