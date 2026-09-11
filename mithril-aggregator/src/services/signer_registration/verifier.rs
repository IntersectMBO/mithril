use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;

use mithril_cardano_node_chain::chain_observer::ChainObserver;
#[cfg(feature = "future_snark")]
use mithril_common::entities::Epoch;
use mithril_common::{
    StdResult,
    crypto_helper::{ProtocolKeyRegistration, SignerRegistrationParameters},
    entities::{Signer, SignerWithStake, StakeDistribution},
};

use super::SignerRegistrationVerifier;

/// Implementation of a [SignerRegistrationVerifier]
pub struct MithrilSignerRegistrationVerifier {
    /// Chain observer service.
    chain_observer: Arc<dyn ChainObserver>,
}

impl MithrilSignerRegistrationVerifier {
    /// Creates a new [MithrilSignerRegistrationVerifier].
    pub fn new(chain_observer: Arc<dyn ChainObserver>) -> Self {
        Self { chain_observer }
    }
}

#[async_trait]
impl SignerRegistrationVerifier for MithrilSignerRegistrationVerifier {
    async fn verify(
        &self,
        signer: &Signer,
        stake_distribution: &StakeDistribution,
        #[cfg(feature = "future_snark")] epoch: Epoch,
    ) -> StdResult<SignerWithStake> {
        let mut key_registration = ProtocolKeyRegistration::init(
            &stake_distribution
                .iter()
                .map(|(k, v)| (k.to_owned(), *v))
                .collect::<Vec<_>>(),
        );
        let party_id_register = match signer.party_id.as_str() {
            "" => None,
            party_id => Some(party_id.to_string()),
        };
        let kes_evolutions = match &signer.operational_certificate {
            Some(operational_certificate) => Some(
                self.chain_observer
                    .get_current_kes_period()
                    .await?
                    .unwrap_or_default()
                    - operational_certificate.get_start_kes_period(),
            ),
            None => None,
        };
        let party_id_registered = key_registration
            .register(SignerRegistrationParameters {
                party_id: party_id_register.clone(),
                operational_certificate: signer.operational_certificate.clone(),
                verification_key_signature_for_concatenation: signer
                    .verification_key_signature_for_concatenation,
                kes_evolutions,
                verification_key_for_concatenation: signer.verification_key_for_concatenation,
                #[cfg(feature = "future_snark")]
                verification_key_for_snark: signer.verification_key_for_snark,
                #[cfg(feature = "future_snark")]
                verification_key_signature_for_snark: signer.verification_key_signature_for_snark,
                #[cfg(feature = "future_snark")]
                proof_of_bound_possession_for_snark: signer.proof_of_bound_possession_for_snark,
            },
            #[cfg(feature = "future_snark")] 
            epoch,
        )
            .with_context(|| {
                format!(
                    "KeyRegwrapper can not register signer with party_id: '{party_id_register:?}', kes_evolutions: '{kes_evolutions:?}'"
                )
            })?;
        let party_id_registered_stake = *stake_distribution
            .get(&party_id_registered)
            .with_context(|| format!("Stake not found for party_id: '{party_id_registered}"))?;

        Ok(SignerWithStake {
            party_id: party_id_registered,
            ..SignerWithStake::from_signer(signer.to_owned(), party_id_registered_stake)
        })
    }
}

#[cfg(test)]
mod tests {
    use mithril_cardano_node_chain::test::double::FakeChainObserver;
    use mithril_common::{
        entities::TimePoint,
        test::{builder::MithrilFixtureBuilder, double::Dummy},
    };

    use super::*;

    #[tokio::test]
    async fn verify_succeeds_with_valid_signer_registration() {
        let fixture = MithrilFixtureBuilder::default().with_signers(1).build();
        let signer_to_register: Signer = fixture.signers()[0].to_owned();
        let signer_registration_verifier = MithrilSignerRegistrationVerifier::new(Arc::new(
            FakeChainObserver::new(Some(TimePoint::dummy())),
        ));

        signer_registration_verifier
            .verify(
                &signer_to_register,
                &fixture.stake_distribution(),
                #[cfg(feature = "future_snark")]
                Epoch::default(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn verify_fails_with_invalid_signer_registration() {
        let fixture = MithrilFixtureBuilder::default().with_signers(2).build();
        let signer_to_register: Signer = Signer {
            verification_key_signature_for_concatenation: fixture.signers()[1]
                .verification_key_signature_for_concatenation,
            ..fixture.signers()[0].to_owned()
        };
        let signer_registration_verifier = MithrilSignerRegistrationVerifier::new(Arc::new(
            FakeChainObserver::new(Some(TimePoint::dummy())),
        ));

        signer_registration_verifier
            .verify(
                &signer_to_register,
                &fixture.stake_distribution(),
                #[cfg(feature = "future_snark")]
                Epoch::default(),
            )
            .await
            .expect_err("Verification should fail");
    }
}
