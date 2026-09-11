use async_trait::async_trait;

use mithril_common::{
    StdResult,
    entities::{Epoch, Signer, SignerWithStake, StakeDistribution},
};

use crate::entities::LeaderAggregatorEpochSettings;

use super::SignerRegistrationError;

/// Represents the information needed to handle a signer registration round
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerRegistrationRound {
    /// Registration round epoch
    pub epoch: Epoch,

    /// Stake distribution
    pub(super) stake_distribution: StakeDistribution,
}

#[cfg(test)]
impl SignerRegistrationRound {
    pub(crate) fn dummy(epoch: Epoch, stake_distribution: StakeDistribution) -> Self {
        Self {
            epoch,
            stake_distribution,
        }
    }
}

/// Trait to register a signer
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SignerRegisterer: Sync + Send {
    /// Register a signer
    async fn register_signer(
        &self,
        epoch: Epoch,
        signer: &Signer,
    ) -> Result<SignerWithStake, SignerRegistrationError>;

    /// Get current open round if exists
    async fn get_current_round(&self) -> Option<SignerRegistrationRound>;
}

/// Trait to synchronize signers
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SignerSynchronizer: Sync + Send {
    /// Check if the signers can be synchronized
    async fn can_synchronize_signers(&self, epoch: Epoch) -> Result<bool, SignerRegistrationError>;

    /// Synchronize all signers
    async fn synchronize_all_signers(&self) -> Result<(), SignerRegistrationError>;
}

/// Trait to open a signer registration round
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SignerRegistrationRoundOpener: Sync + Send {
    /// Open a signer registration round
    async fn open_registration_round(
        &self,
        registration_epoch: Epoch,
        stake_distribution: StakeDistribution,
    ) -> StdResult<()>;

    /// Close a signer registration round
    async fn close_registration_round(&self) -> StdResult<()>;
}

/// Signer recorder trait
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SignerRecorder: Sync + Send {
    /// Record a signer registration
    async fn record_signer_registration(&self, signer_id: String) -> StdResult<()>;
}

/// A trait for verifying a [Signer] registration.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SignerRegistrationVerifier: Send + Sync {
    /// Verifies a [Signer] registration.
    async fn verify(
        &self,
        signer: &Signer,
        stake_distribution: &StakeDistribution,
        // no future_snark here to not mess with the mock derivation
        epoch: Epoch,
    ) -> StdResult<SignerWithStake>;
}

/// Define how data are retrieved from a leader aggregator
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait LeaderAggregatorClient: Sync + Send {
    /// Retrieves epoch settings from the aggregator
    async fn retrieve_epoch_settings(&self) -> StdResult<Option<LeaderAggregatorEpochSettings>>;
}
