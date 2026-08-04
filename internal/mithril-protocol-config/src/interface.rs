//! Interface definition for Mithril Protocol Configuration provider.

use async_trait::async_trait;
use mithril_common::{StdResult, entities::Epoch};

use crate::model::{ConfigurationResolverFromMarkers, MithrilNetworkConfiguration};

/// A provider for the Mithril network configuration of the a given epoch.
#[async_trait]
pub trait MithrilNetworkConfigurationProvider: Sync + Send {
    /// Get the Mithril network configuration for a given epoch.
    async fn get_network_configuration(
        &self,
        epoch: Epoch,
    ) -> StdResult<MithrilNetworkConfiguration>;
}

/// A reader for Protocol Configuration Markers
#[async_trait]
pub trait ProtocolConfigurationMarkersReader: Sync + Send {
    /// Read protocol configuration markers.
    async fn read_configuration_markers(&self) -> StdResult<ConfigurationResolverFromMarkers>;
}
