use std::sync::RwLock;

use async_trait::async_trait;
use mithril_common::StdResult;

use crate::{
    interface::ProtocolConfigurationMarkersReader, model::ConfigurationResolverFromMarkers,
};

/// Dummy reader is intended to be used in a test environment (end to end test)
/// to simulate retreiving protocol configurations
#[derive(Default)]
pub struct FakeProtocolConfigurationMarkersReader {
    markers: RwLock<ConfigurationResolverFromMarkers>,
}

impl FakeProtocolConfigurationMarkersReader {
    /// Create a new instance directly from markers
    pub fn from_markers(markers: ConfigurationResolverFromMarkers) -> Self {
        let myself = Self::default();
        myself.set_markers(markers);

        myself
    }

    /// Tells what markers should be sent back by the reader.
    pub fn set_markers(&self, markers: ConfigurationResolverFromMarkers) {
        let mut my_markers = self.markers.write().unwrap();
        *my_markers = markers;
    }
}

#[async_trait]
impl ProtocolConfigurationMarkersReader for FakeProtocolConfigurationMarkersReader {
    async fn read_configuration_markers(&self) -> StdResult<ConfigurationResolverFromMarkers> {
        let markers = self.markers.read().unwrap();

        Ok(markers.clone())
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::test::double::Dummy;

    use super::*;

    #[tokio::test]
    async fn empty_dummy_reader() {
        let reader = FakeProtocolConfigurationMarkersReader::default();

        let result = reader
            .read_configuration_markers()
            .await
            .expect("dummy reader shall not fail reading");

        assert!(result.markers.is_empty());
    }

    #[tokio::test]
    async fn dummy_reader_output() {
        let markers = ConfigurationResolverFromMarkers::dummy();
        let reader = FakeProtocolConfigurationMarkersReader::default();
        reader.set_markers(markers.clone());

        assert_eq!(
            markers,
            reader
                .read_configuration_markers()
                .await
                .expect("dummy reader shall not fail reading")
        );
    }
}
