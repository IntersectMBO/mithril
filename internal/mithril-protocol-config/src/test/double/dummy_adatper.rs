use std::sync::RwLock;

use async_trait::async_trait;
use mithril_common::StdResult;

use crate::{ProtocolConfigurationMarker, ProtocolConfigurationReaderAdapter};

/// Dummy adapter is intended to be used in a test environment (end to end test)
/// to simulate retreiving protocol configurations
#[derive(Default)]
pub struct DummyAdapter {
    markers: RwLock<Vec<ProtocolConfigurationMarker>>,
}

impl DummyAdapter {
    /// Create a new instance directly from markers
    pub fn from_markers(markers: Vec<ProtocolConfigurationMarker>) -> Self {
        let myself = Self::default();
        myself.set_markers(markers);

        myself
    }

    /// Tells what markers should be sent back by the adapter.
    pub fn set_markers(&self, markers: Vec<ProtocolConfigurationMarker>) {
        let mut my_markers = self.markers.write().unwrap();
        *my_markers = markers;
    }
}

#[async_trait]
impl ProtocolConfigurationReaderAdapter for DummyAdapter {
    async fn read(&self) -> StdResult<Vec<ProtocolConfigurationMarker>> {
        let markers = self.markers.read().unwrap();

        Ok((*markers.clone()).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::entities::Epoch;
    use mithril_common::test::double::Dummy;

    use crate::ProtocolConfigurationForEpoch;

    use super::*;

    #[tokio::test]
    async fn empty_dummy_adapter() {
        let adapter = DummyAdapter::default();

        assert!(
            adapter
                .read()
                .await
                .expect("dummy adapter shall not fail reading")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn dummy_adapter_output() {
        let markers = vec![
            ProtocolConfigurationMarker::new(
                Epoch(1),
                ProtocolConfigurationForEpoch::dummy()
                    .to_cbor()
                    .expect("should not fail"),
            ),
            ProtocolConfigurationMarker::new(
                Epoch(2),
                ProtocolConfigurationForEpoch::dummy()
                    .to_cbor()
                    .expect("should not fail"),
            ),
            ProtocolConfigurationMarker::new(
                Epoch(3),
                ProtocolConfigurationForEpoch::dummy()
                    .to_cbor()
                    .expect("should not fail"),
            ),
        ];

        let adapter = DummyAdapter::default();
        adapter.set_markers(markers.clone());

        assert_eq!(
            markers,
            adapter.read().await.expect("dummy adapter shall not fail reading")
        );
    }
}
