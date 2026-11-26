use std::sync::Arc;

use anyhow::anyhow;
use semver::Version;
use sqlite::Connection;

use mithril_common::StdResult;

use super::LayoutRc2026w44;

/// The layout of the immutable partition of the LeiosDB of one node release.
///
/// Implementations are the only code that knows the tables, columns and encodings of the node.
pub trait LeiosImmutableDatabaseLayout: Send + Sync {
    /// Name of the layout, the node release that introduced it.
    fn name(&self) -> &'static str;

    /// Tells whether the database holds the closure of an endorser block given its hash in lowercase hex.
    fn has_closure(&self, connection: &Connection, endorser_block_hash: &str) -> StdResult<bool>;
}

/// Provider of the LeiosDB layout of a cardano-node version.
pub struct LeiosImmutableDatabaseLayoutProvider;

impl LeiosImmutableDatabaseLayoutProvider {
    /// First cardano-node version whose LeiosDB follows the `rc-2026w44` layout.
    const FIRST_RC_2026W44_CARDANO_NODE_VERSION: Version = Version::new(11, 2, 0);

    /// Selects the LeiosDB layout of a cardano-node version.
    ///
    /// A pre-release or a build of a version has the layout of that version.
    pub fn layout_for_cardano_node_version(
        version: &Version,
    ) -> StdResult<Arc<dyn LeiosImmutableDatabaseLayout>> {
        let release_version = Version::new(version.major, version.minor, version.patch);
        if release_version >= Self::FIRST_RC_2026W44_CARDANO_NODE_VERSION {
            Ok(Arc::new(LayoutRc2026w44))
        } else {
            Err(anyhow!(
                "No Leios database layout for cardano-node {version}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_the_rc_2026w44_layout_from_cardano_node_11_2_0() {
        for version in [Version::new(11, 2, 0), Version::new(11, 3, 1)] {
            let layout =
                LeiosImmutableDatabaseLayoutProvider::layout_for_cardano_node_version(&version)
                    .unwrap();

            assert_eq!(layout.name(), "rc-2026w44");
        }
    }

    #[test]
    fn selects_the_rc_2026w44_layout_for_a_pre_release_of_cardano_node_11_2_0() {
        let version = Version::parse("11.2.0-rc-2026w46").unwrap();

        let layout =
            LeiosImmutableDatabaseLayoutProvider::layout_for_cardano_node_version(&version)
                .unwrap();

        assert_eq!(layout.name(), "rc-2026w44");
    }

    #[test]
    fn has_no_layout_before_cardano_node_11_2_0() {
        LeiosImmutableDatabaseLayoutProvider::layout_for_cardano_node_version(&Version::new(
            11, 1, 3,
        ))
        .err()
        .expect("should have no layout");
    }
}
