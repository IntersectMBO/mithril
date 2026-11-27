//! Kind of environment targeted by the signer, guessed from the selected Mithril network

/// Kind of environment targeted by the signer
///
/// It gives the default values of the signer that depend on the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MithrilEnvironment {
    /// A `release-*` Mithril network, ie: `release-mainnet`, `release-preprod`
    Release,

    /// A `pre-release-*` Mithril network, ie: `pre-release-preview`
    PreRelease,

    /// Any other Mithril network of `networks.json`, ie: `testing-preview`, `ivc-snark-preview`
    Testing,

    /// No Mithril network of `networks.json`: a devnet or a private network
    Devnet,
}

impl MithrilEnvironment {
    /// Directory of the signer stores, as advised by the signer operations guide
    const DEFAULT_DATA_STORES_DIRECTORY: &str = "/opt/mithril/stores";

    /// Number of records kept in the signer stores, as advised by the signer operations guide
    const DEFAULT_STORE_RETENTION_LIMIT: u64 = 5;

    /// Run interval (ms) of a production environment, as advised by the signer operations guide
    const DEFAULT_RUN_INTERVAL: u64 = 60000;

    /// Run interval (ms) of a test environment, shorter for faster cycles
    const TEST_RUN_INTERVAL: u64 = 20000;

    /// Environment of the selected Mithril network, identified by the prefix of its name
    ///
    /// No Mithril network means a devnet or a private network. A name with an unknown prefix
    /// is a test environment, so that a new network does not get production values.
    pub fn from_mithril_network(name: Option<&str>) -> Self {
        match name {
            None => Self::Devnet,
            Some(name) if name.starts_with("pre-release-") => Self::PreRelease,
            Some(name) if name.starts_with("release-") => Self::Release,
            Some(_) => Self::Testing,
        }
    }

    /// Directory of the signer stores (`DATA_STORES_DIRECTORY`)
    pub fn data_stores_directory(&self) -> &'static str {
        match self {
            Self::Release | Self::PreRelease | Self::Testing | Self::Devnet => {
                Self::DEFAULT_DATA_STORES_DIRECTORY
            }
        }
    }

    /// Number of records kept in the signer stores (`STORE_RETENTION_LIMIT`)
    pub fn store_retention_limit(&self) -> u64 {
        match self {
            Self::Release | Self::PreRelease | Self::Testing | Self::Devnet => {
                Self::DEFAULT_STORE_RETENTION_LIMIT
            }
        }
    }

    /// Interval in milliseconds between two runtime cycles of the signer (`RUN_INTERVAL`)
    pub fn run_interval(&self) -> u64 {
        match self {
            Self::Release | Self::PreRelease => Self::DEFAULT_RUN_INTERVAL,
            Self::Testing | Self::Devnet => Self::TEST_RUN_INTERVAL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_ENVIRONMENTS: [MithrilEnvironment; 4] = [
        MithrilEnvironment::Release,
        MithrilEnvironment::PreRelease,
        MithrilEnvironment::Testing,
        MithrilEnvironment::Devnet,
    ];

    mod from_mithril_network {
        use super::*;

        #[test]
        fn identifies_the_release_networks() {
            for name in ["release-mainnet", "release-preprod"] {
                assert_eq!(
                    MithrilEnvironment::Release,
                    MithrilEnvironment::from_mithril_network(Some(name)),
                    "for {name}"
                );
            }
        }

        #[test]
        fn identifies_the_pre_release_networks() {
            assert_eq!(
                MithrilEnvironment::PreRelease,
                MithrilEnvironment::from_mithril_network(Some("pre-release-preview"))
            );
        }

        #[test]
        fn identifies_the_other_networks_as_testing() {
            for name in ["testing-preview", "ivc-snark-preview"] {
                assert_eq!(
                    MithrilEnvironment::Testing,
                    MithrilEnvironment::from_mithril_network(Some(name)),
                    "for {name}"
                );
            }
        }

        #[test]
        fn identifies_a_network_with_an_unknown_prefix_as_testing() {
            assert_eq!(
                MithrilEnvironment::Testing,
                MithrilEnvironment::from_mithril_network(Some("new-network-preview"))
            );
        }

        #[test]
        fn identifies_no_mithril_network_as_a_devnet() {
            assert_eq!(
                MithrilEnvironment::Devnet,
                MithrilEnvironment::from_mithril_network(None)
            );
        }
    }

    #[test]
    fn gives_the_data_stores_directory_of_each_environment() {
        for environment in ALL_ENVIRONMENTS {
            assert_eq!(
                "/opt/mithril/stores",
                environment.data_stores_directory(),
                "for {environment:?}"
            );
        }
    }

    #[test]
    fn gives_the_store_retention_limit_of_each_environment() {
        for environment in ALL_ENVIRONMENTS {
            assert_eq!(
                5,
                environment.store_retention_limit(),
                "for {environment:?}"
            );
        }
    }

    #[test]
    fn gives_a_production_run_interval_to_the_release_environments() {
        assert_eq!(60000, MithrilEnvironment::Release.run_interval());
        assert_eq!(60000, MithrilEnvironment::PreRelease.run_interval());
    }

    #[test]
    fn gives_a_shorter_run_interval_to_the_test_environments() {
        assert_eq!(20000, MithrilEnvironment::Testing.run_interval());
        assert_eq!(20000, MithrilEnvironment::Devnet.run_interval());
    }
}
