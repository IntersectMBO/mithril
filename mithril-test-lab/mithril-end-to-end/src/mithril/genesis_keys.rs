use std::fmt::{self, Debug, Formatter};

use mithril_common::entities::SupportedEra;

use crate::utils::NodeVersion;

const LEGACY_VERIFICATION_KEY: &str = "5b33322c3235332c3138362c3230312c3137372c31312c3131372c3133352c3138372c3136372c3138312c3138382c32322c35392c3230362c3130352c3233312c3135302c3231352c33302c37382c3231322c37362c31362c3235322c3138302c37322c3133342c3133372c3234372c3136312c36385d";
const LEGACY_SECRET_KEY: &str = "5b3131382c3138342c3232342c3137332c3136302c3234312c36312c3134342c36342c39332c3130362c3232392c38332c3133342c3138392c34302c3138392c3231302c32352c3138342c3136302c3134312c3233372c32362c3136382c35342c3233392c3230342c3133392c3131392c31332c3139395d";
const DUAL_VERIFICATION_KEY: &str = "012020fdbac9b10b7587bba7b5bc163bce69e796d71e4ed44c10fcb4488689f7a1444069c10d42f944c2a7a5138391aafe3dbe1e40e8516a9e174aff16dddfe5c3f303e65a3fa2187e10860541ff2dfc59296f15833b6ba549ff83153f9cde07d0eb26";
const DUAL_SECRET_KEY: &str = "012076b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7202c9dc80e956510c4461bdc39bda7e96a88a3f7a4635ff5e66e3040b5baa08e04";

/// First aggregator version accepting a dual genesis key bundle
const MIN_AGGREGATOR_VERSION_WITH_DUAL_KEYS: &str = "0.9.6";

/// First client version accepting a dual genesis key bundle
const MIN_CLIENT_VERSION_WITH_DUAL_KEYS: &str = "0.13.15";

/// Genesis keys handed to the nodes
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GenesisKeys {
    /// Hex encoded genesis verification key
    pub verification_key: &'static str,

    /// Hex encoded genesis secret key
    pub secret_key: &'static str,
}

impl GenesisKeys {
    /// Legacy Ed25519 keys, accepted by every node version
    pub const LEGACY: Self = Self {
        verification_key: LEGACY_VERIFICATION_KEY,
        secret_key: LEGACY_SECRET_KEY,
    };

    /// Dual Ed25519 and Schnorr key bundles sharing the legacy Ed25519 keys, needed to sign a
    /// Lagrange genesis certificate on nodes built with the SNARK feature
    pub const DUAL: Self = Self {
        verification_key: DUAL_VERIFICATION_KEY,
        secret_key: DUAL_SECRET_KEY,
    };

    /// Select the dual key bundles when a Lagrange era is run on nodes accepting them and the
    /// runner is built with the SNARK feature, as the nodes then are, and the legacy keys otherwise
    pub fn select(
        mithril_era: &str,
        mithril_next_era: Option<&str>,
        aggregator_version: &NodeVersion,
        client_version: &NodeVersion,
    ) -> Self {
        let runs_lagrange = [Some(mithril_era), mithril_next_era]
            .into_iter()
            .flatten()
            .any(|era| era.parse() == Ok(SupportedEra::Lagrange));
        let nodes_accept_dual_keys = aggregator_version
            .is_above_or_equal(MIN_AGGREGATOR_VERSION_WITH_DUAL_KEYS)
            && client_version.is_above_or_equal(MIN_CLIENT_VERSION_WITH_DUAL_KEYS);

        if cfg!(feature = "future_snark") && runs_lagrange && nodes_accept_dual_keys {
            Self::DUAL
        } else {
            Self::LEGACY
        }
    }
}

impl Debug for GenesisKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenesisKeys")
            .field("verification_key", &self.verification_key)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(version: &str) -> NodeVersion {
        NodeVersion::new(semver::Version::parse(version).unwrap())
    }

    #[test]
    fn debug_output_redacts_the_secret_key() {
        let output = format!("{:?}", GenesisKeys::LEGACY);

        assert!(output.contains(LEGACY_VERIFICATION_KEY));
        assert!(!output.contains(LEGACY_SECRET_KEY));
    }

    #[test]
    fn legacy_keys_for_pythagoras_whatever_the_node_versions() {
        let genesis_keys =
            GenesisKeys::select("pythagoras", None, &version("0.10.1"), &version("0.13.23"));

        assert_eq!(GenesisKeys::LEGACY, genesis_keys);
    }

    #[test]
    fn legacy_keys_for_lagrange_on_an_aggregator_not_accepting_dual_keys() {
        let genesis_keys =
            GenesisKeys::select("lagrange", None, &version("0.9.5"), &version("0.13.23"));

        assert_eq!(GenesisKeys::LEGACY, genesis_keys);
    }

    #[test]
    fn legacy_keys_for_lagrange_on_a_client_not_accepting_dual_keys() {
        let genesis_keys =
            GenesisKeys::select("lagrange", None, &version("0.10.1"), &version("0.13.14"));

        assert_eq!(GenesisKeys::LEGACY, genesis_keys);
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn dual_keys_for_lagrange_on_nodes_accepting_them() {
        let genesis_keys =
            GenesisKeys::select("lagrange", None, &version("0.9.6"), &version("0.13.15"));

        assert_eq!(GenesisKeys::DUAL, genesis_keys);
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn dual_keys_when_lagrange_is_the_next_era() {
        let genesis_keys = GenesisKeys::select(
            "pythagoras",
            Some("lagrange"),
            &version("0.10.1"),
            &version("0.13.23"),
        );

        assert_eq!(GenesisKeys::DUAL, genesis_keys);
    }

    #[cfg(not(feature = "future_snark"))]
    #[test]
    fn legacy_keys_for_lagrange_without_the_snark_feature() {
        let genesis_keys =
            GenesisKeys::select("lagrange", None, &version("0.10.1"), &version("0.13.23"));

        assert_eq!(GenesisKeys::LEGACY, genesis_keys);
    }
}
