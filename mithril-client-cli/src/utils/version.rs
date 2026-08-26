use semver::{Prerelease, Version};

/// Version in which Cardano introduces a breaking change regarding the snapshot converter command
pub const CARDANO_NODE_V10_6_2: Version = Version::new(10, 6, 2);

/// Version in which Cardano introduces a breaking change regarding the snapshot converter command
pub const CARDANO_NODE_V10_7_0: Version = Version::new(10, 7, 0);

/// Version in which Cardano introduces a breaking change regarding the snapshot converter command
pub const CARDANO_NODE_V11_1_0: Version = Version::new(11, 1, 0);

/// Returns `true` when `version_to_check` is equal to or newer than `version_reference`.
///
/// The value `latest` is always considered newer. Pre-release tags (e.g. `11.1.0-integration`) are
/// ignored so a pre-release build is treated as its release version, which would otherwise rank
/// lower than the release per semantic versioning rules.
pub fn is_version_equal_or_upper(version_to_check: &str, version_reference: Version) -> bool {
    let normalized_version = version_to_check.trim().to_ascii_lowercase();
    if normalized_version == "latest" {
        return true;
    }

    Version::parse(&normalized_version).is_ok_and(|mut version| {
        version.pre = Prerelease::EMPTY;
        version >= version_reference
    })
}

/// Returns `true` when the Cardano node version is `10.6.2` or newer.
pub fn is_version_at_least_10_6_2_or_latest(version: &str) -> bool {
    is_version_equal_or_upper(version, CARDANO_NODE_V10_6_2)
}

/// Returns `true` when the Cardano node version is `10.7.0` or newer.
pub fn is_version_at_least_10_7_0_or_latest(version: &str) -> bool {
    is_version_equal_or_upper(version, CARDANO_NODE_V10_7_0)
}

/// Returns `true` when the Cardano node version is `11.1.0` or newer.
pub fn is_version_at_least_11_1_0_or_latest(version: &str) -> bool {
    is_version_equal_or_upper(version, CARDANO_NODE_V11_1_0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_version() {
        const VERSION_10_6_2: Version = Version::new(10, 6, 2);

        assert!(!is_version_equal_or_upper(
            "not a string number",
            VERSION_10_6_2
        ));
        assert!(!is_version_equal_or_upper("0", VERSION_10_6_2));
        assert!(!is_version_equal_or_upper("10.5.1", VERSION_10_6_2));

        assert!(is_version_equal_or_upper("10.6.2", VERSION_10_6_2));
        assert!(is_version_equal_or_upper("10.7.1", VERSION_10_6_2));
        assert!(is_version_equal_or_upper("10.7.3", VERSION_10_6_2));
        assert!(is_version_equal_or_upper("latest", VERSION_10_6_2));
    }

    #[test]
    fn prerelease_version_is_treated_as_its_release() {
        const VERSION_11_1_0: Version = Version::new(11, 1, 0);

        assert!(is_version_equal_or_upper(
            "11.1.0-integration",
            VERSION_11_1_0
        ));
        assert!(is_version_equal_or_upper("11.1.0-rc1", VERSION_11_1_0));
        assert!(is_version_equal_or_upper(
            "11.2.0-integration",
            VERSION_11_1_0
        ));
        assert!(!is_version_equal_or_upper(
            "11.0.0-integration",
            VERSION_11_1_0
        ));
    }

    #[test]
    fn cardano_node_version_predicates_match_their_reference_version() {
        assert!(!is_version_at_least_10_6_2_or_latest("10.6.1"));
        assert!(is_version_at_least_10_6_2_or_latest("10.6.2"));
        assert!(is_version_at_least_10_6_2_or_latest("latest"));

        assert!(!is_version_at_least_10_7_0_or_latest("10.6.9"));
        assert!(is_version_at_least_10_7_0_or_latest("10.7.0"));
        assert!(is_version_at_least_10_7_0_or_latest("latest"));

        assert!(!is_version_at_least_11_1_0_or_latest("11.0.9"));
        assert!(is_version_at_least_11_1_0_or_latest("11.1.0"));
        assert!(is_version_at_least_11_1_0_or_latest("latest"));
    }
}
