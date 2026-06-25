use semver::Version;

/// Version in which Cardano introduces a breaking change regarding the snapshot converter command
pub const CARDANO_NODE_V10_6_2: Version = Version::new(10, 6, 2);

/// Version in which Cardano introduces a breaking change regarding the snapshot converter command
pub const CARDANO_NODE_V10_7_0: Version = Version::new(10, 7, 0);

/// Version in which Cardano introduces a breaking change regarding the snapshot converter command
pub const CARDANO_NODE_V11_1_0: Version = Version::new(11, 1, 0);

pub fn is_version_equal_or_upper(version_to_check: &str, version_reference: Version) -> bool {
    let normalized_version = version_to_check.trim().to_ascii_lowercase();
    if normalized_version == "latest" {
        return true;
    }

    Version::parse(&normalized_version).is_ok_and(|v| v >= version_reference)
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
}
