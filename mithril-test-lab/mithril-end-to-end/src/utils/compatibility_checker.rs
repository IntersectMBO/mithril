use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

use crate::{Aggregator, Signer};

/// Tool to check if the end-to-end runner can be launched with the given nodes versions
pub struct CompatibilityChecker {
    rules: Vec<CompatibilityRule>,
}

impl Default for CompatibilityChecker {
    fn default() -> Self {
        Self::new(vec![
            incompatibility_rule!(
                "mithril-client", below_version: semver::Version::new(0, 11, 14),
                is_incompatible_with: "mithril-aggregator", starting_version: semver::Version::new(0, 7, 31),
                context: "below versions doesn't support properly cardano db verification without ancillary files"
            ),
            incompatibility_rule!(
                "mithril-aggregator", below_version: semver::Version::new(0, 7, 91),
                is_incompatible_with: "mithril-signer", starting_version: semver::Version::new(0, 2, 277),
                context: "signers starting `0.2.277` needs the `/protocol-parameters/{epoch}` route which is not available in aggregator older versions"
            ),
            incompatibility_rule!(
                "mithril-aggregator", below_version: semver::Version::new(0, 7, 55),
                is_incompatible_with: "cardano-node", starting_version: semver::Version::new(10, 4, 1),
                context: "older aggregator doesn't support UTxO-HD ledgers"
            ),
            incompatibility_rule!(
                "mithril-signer", min_supported_version: semver::Version::new(0, 2, 221),
                context: "older signers raise errors when an aggregator propagate a signed entity types that they don't know (i.e. CardanoDatabase signed entity type)"
            ),
            incompatibility_rule!(
                "mithril-aggregator", below_version: semver::Version::new(0, 8, 46),
                is_incompatible_with: "cardano-node", starting_version: semver::Version::new(10, 7, 0),
                context: "older aggregator doesn't support new UTxO-HD ledger state snapshot format"
            ),
            incompatibility_rule!(
                "mithril-aggregator", below_version: Aggregator::SEQUENCED_ERA_MARKERS_MIN_VERSION,
                is_incompatible_with: "mithril-signer", starting_version: Signer::SEQUENCED_ERA_MARKERS_MIN_VERSION,
                context: "these signers only read the era markers signed with a sequence number, which older aggregators can not generate"
            ),
        ])
    }
}

/// Error returned by the compatibility checker when the nodes are incompatible with one or more rules
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityCheckerError {
    nodes_with_version: BTreeMap<&'static str, semver::Version>,
    detected_incompatibilities: Vec<CompatibilityRule>,
}

impl Display for CompatibilityCheckerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Incompatible nodes detected:")?;
        for rule in &self.detected_incompatibilities {
            writeln!(f, "- {rule}")?;
        }
        writeln!(f)?;
        writeln!(f, "Actual nodes versions:")?;
        for (node_name, version) in &self.nodes_with_version {
            writeln!(f, "- {node_name}: `{version}`")?;
        }

        Ok(())
    }
}

impl std::error::Error for CompatibilityCheckerError {}

/// A rule defining an incompatibility of the end-to-end runner with a given node version, or of
/// two node versions between each others
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityRule {
    node_name: &'static str,
    is_incompatible_with: IncompatibilityReason,
    additional_context: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncompatibilityReason {
    /// Two nodes are incompatible with each others
    IncompatibleWithNode {
        min_compatible_version: semver::Version,
        other_node_name: &'static str,
        other_node_min_compatible_version: semver::Version,
    },
    /// The end-to-end runner is not compatible with the given node version
    NotSupportedVersion {
        min_supported_version: semver::Version,
    },
}

impl CompatibilityRule {
    /// Check if the given nodes versions are incompatible with this rule.
    pub fn has_incompatibility(
        &self,
        nodes_with_version: &BTreeMap<&'static str, semver::Version>,
    ) -> bool {
        if !nodes_with_version.contains_key(self.node_name) {
            return false;
        }
        let node_version = nodes_with_version.get(self.node_name).unwrap();

        // Note: unwrap on the comparator is safe because the comparator is constructed from a valid semver object.
        match &self.is_incompatible_with {
            IncompatibilityReason::NotSupportedVersion {
                min_supported_version,
            } => {
                let comparator =
                    semver::Comparator::parse(&format!("<{min_supported_version}")).unwrap();
                comparator.matches(node_version)
            }
            IncompatibilityReason::IncompatibleWithNode {
                min_compatible_version,
                other_node_name: incompatible_node_name,
                other_node_min_compatible_version: incompatible_node_version,
            } => {
                if let Some(other_node_version) = nodes_with_version.get(incompatible_node_name) {
                    let node_comparator =
                        semver::Comparator::parse(&format!("<{min_compatible_version}")).unwrap();
                    let other_node_comparator =
                        semver::Comparator::parse(&format!(">={incompatible_node_version}"))
                            .unwrap();

                    node_comparator.matches(node_version)
                        && other_node_comparator.matches(other_node_version)
                } else {
                    false
                }
            }
        }
    }
}

impl Display for CompatibilityRule {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let context: String = self
            .additional_context
            .map(|ctx| format!(", {ctx}"))
            .unwrap_or_default();

        match &self.is_incompatible_with {
            IncompatibilityReason::NotSupportedVersion {
                min_supported_version,
            } => {
                write!(
                    f,
                    "minimum supported {name} version is `{min_supported_version}`{context}",
                    name = self.node_name,
                )
            }
            IncompatibilityReason::IncompatibleWithNode {
                min_compatible_version,
                other_node_name,
                other_node_min_compatible_version,
            } => {
                write!(
                    f,
                    "{other_node_name} starting version `{other_node_min_compatible_version}` is incompatible with {name} with a version below `{min_compatible_version}`{context}",
                    name = self.node_name,
                )
            }
        }
    }
}

impl CompatibilityChecker {
    /// Create a new compatibility checker with the given rules.
    pub fn new(rules: Vec<CompatibilityRule>) -> Self {
        CompatibilityChecker { rules }
    }

    /// Check if the given nodes versions are compatible with the parametrized rules.
    pub fn check(
        &self,
        nodes_with_version: BTreeMap<&'static str, semver::Version>,
    ) -> Result<(), CompatibilityCheckerError> {
        slog_scope::debug!(
            "Checking nodes compatibility";
            "nodes" => #?nodes_with_version.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>(),
            "rules" => #?self.rules.iter().map(|r| format!("{r}")).collect::<Vec<_>>()
        );
        let detected_incompatibilities: Vec<_> = self
            .rules
            .iter()
            .filter(|r| r.has_incompatibility(&nodes_with_version))
            .cloned()
            .collect();

        if detected_incompatibilities.is_empty() {
            Ok(())
        } else {
            Err(CompatibilityCheckerError {
                detected_incompatibilities,
                nodes_with_version,
            })
        }
    }
}

/// Define a compatibility rule that will be checked against the nodes with their versions
/// to ensure that the end-to-end runner can be executed
macro_rules! incompatibility_rule {
    ($node:literal, min_supported_version:$min_version:expr, context:$context:literal) => {
        $crate::utils::CompatibilityRule {
            node_name: $node,
            is_incompatible_with: $crate::utils::IncompatibilityReason::NotSupportedVersion {
                min_supported_version: $min_version,
            },
            additional_context: (!$context.is_empty()).then_some($context),
        }
    };
    ($node:literal, min_supported_version:$min_version:expr) => {
        $crate::utils::incompatibility_rule!($node, min_supported_version:$min_version, context:"")
    };
    ($node:literal, below_version:$version:expr, is_incompatible_with:$incompatible_node:literal, starting_version:$min_version:expr, context:$context:literal) => {
        $crate::utils::CompatibilityRule {
            node_name: $node,
            is_incompatible_with: $crate::utils::IncompatibilityReason::IncompatibleWithNode {
                min_compatible_version: $version,
                other_node_name: $incompatible_node,
                other_node_min_compatible_version: $min_version,
            },
            additional_context: (!$context.is_empty()).then_some($context),
        }
    };
    ($node:literal, below_version:$version:expr, is_incompatible_with:$incompatible_node:literal, starting_version:$min_version:expr) => {
        $crate::utils::incompatibility_rule!($node, below_version:$version, is_incompatible_with:$incompatible_node, starting_version:$min_version, context:"")
    };
}
pub(crate) use incompatibility_rule;

#[cfg(test)]
mod tests {
    use semver::Version;

    use super::*;

    #[test]
    fn check_min_compatible_version() {
        let rule = incompatibility_rule!("TestNode", min_supported_version: Version::new(10, 2, 1));

        assert!(!rule.has_incompatibility(&BTreeMap::from([])));
        assert!(!rule.has_incompatibility(&BTreeMap::from([("TestNode", Version::new(10, 2, 1))])));
        assert!(rule.has_incompatibility(&BTreeMap::from([("TestNode", Version::new(10, 2, 0))])));
    }

    #[test]
    fn check_incompatible_nodes_versions() {
        let rule = incompatibility_rule!("node alpha", below_version: Version::new(3, 2, 1), is_incompatible_with: "node beta", starting_version: Version::new(6, 4, 1));

        assert!(!rule.has_incompatibility(&BTreeMap::from([])));
        assert!(!rule.has_incompatibility(&BTreeMap::from([
            ("node alpha", Version::new(3, 2, 1)),
            ("node beta", Version::new(6, 4, 1)),
        ])));
        // Even if node alpha is far below the minimum version of the rule, there is no incompatibility if node beta is missing
        assert!(
            !rule.has_incompatibility(&BTreeMap::from([("node alpha", Version::new(1, 0, 0))]))
        );
        // Incompatible if Node beta right at the threshold and Node alpha right below the minimum version threshold
        assert!(rule.has_incompatibility(&BTreeMap::from([
            ("node alpha", Version::new(3, 2, 0)),
            ("node beta", Version::new(6, 4, 1)),
        ])));
    }

    #[test]
    fn checker_can_detect_multiple_incompatible_rule() {
        let checker = CompatibilityChecker::new(vec![
            incompatibility_rule!("node alpha", min_supported_version: Version::new(2, 2, 1)),
            incompatibility_rule!("node alpha", min_supported_version: Version::new(3, 2, 1)),
            incompatibility_rule!("node alpha", below_version: Version::new(3, 2, 1), is_incompatible_with: "node beta", starting_version: Version::new(1, 0, 1)),
        ]);

        let error = checker
            .check(BTreeMap::from([
                ("node alpha", Version::new(3, 1, 5)),
                ("node beta", Version::new(1, 0, 9)),
            ]))
            .unwrap_err();

        assert_eq!(
            error.detected_incompatibilities,
            vec![
                incompatibility_rule!("node alpha", min_supported_version: Version::new(3, 2, 1)),
                incompatibility_rule!("node alpha", below_version: Version::new(3, 2, 1), is_incompatible_with: "node beta", starting_version: Version::new(1, 0, 1)),
            ]
        );
    }

    #[test]
    fn display_compat_error() {
        let error = CompatibilityCheckerError {
            nodes_with_version: BTreeMap::from([
                ("node alpha", Version::new(1, 1, 1)),
                ("node beta", Version::new(5, 5, 5)),
                ("node gamma", Version::new(6, 6, 6)),
                ("node zeta", Version::new(8, 8, 8)),
            ]),
            detected_incompatibilities: vec![
                incompatibility_rule!("node alpha", min_supported_version: Version::new(2, 0, 0), context: "first error context"),
                incompatibility_rule!(
                    "node alpha", below_version: Version::new(2, 0, 0),
                    is_incompatible_with: "node beta", starting_version: Version::new(5, 0, 0),
                    context: "second error context"
                ),
                incompatibility_rule!("node gamma", min_supported_version: Version::new(3, 0, 0)),
            ],
        };

        assert_eq!(
            "Incompatible nodes detected:\
            \n- minimum supported node alpha version is `2.0.0`, first error context\
            \n- node beta starting version `5.0.0` is incompatible with node alpha with a version below `2.0.0`, second error context\
            \n- minimum supported node gamma version is `3.0.0`\
            \n\
            \nActual nodes versions:\
            \n- node alpha: `1.1.1`\
            \n- node beta: `5.5.5`\
            \n- node gamma: `6.6.6`\
            \n- node zeta: `8.8.8`\n",
            format!("{error}")
        );
    }
}
