use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use mithril_stm::AggregateSignatureType;

use crate::messages::SignedEntityTypeDiscriminantsMessage;

/// Message advertised by an Aggregator to inform about its features
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AggregatorFeaturesMessage {
    /// Version of the OpenAPI specification
    pub open_api_version: String,

    /// URL of the documentation
    pub documentation_url: String,

    /// Capabilities of the Aggregator
    pub capabilities: AggregatorCapabilities,

    /// Distribution configuration for the Cardano database's immutable files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cardano_database_distribution: Option<CardanoDatabaseDistribution>,
}

/// Capabilities of an Aggregator
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AggregatorCapabilities {
    /// Signed entity types that are signed by the aggregator
    pub signed_entity_types: BTreeSet<SignedEntityTypeDiscriminantsMessage>,

    /// Aggregate signature type used by the aggregator
    #[serde(default)]
    pub aggregate_signature_type: AggregateSignatureType,

    /// Cardano transactions prover capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cardano_transactions_prover: Option<CardanoTransactionsProverCapabilities>,
}

/// Cardano transactions prover capabilities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CardanoTransactionsProverCapabilities {
    /// Maximum number of hashes allowed for a single request
    pub max_hashes_allowed_by_request: usize,
}

/// Distribution configuration for the Cardano database's immutable files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CardanoDatabaseDistribution {
    /// IPFS path of the IPNS record linking to an IPFS directory containing the cardano database immutables files
    ///
    /// Only set if the aggregator is configured to distribute immutable files via IPFS and the IPNS
    /// publication is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipns_record: Option<String>,

    /// Share of the immutables files to distribute through IPFS (0-100 inclusive)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipfs_share: Option<u8>,
}

#[cfg(test)]
mod tests {
    use crate::entities::{CardanoTransactionsSigningConfig, SignedEntityTypeDiscriminants};

    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct AggregatorFeaturesMessageUntilV0_1_45 {
        pub open_api_version: String,
        pub documentation_url: String,
        pub capabilities: AggregatorCapabilitiesUntilV0_1_45,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct AggregatorCapabilitiesUntilV0_1_45 {
        pub signed_entity_types: BTreeSet<SignedEntityTypeDiscriminantsMessage>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cardano_transactions_prover: Option<CardanoTransactionsProverCapabilities>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cardano_transactions_signing_config: Option<CardanoTransactionsSigningConfig>,
    }

    fn golden_message_until_open_api_0_1_45() -> AggregatorFeaturesMessageUntilV0_1_45 {
        AggregatorFeaturesMessageUntilV0_1_45 {
            open_api_version: "0.0.1".to_string(),
            documentation_url: "https://example.com".to_string(),
            capabilities: AggregatorCapabilitiesUntilV0_1_45 {
                signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminants::CardanoTransactions.into(),
                ]),
                cardano_transactions_prover: Some(CardanoTransactionsProverCapabilities {
                    max_hashes_allowed_by_request: 100,
                }),
                cardano_transactions_signing_config: None,
            },
        }
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct AggregatorFeaturesMessageUntilV0_6_17 {
        pub open_api_version: String,
        pub documentation_url: String,
        pub capabilities: AggregatorCapabilitiesUntilV0_6_17,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct AggregatorCapabilitiesUntilV0_6_17 {
        pub signed_entity_types: BTreeSet<SignedEntityTypeDiscriminantsMessage>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cardano_transactions_prover: Option<CardanoTransactionsProverCapabilities>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cardano_transactions_signing_config: Option<CardanoTransactionsSigningConfig>,
    }

    fn golden_message_until_open_api_0_6_17() -> AggregatorFeaturesMessageUntilV0_6_17 {
        AggregatorFeaturesMessageUntilV0_6_17 {
            open_api_version: "0.0.1".to_string(),
            documentation_url: "https://example.com".to_string(),
            capabilities: AggregatorCapabilitiesUntilV0_6_17 {
                signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminants::CardanoTransactions.into(),
                ]),
                cardano_transactions_prover: Some(CardanoTransactionsProverCapabilities {
                    max_hashes_allowed_by_request: 100,
                }),
                cardano_transactions_signing_config: None,
            },
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct AggregatorFeaturesMessageUntilV0_8_3 {
        pub open_api_version: String,
        pub documentation_url: String,
        pub capabilities: AggregatorCapabilitiesUntilV0_8_3,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct AggregatorCapabilitiesUntilV0_8_3 {
        pub signed_entity_types: BTreeSet<SignedEntityTypeDiscriminantsMessage>,
        #[serde(default)]
        pub aggregate_signature_type: AggregateSignatureType,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cardano_transactions_prover: Option<CardanoTransactionsProverCapabilitiesUntilV0_8_3>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct CardanoTransactionsProverCapabilitiesUntilV0_8_3 {
        pub max_hashes_allowed_by_request: usize,
    }

    fn golden_message_until_open_api_0_8_3() -> AggregatorFeaturesMessageUntilV0_8_3 {
        AggregatorFeaturesMessageUntilV0_8_3 {
            open_api_version: "0.0.1".to_string(),
            documentation_url: "https://example.com".to_string(),
            capabilities: AggregatorCapabilitiesUntilV0_8_3 {
                signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminants::CardanoTransactions.into(),
                ]),
                aggregate_signature_type: AggregateSignatureType::Concatenation,
                cardano_transactions_prover: Some(
                    CardanoTransactionsProverCapabilitiesUntilV0_8_3 {
                        max_hashes_allowed_by_request: 100,
                    },
                ),
            },
        }
    }

    fn golden_message_current() -> AggregatorFeaturesMessage {
        AggregatorFeaturesMessage {
            open_api_version: "0.0.1".to_string(),
            documentation_url: "https://example.com".to_string(),
            capabilities: AggregatorCapabilities {
                signed_entity_types: BTreeSet::from([
                    SignedEntityTypeDiscriminants::CardanoTransactions.into(),
                ]),
                aggregate_signature_type: AggregateSignatureType::Concatenation,
                cardano_transactions_prover: Some(CardanoTransactionsProverCapabilities {
                    max_hashes_allowed_by_request: 100,
                }),
            },
            cardano_database_distribution: Some(CardanoDatabaseDistribution {
                ipns_record: Some(
                    "/ipns/k51qzi5uqu5djd98ozajs6h4ljp0p53lqf4fn4p3904t20yqjbc2nksxotpz66"
                        .to_string(),
                ),
                ipfs_share: Some(30),
            }),
        }
    }

    const CURRENT_JSON: &str = r#"{
        "open_api_version": "0.0.1",
        "documentation_url": "https://example.com",
        "capabilities": {
            "signed_entity_types": ["CardanoTransactions"],
            "aggregate_signature_type": "Concatenation",
            "cardano_transactions_prover": {
                "max_hashes_allowed_by_request": 100
            }
        },
        "cardano_database_distribution": {
            "ipns_record": "/ipns/k51qzi5uqu5djd98ozajs6h4ljp0p53lqf4fn4p3904t20yqjbc2nksxotpz66",
            "ipfs_share": 30
        }
    }"#;

    #[test]
    fn test_current_json_deserialized_into_message_supported_until_open_api_0_1_45() {
        let json = CURRENT_JSON;
        let message: AggregatorFeaturesMessageUntilV0_1_45 = serde_json::from_str(json).unwrap();

        assert_eq!(golden_message_until_open_api_0_1_45(), message);
    }

    #[test]
    fn test_current_json_deserialized_into_message_supported_until_open_api_0_6_17() {
        let json = CURRENT_JSON;
        let message: AggregatorFeaturesMessageUntilV0_6_17 = serde_json::from_str(json).unwrap();

        assert_eq!(golden_message_until_open_api_0_6_17(), message);
    }

    #[test]
    fn test_current_json_deserialized_into_message_supported_until_open_api_0_8_3() {
        let json = CURRENT_JSON;
        let message: AggregatorFeaturesMessageUntilV0_8_3 = serde_json::from_str(json).unwrap();

        assert_eq!(golden_message_until_open_api_0_8_3(), message);
    }

    #[test]
    fn test_current_json_deserialized_into_current_message() {
        let json = CURRENT_JSON;
        let message: AggregatorFeaturesMessage = serde_json::from_str(json).unwrap();

        assert_eq!(golden_message_current(), message);
    }
}
