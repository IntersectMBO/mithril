use serde::{Deserialize, Serialize};

use crate::entities::{CardanoEra, Epoch, ProtocolParameters, Stake, SupportedEra, TotalSPOs};

/// Message advertised by an aggregator to inform about its status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AggregatorStatusMessage {
    /// Current epoch
    pub epoch: Epoch,

    /// Current Cardano era
    pub cardano_era: CardanoEra,

    /// Cardano network
    pub cardano_network: String,

    /// Current Mithril era
    pub mithril_era: SupportedEra,

    /// Cardano node version
    pub cardano_node_version: String,

    /// Aggregator node version
    pub aggregator_node_version: String,

    /// Current Protocol parameters
    #[serde(rename = "protocol")]
    pub protocol_parameters: ProtocolParameters,

    /// Next Protocol parameters
    #[serde(rename = "next_protocol")]
    pub next_protocol_parameters: ProtocolParameters,

    /// The number of signers for the current epoch
    pub total_signers: usize,

    /// The number of signers that will be able to sign on the next epoch
    pub total_next_signers: usize,

    /// The total stakes of the signers for the current epoch
    pub total_stakes_signers: Stake,

    /// The total stakes of the signers that will be able to sign on the next epoch
    pub total_next_stakes_signers: Stake,

    /// The number of Cardano SPOs
    pub total_cardano_spo: TotalSPOs,

    /// The total stake in Cardano
    pub total_cardano_stake: Stake,

    /// Endpoint of the leader aggregator followed for the signer registrations, absent when this
    /// aggregator is a leader
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leader_aggregator_endpoint: Option<String>,

    /// Endpoint of the aggregator followed for the certificate chain, absent when this
    /// aggregator is a leader
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_chain_aggregator_endpoint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT_JSON: &str = r#"{
        "epoch": 48,
        "cardano_era": "conway",
        "cardano_network": "mainnet",
        "mithril_era": "pythagoras",
        "cardano_node_version": "1.2.3",
        "aggregator_node_version": "4.5.6",
        "protocol": { "k": 5, "m": 100, "phi_f": 0.65 },
        "next_protocol": { "k": 50, "m": 1000, "phi_f": 0.65 },
        "total_signers": 1234,
        "total_next_signers": 56789,
        "total_stakes_signers": 123456789,
        "total_next_stakes_signers": 987654321,
        "total_cardano_spo": 7777,
        "total_cardano_stake": 888888888
        }"#;

    fn golden_current_message() -> AggregatorStatusMessage {
        AggregatorStatusMessage {
            epoch: Epoch(48),
            cardano_era: "conway".to_string(),
            cardano_network: "mainnet".to_string(),
            mithril_era: SupportedEra::Pythagoras,
            cardano_node_version: "1.2.3".to_string(),
            aggregator_node_version: "4.5.6".to_string(),
            protocol_parameters: ProtocolParameters {
                k: 5,
                m: 100,
                phi_f: 0.65,
            },
            next_protocol_parameters: ProtocolParameters {
                k: 50,
                m: 1000,
                phi_f: 0.65,
            },
            total_signers: 1234,
            total_next_signers: 56789,
            total_stakes_signers: 123456789,
            total_next_stakes_signers: 987654321,
            total_cardano_spo: 7777,
            total_cardano_stake: 888888888,
            leader_aggregator_endpoint: None,
            certificate_chain_aggregator_endpoint: None,
        }
    }

    #[test]
    fn deserializing_a_follower_json_populates_the_followed_aggregator_endpoints() {
        let json = CURRENT_JSON.trim_end().trim_end_matches('}');
        let json = format!(
            r#"{json},
        "leader_aggregator_endpoint": "https://leader.aggregator",
        "certificate_chain_aggregator_endpoint": "https://certificates.aggregator"
        }}"#
        );

        let message: AggregatorStatusMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(
            Some("https://leader.aggregator".to_string()),
            message.leader_aggregator_endpoint
        );
        assert_eq!(
            Some("https://certificates.aggregator".to_string()),
            message.certificate_chain_aggregator_endpoint
        );
    }

    #[test]
    fn serializing_a_leader_message_omits_the_followed_aggregator_endpoints() {
        let json = serde_json::to_string(&golden_current_message()).unwrap();

        assert!(!json.contains("leader_aggregator_endpoint"));
        assert!(!json.contains("certificate_chain_aggregator_endpoint"));
    }

    #[test]
    fn test_current_json_deserialized_into_current_message() {
        let json = CURRENT_JSON;
        let message: AggregatorStatusMessage = serde_json::from_str(json).expect(
            "This JSON is expected to be successfully parsed into a AggregatorStatusMessage instance.",
        );

        assert_eq!(golden_current_message(), message);
    }
}
