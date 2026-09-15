use serde::{Deserialize, Serialize};

use crate::entities::{CardanoTransactionsSigningConfig, Epoch, ProtocolParameters};
use crate::messages::SignerMessagePart;

/// EpochSettings represents the settings of an epoch
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EpochSettingsMessage {
    /// Current Epoch
    pub epoch: Epoch,

    /// Signer Registration Protocol parameters
    #[deprecated(
        since = "0.6.27",
        note = "Will be removed soon. use `mithril-protocol-config` crate instead."
    )]
    #[serde(
        rename = "signer_registration_protocol",
        skip_serializing_if = "Option::is_none"
    )]
    pub signer_registration_protocol_parameters: Option<ProtocolParameters>,

    /// Current Signers
    pub current_signers: Vec<SignerMessagePart>,

    /// Signers that will be able to sign on the next epoch
    pub next_signers: Vec<SignerMessagePart>,

    /// Cardano transactions signing configuration for the current epoch
    #[deprecated(
        since = "0.6.27",
        note = "Will be removed soon. use `mithril-protocol-config` crate instead."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cardano_transactions_signing_config: Option<CardanoTransactionsSigningConfig>,
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto_helper::KesEvolutions,
        entities::{BlockNumber, BlockNumberOffset},
    };

    use super::*;

    const CURRENT_JSON: &str = r#"{
        "epoch": 10,
        "signer_registration_protocol":  { "k": 500, "m": 10000, "phi_f": 0.65 },
        "current_signers":[{
            "party_id":"123",
            "verification_key":"key_123",
            "verification_key_signature":"signature_123",
            "operational_certificate":"certificate_123",
            "kes_period":12
        }],
        "next_signers": [{
            "party_id":"456",
            "verification_key":"key_456",
            "verification_key_signature":"signature_456",
            "operational_certificate":"certificate_456",
            "kes_period":45
        }],
        "cardano_transactions_signing_config": {
            "security_parameter": 70,
            "step": 20
        }
    }"#;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct EpochSettingsMessageUntilV0_1_51 {
        pub epoch: Epoch,
        #[serde(rename = "signer_registration_protocol")]
        pub signer_registration_protocol_parameters: ProtocolParameters,
        pub current_signers: Vec<SignerMessagePart>,
        pub next_signers: Vec<SignerMessagePart>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cardano_transactions_signing_config: Option<CardanoTransactionsSigningConfig>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub next_cardano_transactions_signing_config: Option<CardanoTransactionsSigningConfig>,
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct EpochSettingsMessageUntilV0_1_55 {
        pub epoch: Epoch,
        #[serde(rename = "signer_registration_protocol")]
        pub signer_registration_protocol_parameters: ProtocolParameters,
        pub current_signers: Vec<SignerMessagePart>,
        pub next_signers: Vec<SignerMessagePart>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cardano_transactions_signing_config: Option<CardanoTransactionsSigningConfig>,
    }

    fn golden_message_until_open_api_0_1_51() -> EpochSettingsMessageUntilV0_1_51 {
        EpochSettingsMessageUntilV0_1_51 {
            epoch: Epoch(10),
            signer_registration_protocol_parameters: ProtocolParameters {
                k: 500,
                m: 10000,
                phi_f: 0.65,
            },
            current_signers: vec![SignerMessagePart {
                party_id: "123".to_string(),
                verification_key_for_concatenation: "key_123".to_string(),
                verification_key_signature_for_concatenation: Some("signature_123".to_string()),
                operational_certificate: Some("certificate_123".to_string()),
                kes_evolutions: Some(KesEvolutions(12)),
                #[cfg(feature = "future_snark")]
                verification_key_for_snark: None,
                #[cfg(feature = "future_snark")]
                verification_key_signature_for_snark: None,
                #[cfg(feature = "future_snark")]
                proof_of_bound_possession_for_snark: None,
            }],
            next_signers: vec![SignerMessagePart {
                party_id: "456".to_string(),
                verification_key_for_concatenation: "key_456".to_string(),
                verification_key_signature_for_concatenation: Some("signature_456".to_string()),
                operational_certificate: Some("certificate_456".to_string()),
                kes_evolutions: Some(KesEvolutions(45)),
                #[cfg(feature = "future_snark")]
                verification_key_for_snark: None,
                #[cfg(feature = "future_snark")]
                verification_key_signature_for_snark: None,
                #[cfg(feature = "future_snark")]
                proof_of_bound_possession_for_snark: None,
            }],
            cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(70),
                step: BlockNumber(20),
            }),
            next_cardano_transactions_signing_config: None,
        }
    }

    fn golden_message_until_open_api_0_1_55() -> EpochSettingsMessageUntilV0_1_55 {
        EpochSettingsMessageUntilV0_1_55 {
            epoch: Epoch(10),
            signer_registration_protocol_parameters: ProtocolParameters {
                k: 500,
                m: 10000,
                phi_f: 0.65,
            },
            current_signers: vec![SignerMessagePart {
                party_id: "123".to_string(),
                verification_key_for_concatenation: "key_123".to_string(),
                verification_key_signature_for_concatenation: Some("signature_123".to_string()),
                operational_certificate: Some("certificate_123".to_string()),
                kes_evolutions: Some(KesEvolutions(12)),
                #[cfg(feature = "future_snark")]
                verification_key_for_snark: None,
                #[cfg(feature = "future_snark")]
                verification_key_signature_for_snark: None,
                #[cfg(feature = "future_snark")]
                proof_of_bound_possession_for_snark: None,
            }],
            next_signers: vec![SignerMessagePart {
                party_id: "456".to_string(),
                verification_key_for_concatenation: "key_456".to_string(),
                verification_key_signature_for_concatenation: Some("signature_456".to_string()),
                operational_certificate: Some("certificate_456".to_string()),
                kes_evolutions: Some(KesEvolutions(45)),
                #[cfg(feature = "future_snark")]
                verification_key_for_snark: None,
                #[cfg(feature = "future_snark")]
                verification_key_signature_for_snark: None,
                #[cfg(feature = "future_snark")]
                proof_of_bound_possession_for_snark: None,
            }],
            cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(70),
                step: BlockNumber(20),
            }),
        }
    }

    fn golden_current_message() -> EpochSettingsMessage {
        #[allow(deprecated)]
        EpochSettingsMessage {
            epoch: Epoch(10),
            signer_registration_protocol_parameters: Some(ProtocolParameters {
                k: 500,
                m: 10000,
                phi_f: 0.65,
            }),
            current_signers: vec![SignerMessagePart {
                party_id: "123".to_string(),
                verification_key_for_concatenation: "key_123".to_string(),
                verification_key_signature_for_concatenation: Some("signature_123".to_string()),
                operational_certificate: Some("certificate_123".to_string()),
                kes_evolutions: Some(KesEvolutions(12)),
                #[cfg(feature = "future_snark")]
                verification_key_for_snark: None,
                #[cfg(feature = "future_snark")]
                verification_key_signature_for_snark: None,
                #[cfg(feature = "future_snark")]
                proof_of_bound_possession_for_snark: None,
            }],
            next_signers: vec![SignerMessagePart {
                party_id: "456".to_string(),
                verification_key_for_concatenation: "key_456".to_string(),
                verification_key_signature_for_concatenation: Some("signature_456".to_string()),
                operational_certificate: Some("certificate_456".to_string()),
                kes_evolutions: Some(KesEvolutions(45)),
                #[cfg(feature = "future_snark")]
                verification_key_for_snark: None,
                #[cfg(feature = "future_snark")]
                verification_key_signature_for_snark: None,
                #[cfg(feature = "future_snark")]
                proof_of_bound_possession_for_snark: None,
            }],
            cardano_transactions_signing_config: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(70),
                step: BlockNumber(20),
            }),
        }
    }

    #[test]
    fn test_current_json_deserialized_into_message_supported_until_open_api_0_1_51() {
        let json = CURRENT_JSON;
        let message: EpochSettingsMessageUntilV0_1_51 = serde_json::from_str(json).unwrap();

        assert_eq!(golden_message_until_open_api_0_1_51(), message);
    }

    #[test]
    fn test_current_json_deserialized_into_message_supported_until_open_api_0_1_55() {
        let json = CURRENT_JSON;
        let message: EpochSettingsMessageUntilV0_1_55 = serde_json::from_str(json).unwrap();

        assert_eq!(golden_message_until_open_api_0_1_55(), message);
    }

    #[test]
    fn test_current_json_deserialized_into_current_message() {
        let json = CURRENT_JSON;
        let message: EpochSettingsMessage = serde_json::from_str(json).expect(
            "This JSON is expected to be successfully parsed into a EpochSettingsMessage instance.",
        );

        assert_eq!(golden_current_message(), message);
    }
}
