use std::fmt::{Debug, Formatter};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::StdError;
#[cfg(feature = "future_snark")]
use crate::crypto_helper::GenesisSchnorrSignature;
use crate::entities::{
    Certificate, CertificateMetadata, CertificateSignature, Epoch, ProtocolMessage,
};
use crate::messages::{CertificateMetadataMessagePart, SignedEntityTypeMessage};

/// Message structure of a certificate
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificateMessage {
    /// Hash of the current certificate
    /// Computed from the other fields of the certificate
    /// aka H(Cp,n))
    pub hash: String,

    /// Hash of the previous certificate in the chain
    /// This is either the hash of the first certificate of the epoch in the chain
    /// Or the first certificate of the previous epoch in the chain (if the certificate is the first of its epoch)
    /// aka H(FC(n))
    pub previous_hash: String,

    /// Epoch of the Cardano chain
    pub epoch: Epoch,

    /// The signed entity type of the message.
    /// aka BEACON(p,n)
    pub signed_entity_type: SignedEntityTypeMessage,

    /// Certificate metadata
    /// aka METADATA(p,n)
    pub metadata: CertificateMetadataMessagePart,

    /// Structured message that is used to create the signed message
    /// aka MSG(p,n) U AVK(n-1)
    pub protocol_message: ProtocolMessage,

    /// Message that is signed by the signers
    /// aka H(MSG(p,n) || AVK(n-1))
    pub signed_message: String,

    /// Aggregate verification key for Concatenation
    /// The AVK used to sign for Concatenation during the current epoch
    /// aka AVK(n-2)
    pub aggregate_verification_key: String,

    /// Aggregate verification key for SNARK
    /// The AVK used to sign for SNARK during the current epoch
    /// aka AVKS(n-2)
    #[cfg(feature = "future_snark")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub aggregate_verification_key_snark: Option<String>,

    /// Ancillary data used by the prover to produce the next certificate, hex-encoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ancillary_prover_data: Option<String>,

    /// Ancillary data used to verify the certificate, hex-encoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ancillary_verifier_data: Option<String>,

    /// STM multi signature created from a quorum of single signatures from the signers
    /// aka MULTI_SIG(H(MSG(p,n) || AVK(n-1)))
    pub multi_signature: String,

    /// Genesis signature created from the original stake distribution
    /// aka GENESIS_SIG(AVK(-1))
    pub genesis_signature: String,

    /// SNARK-friendly Schnorr genesis signature carried alongside [Self::genesis_signature]
    /// on Lagrange-era genesis certificates.
    ///
    /// Empty string for Pythagoras and non-genesis certificates. Legacy clients deserialising
    /// this message ignore the field entirely (default to empty), so the wire format remains a
    /// strict superset of the pre-Lagrange one.
    #[cfg(feature = "future_snark")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub genesis_schnorr_signature: String,
}

impl CertificateMessage {
    /// Check that the certificate signed message match the given protocol message.
    pub fn match_message(&self, message: &ProtocolMessage) -> bool {
        message.compute_hash() == self.signed_message
    }

    /// Build a standard certificate's multi-signature from its wire-format parts.
    fn multi_signature_from_message(
        signed_entity_type: SignedEntityTypeMessage,
        multi_signature: String,
    ) -> Result<CertificateSignature, StdError> {
        Ok(CertificateSignature::MultiSignature(
            signed_entity_type.try_into()?,
            multi_signature.try_into().with_context(
                || "Can not convert message to certificate: can not decode the multi-signature",
            )?,
        ))
    }

    /// Build a genesis certificate's signature from its wire-format parts.
    ///
    /// Yields a dual signature when the SNARK half is present, a single Ed25519 signature otherwise.
    fn genesis_signature_from_message(
        genesis_signature: String,
        #[cfg(feature = "future_snark")] genesis_schnorr_signature: String,
    ) -> Result<CertificateSignature, StdError> {
        let concatenation_signature = genesis_signature.try_into().with_context(
            || "Can not convert message to certificate: can not decode the genesis signature",
        )?;
        #[cfg(feature = "future_snark")]
        {
            if genesis_schnorr_signature.is_empty() {
                Ok(CertificateSignature::GenesisSignature(
                    concatenation_signature,
                ))
            } else {
                let snark_bytes = hex::decode(&genesis_schnorr_signature).with_context(|| {
                    "Can not convert message to certificate: SNARK genesis signature is not valid hex"
                })?;
                let snark_signature =
                    GenesisSchnorrSignature::from_bytes(&snark_bytes).with_context(|| {
                        "Can not convert message to certificate: can not decode the SNARK genesis signature"
                    })?;
                Ok(CertificateSignature::GenesisDualSignature(
                    concatenation_signature,
                    snark_signature,
                ))
            }
        }
        #[cfg(not(feature = "future_snark"))]
        {
            Ok(CertificateSignature::GenesisSignature(
                concatenation_signature,
            ))
        }
    }
}

impl Debug for CertificateMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let should_be_exhaustive = f.alternate();
        let mut debug = f.debug_struct("Certificate");
        debug
            .field("hash", &self.hash)
            .field("previous_hash", &self.previous_hash)
            .field("epoch", &format_args!("{:?}", self.epoch))
            .field(
                "signed_entity_type",
                &format_args!("{:?}", self.signed_entity_type),
            )
            .field("metadata", &format_args!("{:?}", self.metadata))
            .field(
                "protocol_message",
                &format_args!("{:?}", self.protocol_message),
            )
            .field("signed_message", &self.signed_message);

        match should_be_exhaustive {
            true => {
                debug.field(
                    "aggregate_verification_key",
                    &self.aggregate_verification_key,
                );
                #[cfg(feature = "future_snark")]
                debug.field(
                    "aggregate_verification_key_snark",
                    &self.aggregate_verification_key_snark,
                );
                debug.field("ancillary_prover_data", &self.ancillary_prover_data);
                debug.field("ancillary_verifier_data", &self.ancillary_verifier_data);
                debug
                    .field("multi_signature", &self.multi_signature)
                    .field("genesis_signature", &self.genesis_signature);
                #[cfg(feature = "future_snark")]
                debug.field("genesis_schnorr_signature", &self.genesis_schnorr_signature);
                debug.finish()
            }
            false => debug.finish_non_exhaustive(),
        }
    }
}

impl TryFrom<CertificateMessage> for Certificate {
    type Error = StdError;

    fn try_from(certificate_message: CertificateMessage) -> Result<Self, Self::Error> {
        let metadata = CertificateMetadata {
            network: certificate_message.metadata.network,
            protocol_version: certificate_message.metadata.protocol_version,
            protocol_parameters: certificate_message.metadata.protocol_parameters,
            initiated_at: certificate_message.metadata.initiated_at,
            sealed_at: certificate_message.metadata.sealed_at,
            signers: certificate_message.metadata.signers,
        };

        let certificate = Certificate {
            hash: certificate_message.hash,
            previous_hash: certificate_message.previous_hash,
            epoch: certificate_message.epoch,
            metadata,
            protocol_message: certificate_message.protocol_message,
            signed_message: certificate_message.signed_message,
            aggregate_verification_key: certificate_message
                .aggregate_verification_key
                .try_into()
                .with_context(|| {
                "Can not convert message to certificate: can not decode the aggregate verification key for Concatenation"
            })?,
            #[cfg(feature = "future_snark")]
            aggregate_verification_key_snark: certificate_message
                .aggregate_verification_key_snark
                .map(|avk| avk.try_into())
                .transpose()
                .with_context(|| {
                "Can not convert message to certificate: can not decode the aggregate verification key for SNARK"
            })?,
            ancillary_prover_data: certificate_message
                .ancillary_prover_data
                .map(|hex_data| hex_data.try_into())
                .transpose()
                .with_context(|| {
                    "Can not convert message to certificate: can not decode the ancillary prover data"
                })?,
            ancillary_verifier_data: certificate_message
                .ancillary_verifier_data
                .map(|hex_data| hex_data.try_into())
                .transpose()
                .with_context(|| {
                    "Can not convert message to certificate: can not decode the ancillary verifier data"
                })?,
            signature: if certificate_message.genesis_signature.is_empty() {
                CertificateMessage::multi_signature_from_message(
                    certificate_message.signed_entity_type,
                    certificate_message.multi_signature,
                )?
            } else {
                CertificateMessage::genesis_signature_from_message(
                    certificate_message.genesis_signature,
                    #[cfg(feature = "future_snark")]
                    certificate_message.genesis_schnorr_signature,
                )?
            },
        };

        Ok(certificate)
    }
}

impl TryFrom<Certificate> for CertificateMessage {
    type Error = StdError;

    fn try_from(certificate: Certificate) -> Result<Self, Self::Error> {
        let signed_entity_type = certificate.signed_entity_type();
        let metadata = CertificateMetadataMessagePart {
            network: certificate.metadata.network,
            protocol_version: certificate.metadata.protocol_version,
            protocol_parameters: certificate.metadata.protocol_parameters,
            initiated_at: certificate.metadata.initiated_at,
            sealed_at: certificate.metadata.sealed_at,
            signers: certificate.metadata.signers,
        };

        #[cfg(feature = "future_snark")]
        let mut genesis_schnorr_signature = String::new();
        let (multi_signature, genesis_signature) = match certificate.signature {
            CertificateSignature::GenesisSignature(signature) => (
                String::new(),
                String::try_from(&signature).with_context(|| {
                    "Can not convert certificate to message: can not encode the genesis signature"
                })?,
            ),
            #[cfg(feature = "future_snark")]
            CertificateSignature::GenesisDualSignature(ed_signature, schnorr_signature) => {
                genesis_schnorr_signature = hex::encode(schnorr_signature.to_bytes());
                (
                    String::new(),
                    String::try_from(&ed_signature).with_context(|| {
                        "Can not convert certificate to message: can not encode the genesis signature"
                    })?,
                )
            }
            CertificateSignature::MultiSignature(_, signature) => (
                String::try_from(&signature).with_context(|| {
                    "Can not convert certificate to message: can not encode the multi-signature"
                })?,
                String::new(),
            ),
        };

        let message = CertificateMessage {
            hash: certificate.hash,
            previous_hash: certificate.previous_hash,
            epoch: certificate.epoch,
            signed_entity_type: signed_entity_type.into(),
            metadata,
            protocol_message: certificate.protocol_message,
            signed_message: certificate.signed_message,
            aggregate_verification_key: String::try_from(&certificate.aggregate_verification_key)
                .with_context(|| {
                    "Can not convert certificate to message: can not encode aggregate verification key for Concatenation"
                })?,
            #[cfg(feature = "future_snark")]
            aggregate_verification_key_snark: certificate
                .aggregate_verification_key_snark
                .map(String::try_from)
                .transpose()
                .with_context(|| {
                    "Can not convert certificate to message: can not encode aggregate verification key for SNARK"
                })?,
            ancillary_prover_data: certificate
                .ancillary_prover_data
                .map(String::try_from)
                .transpose()
                .with_context(|| {
                    "Can not convert certificate to message: can not encode the ancillary prover data"
                })?,
            ancillary_verifier_data: certificate
                .ancillary_verifier_data
                .map(String::try_from)
                .transpose()
                .with_context(|| {
                    "Can not convert certificate to message: can not encode the ancillary verifier data"
                })?,
            multi_signature,
            genesis_signature,
            #[cfg(feature = "future_snark")]
            genesis_schnorr_signature,
        };

        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use crate::entities::{
        CardanoDbBeacon, ProtocolMessagePartKey, ProtocolParameters, SignedEntityType,
        StakeDistributionParty,
    };

    use super::*;

    fn golden_certificate_message() -> CertificateMessage {
        CertificateMessage {
            hash: "hash".to_string(),
            previous_hash: "previous_hash".to_string(),
            epoch: Epoch(10),
            signed_entity_type: SignedEntityType::CardanoDatabase(CardanoDbBeacon::new(
                *Epoch(10),
                1728,
            ))
            .into(),
            metadata: CertificateMetadataMessagePart {
                network: "testnet".to_string(),
                protocol_version: "0.1.0".to_string(),
                protocol_parameters: ProtocolParameters::new(1000, 100, 0.123),
                initiated_at: DateTime::parse_from_rfc3339("2024-02-12T13:11:47Z")
                    .unwrap()
                    .with_timezone(&Utc),
                sealed_at: DateTime::parse_from_rfc3339("2024-02-12T13:12:57Z")
                    .unwrap()
                    .with_timezone(&Utc),
                signers: vec![
                    StakeDistributionParty {
                        party_id: "1".to_string(),
                        stake: 10,
                    },
                    StakeDistributionParty {
                        party_id: "2".to_string(),
                        stake: 20,
                    },
                ],
            },
            protocol_message: {
                let mut protocol_message = ProtocolMessage::new();
                protocol_message.set_message_part(
                    ProtocolMessagePartKey::SnapshotDigest,
                    "snapshot-digest-123".to_string(),
                );
                protocol_message.set_message_part(
                    ProtocolMessagePartKey::NextAggregateVerificationKey,
                    "next-avk-123".to_string(),
                );

                protocol_message
            },
            signed_message: "signed_message".to_string(),
            aggregate_verification_key: "aggregate_verification_key".to_string(),
            #[cfg(feature = "future_snark")]
            aggregate_verification_key_snark: None,
            ancillary_prover_data: None,
            ancillary_verifier_data: None,
            multi_signature: "multi_signature".to_string(),
            genesis_signature: "genesis_signature".to_string(),
            #[cfg(feature = "future_snark")]
            genesis_schnorr_signature: String::new(),
        }
    }

    mod golden_json_serialization {

        use super::*;

        const CURRENT_JSON: &str = r#"{
            "hash": "hash",
            "previous_hash": "previous_hash",
            "epoch": 10,
            "signed_entity_type": {
                "CardanoDatabase": {
                    "epoch": 10,
                    "immutable_file_number": 1728
                }
            },
            "metadata": {
                "network": "testnet",
                "version": "0.1.0",
                "parameters": {
                    "k": 1000,
                    "m": 100,
                    "phi_f": 0.123
                },
            "initiated_at": "2024-02-12T13:11:47Z",
            "sealed_at": "2024-02-12T13:12:57Z",
                "signers": [
                    {
                        "party_id": "1",
                        "verification_key": "7b22766b223a5b3134332c3136312c3235352c34382c37382c35372c3230342c3232302c32352c3232312c3136342c3235322c3234382c31342c35362c3132362c3138362c3133352c3232382c3138382c3134352c3138312c35322c3230302c39372c39392c3231332c34362c302c3139392c3139332c38392c3138372c38382c32392c3133352c3137332c3234342c38362c33362c38332c35342c36372c3136342c362c3133372c39342c37322c362c3130352c3132382c3132382c39332c34382c3137362c31312c342c3234362c3133382c34382c3138302c3133332c39302c3134322c3139322c32342c3139332c3131312c3134322c33312c37362c3131312c3131302c3233342c3135332c39302c3230382c3139322c33312c3132342c39352c3130322c34392c3135382c39392c35322c3232302c3136352c39342c3235312c36382c36392c3132312c31362c3232342c3139345d2c22706f70223a5b3136382c35302c3233332c3139332c31352c3133362c36352c37322c3132332c3134382c3132392c3137362c33382c3139382c3230392c34372c32382c3230342c3137362c3134342c35372c3235312c34322c32382c36362c37362c38392c39372c3135382c36332c35342c3139382c3139342c3137362c3133352c3232312c31342c3138352c3139372c3232352c3230322c39382c3234332c37342c3233332c3232352c3134332c3135312c3134372c3137372c3137302c3131372c36362c3136352c36362c36322c33332c3231362c3233322c37352c36382c3131342c3139352c32322c3130302c36352c34342c3139382c342c3136362c3130322c3233332c3235332c3234302c35392c3137352c36302c3131372c3134322c3131342c3134302c3132322c31372c38372c3131302c3138372c312c31372c31302c3139352c3135342c31332c3234392c38362c35342c3232365d7d",
                        "stake": 10
                    },
                    {
                        "party_id": "2",
                        "verification_key": "7b22766b223a5b3134352c35362c3137352c33322c3132322c3138372c3231342c3232362c3235312c3134382c38382c392c312c3130332c3135392c3134362c38302c3136362c3130372c3234332c3235312c3233362c34312c32382c3131312c3132382c3230372c3136342c3133322c3134372c3232382c38332c3234362c3232382c3137302c36382c38392c37382c36302c32382c3132332c3133302c38382c3233342c33382c39372c34322c36352c312c3130302c35332c31382c37382c3133312c382c36312c3132322c3133312c3233382c38342c3233332c3232332c3135342c3131382c3131382c37332c32382c32372c3130312c37382c38302c3233332c3132332c3230362c3232302c3137342c3133342c3230352c37312c3131302c3131322c3138302c39372c39382c302c3131332c36392c3134352c3233312c3136382c34332c3137332c3137322c35362c3130342c3230385d2c22706f70223a5b3133372c3231342c37352c37352c3134342c3136312c3133372c37392c39342c3134302c3138312c34372c33312c38312c3231332c33312c3137312c3231362c32342c3137342c37382c3234382c3133302c37352c3235352c31312c3134352c3132342c36312c38302c3139302c32372c3231362c3130352c3130362c3234382c39312c3134332c3230342c3130322c3230332c3136322c37362c3130372c31352c35322c36312c38322c3134362c3133302c3132342c37342c382c33342c3136342c3138372c3230332c38322c36342c3130382c3139312c3138352c3138382c37372c3132322c352c3234362c3235352c3130322c3131392c3234372c3139392c3131372c36372c3234312c3134332c32392c3136382c36372c39342c3135312c37382c3132392c3133312c33302c3130312c3137332c31302c36392c36382c3137352c39382c33372c3233392c3139342c32395d7d",
                        "stake": 20
                    }
                ]
            },
            "protocol_message": {
                "message_parts": {
                    "snapshot_digest": "snapshot-digest-123",
                    "next_aggregate_verification_key": "next-avk-123"
                }
            },
            "signed_message": "signed_message",
            "aggregate_verification_key": "aggregate_verification_key",
            "multi_signature": "multi_signature",
            "genesis_signature": "genesis_signature"
        }"#;

        fn golden_current_message() -> CertificateMessage {
            golden_certificate_message()
        }

        #[test]
        fn test_current_json_deserialized_into_current_message() {
            let json = CURRENT_JSON;
            let message: CertificateMessage = serde_json::from_str(json).unwrap();

            assert_eq!(golden_current_message(), message);
        }
    }

    mod golden_protocol_key_encodings {
        use super::*;

        mod standard_certificate {
            use super::*;

            fn golden_message_with_json_hex_encoding() -> CertificateMessage {
                CertificateMessage {
                    aggregate_verification_key: "7b226d745f636f6d6d69746d656e74223a7b22726f6f74223a5b3234312c3235352c35332c3133352c3231322c3134322c33372c3131342c3133302c3131372c3135342c3230382c34392c3134352c31362c3132382c3230392c37352c3137392c32392c35392c3136352c3134352c3235302c34372c332c3233312c3134302c3137382c35302c3231322c3131345d2c226e725f6c6561766573223a342c22686173686572223a6e756c6c7d2c22746f74616c5f7374616b65223a33303337393438363730323339327d".to_string(),
                    multi_signature: "7b227369676e617475726573223a5b5b7b227369676d61223a5b3135302c3132312c3230322c3133322c33362c34392c3230342c3137332c35392c3130322c3130382c36362c32322c3230342c3130372c3235302c36352c3136372c3230302c3233372c32312c31372c37382c3233382c34332c3232372c3234382c38392c3136362c3232322c3134352c36382c33312c3134322c3231302c3232342c3139322c3233342c38362c3134372c36362c37302c3132332c33332c39382c37372c3138382c3136375d2c22696e6465786573223a5b352c31332c32322c33312c37312c37355d2c227369676e65725f696e646578223a307d2c5b5b3135302c37362c3234362c3133302c3130352c3136372c3138372c3230372c39382c3132332c3134382c3133322c3132342c3234372c33372c3133342c32332c3137322c312c3138352c3133302c3235312c3138312c38302c36382c3137342c3131362c3139302c3231372c37312c33342c33372c3134302c3139342c3234342c3138342c3136322c3136392c3137302c37322c3139312c3138372c3232392c3136362c34372c3139362c3133392c3233332c372c38372c3232352c392c3139332c37332c3138312c3233352c35342c3135322c312c3133382c34382c3130332c36392c3230392c35322c34302c31372c32312c3134372c37332c3232352c37302c392c3233342c3233362c342c37312c33382c38392c3232352c32342c3131362c392c3133302c3139352c3139362c3233312c3133312c3230332c37372c39372c3230322c36332c3132382c3132332c3230335d2c313030393439373632393034365d5d5d2c2262617463685f70726f6f66223a7b2276616c756573223a5b5b3130312c3230302c3136392c3231322c3135312c3133352c35362c35312c3232312c3138392c3138352c3230322c3232362c3132312c3138332c36382c3135372c3132352c32342c3232332c3135312c38392c3235342c32372c32332c372c3230392c32312c3136372c3234332c322c3131345d2c5b3138352c3134312c3139392c362c3131342c3134342c3235352c37312c3138302c36342c3135332c33322c37362c372c3234392c3137342c3134312c3230302c3131382c3231312c302c31392c3232352c3134392c3133372c33362c3134312c35302c3134382c38312c3137322c3139325d5d2c22696e6469636573223a5b305d2c22686173686572223a6e756c6c7d7d".to_string(),
                    genesis_signature: "".to_string(),
                    ..golden_certificate_message()
                }
            }

            fn golden_message_with_bytes_hex_encoding() -> CertificateMessage {
                CertificateMessage {
                    aggregate_verification_key: "00000000000000000404036cb79141a645faca33405ae82d67388a663fd1f55116781006608cccd2370000000000000006".to_string(),
                    multi_signature: "00000000000000000100000000000000e80000000000000068964cf68269a7bbcf627b94847cf7258617ac01b982fbb55044ae74bed94722258cc2f4b8a2a9aa48bfbbe5a62fc48be90757e109c149b5eb3698018a306745d1342811159349e14609eaec04472659e118740982c3c4e783cb4d61ca3f807bcb000000eb0abf6176000000000000007000000000000000060000000000000005000000000000000d0000000000000016000000000000001f0000000000000047000000000000004b9679ca842431ccad3b666c4216cc6bfa41a7c8ed15114eee2be3f859a6de91441f8ed2e0c0ea569342467b21624dbca700000000000000000000000000000002000000000000000165c8a9d497873833ddbdb9cae279b7449d7d18df9759fe1b1707d115a7f30272b98dc7067290ff47b44099204c07f9ae8dc876d30013e19589248d329451acc00000000000000000".to_string(),
                    genesis_signature: "".to_string(),
                    ..golden_certificate_message()
                }
            }

            #[test]
            fn restorations_from_json_hex_and_bytes_hex_give_same_certificate() {
                let certificate_from_json_hex: Certificate =
                    golden_message_with_json_hex_encoding().try_into().unwrap();
                let certificate_from_bytes_hex: Certificate =
                    golden_message_with_bytes_hex_encoding().try_into().unwrap();

                assert_eq!(certificate_from_json_hex, certificate_from_bytes_hex);
            }
        }

        mod genesis_certificate {
            use super::*;

            fn golden_message_with_bytes_hex_encoding() -> CertificateMessage {
                CertificateMessage {
                    aggregate_verification_key: "00000000000000000404036cb79141a645faca33405ae82d67388a663fd1f55116781006608cccd2370000000000000006".to_string(),
                    multi_signature: "".to_string(),
                    genesis_signature: "c21f77fb812a8111b547c2145d765f854ca224b17e883d6483b668a8c4d095fd893efd2a2ba1d41da9f49d82bf02d8ee603791998b64436000e49184c000170b".to_string(),
                    ..golden_certificate_message()
                }
            }

            #[test]
            fn restorations_from_bytes_hex_succeeds() {
                let _certificate_from_bytes_hex: Certificate =
                    golden_message_with_bytes_hex_encoding().try_into().unwrap();
            }
        }

        #[cfg(feature = "future_snark")]
        mod certificate_with_snark_avk {
            use super::*;

            fn golden_message_with_snark_avk() -> CertificateMessage {
                CertificateMessage {
                    aggregate_verification_key: "00000000000000000404036cb79141a645faca33405ae82d67388a663fd1f55116781006608cccd2370000000000000006".to_string(),
                    aggregate_verification_key_snark: Some("22184a6a150661134dc2a5f2aa241fce222cecabe3ec3a6aad67f5bbe187be670000000000000003".to_string()),
                    multi_signature: "".to_string(),
                    genesis_signature: "c21f77fb812a8111b547c2145d765f854ca224b17e883d6483b668a8c4d095fd893efd2a2ba1d41da9f49d82bf02d8ee603791998b64436000e49184c000170b".to_string(),
                    ..golden_certificate_message()
                }
            }

            #[test]
            fn restorations_from_bytes_hex_succeeds_with_snark_avk() {
                let _certificate: Certificate = golden_message_with_snark_avk().try_into().unwrap();
            }

            #[test]
            fn json_round_trip_preserves_snark_avk() {
                let message = golden_message_with_snark_avk();
                let json = serde_json::to_string(&message).unwrap();
                let deserialized: CertificateMessage = serde_json::from_str(&json).unwrap();

                assert_eq!(message, deserialized);
                assert!(
                    json.contains("aggregate_verification_key_snark"),
                    "JSON should contain the SNARK AVK field"
                );
            }

            #[test]
            fn json_without_snark_avk_deserializes_to_none() {
                let mut message = golden_message_with_snark_avk();
                message.aggregate_verification_key_snark = None;
                let json = serde_json::to_string(&message).unwrap();

                let deserialized: CertificateMessage = serde_json::from_str(&json).unwrap();

                assert_eq!(deserialized.aggregate_verification_key_snark, None);
            }
        }

        #[cfg(feature = "future_snark")]
        mod dual_genesis_certificate {
            use rand_chacha::ChaCha20Rng;
            use rand_core::SeedableRng;

            use crate::crypto_helper::GenesisSchnorrSigner;

            use super::*;

            fn golden_dual_genesis_message() -> CertificateMessage {
                let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
                let schnorr_signer = GenesisSchnorrSigner::generate(&mut rng);
                let snark_signature = schnorr_signer.sign(&[0u8; 32], &mut rng).unwrap();

                CertificateMessage {
                    aggregate_verification_key: "00000000000000000404036cb79141a645faca33405ae82d67388a663fd1f55116781006608cccd2370000000000000006".to_string(),
                    multi_signature: "".to_string(),
                    genesis_signature: "c21f77fb812a8111b547c2145d765f854ca224b17e883d6483b668a8c4d095fd893efd2a2ba1d41da9f49d82bf02d8ee603791998b64436000e49184c000170b".to_string(),
                    genesis_schnorr_signature: hex::encode(snark_signature.to_bytes()),
                    ..golden_certificate_message()
                }
            }

            #[test]
            fn dual_signature_message_decodes_into_dual_certificate_variant() {
                let message = golden_dual_genesis_message();
                let certificate: Certificate = message.try_into().unwrap();

                assert!(matches!(
                    certificate.signature,
                    CertificateSignature::GenesisDualSignature(_, _)
                ));
            }

            #[test]
            fn empty_genesis_schnorr_signature_yields_legacy_genesis_variant() {
                let mut message = golden_dual_genesis_message();
                message.genesis_schnorr_signature.clear();
                let certificate: Certificate = message.try_into().unwrap();

                assert!(matches!(
                    certificate.signature,
                    CertificateSignature::GenesisSignature(_)
                ));
            }

            #[test]
            fn round_trip_preserves_dual_signature_variant() {
                let original = golden_dual_genesis_message();
                let certificate: Certificate = original.clone().try_into().unwrap();
                let restored: CertificateMessage = certificate.try_into().unwrap();

                assert_eq!(original.genesis_signature, restored.genesis_signature);
                assert_eq!(
                    original.genesis_schnorr_signature,
                    restored.genesis_schnorr_signature,
                );
            }

            #[test]
            fn archived_pre_lagrange_json_without_snark_field_still_deserialises() {
                let archived_json = serde_json::json!({
                    "hash": "hash",
                    "previous_hash": "previous_hash",
                    "epoch": 10,
                    "signed_entity_type": {
                        "MithrilStakeDistribution": 10,
                    },
                    "metadata": {
                        "network": "testnet",
                        "version": "0.1.0",
                        "parameters": {"k": 1000, "m": 100, "phi_f": 0.123},
                        "initiated_at": "2024-02-12T13:11:47Z",
                        "sealed_at": "2024-02-12T13:12:57Z",
                        "signers": []
                    },
                    "protocol_message": { "message_parts": {} },
                    "signed_message": "signed_message",
                    "aggregate_verification_key": "agg",
                    "multi_signature": "ms",
                    "genesis_signature": "gs",
                });

                let message: CertificateMessage =
                    serde_json::from_value(archived_json).expect("archived JSON must deserialise");

                assert_eq!(message.genesis_schnorr_signature, "");
            }

            mod golden_json_serialization {
                use super::*;

                const GOLDEN_DUAL_JSON: &str = r#"{"hash":"hash","previous_hash":"previous_hash","epoch":10,"signed_entity_type":{"CardanoDatabase":{"epoch":10,"immutable_file_number":1728}},"metadata":{"network":"testnet","version":"0.1.0","parameters":{"k":1000,"m":100,"phi_f":0.123},"initiated_at":"2024-02-12T13:11:47Z","sealed_at":"2024-02-12T13:12:57Z","signers":[{"party_id":"1","stake":10},{"party_id":"2","stake":20}]},"protocol_message":{"message_parts":{"snapshot_digest":"snapshot-digest-123","next_aggregate_verification_key":"next-avk-123"}},"signed_message":"signed_message","aggregate_verification_key":"aggregate_verification_key","multi_signature":"","genesis_signature":"c21f77fb812a8111b547c2145d765f854ca224b17e883d6483b668a8c4d095fd893efd2a2ba1d41da9f49d82bf02d8ee603791998b64436000e49184c000170b","genesis_schnorr_signature":"4e62a6e0432f63da06d9c2b7e3aeed4f0e1cd0f6b06e5dabb7d96fe33b3cdc1e1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"}"#;

                fn golden_dual_message_with_fixed_snark() -> CertificateMessage {
                    CertificateMessage {
                        multi_signature: "".to_string(),
                        genesis_signature: "c21f77fb812a8111b547c2145d765f854ca224b17e883d6483b668a8c4d095fd893efd2a2ba1d41da9f49d82bf02d8ee603791998b64436000e49184c000170b".to_string(),
                        genesis_schnorr_signature: "4e62a6e0432f63da06d9c2b7e3aeed4f0e1cd0f6b06e5dabb7d96fe33b3cdc1e1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                        ..golden_certificate_message()
                    }
                }

                #[test]
                fn pinned_dual_signature_json_round_trips_into_message_and_back() {
                    let json = GOLDEN_DUAL_JSON;
                    let deserialized: CertificateMessage = serde_json::from_str(json).unwrap();

                    assert_eq!(golden_dual_message_with_fixed_snark(), deserialized);
                    let reserialized = serde_json::to_string(&deserialized).unwrap();
                    assert_eq!(reserialized, json);
                }

                #[test]
                fn dual_signature_field_is_present_in_serialised_wire_form() {
                    let message = golden_dual_message_with_fixed_snark();

                    let json_value: serde_json::Value = serde_json::to_value(&message).unwrap();

                    assert_eq!(
                        json_value.get("genesis_schnorr_signature").and_then(|v| v.as_str()),
                        Some(message.genesis_schnorr_signature.as_str()),
                        "genesis_schnorr_signature field must appear in the wire form when set",
                    );
                }
            }
        }
    }

    mod multi_signature_encoding {
        use crate::test::double::fake_data;

        use super::*;

        #[test]
        fn concatenation_multi_signature_is_encoded_as_json_hex() {
            let certificate = fake_data::certificate("hash");
            let expected_json_hex = match &certificate.signature {
                CertificateSignature::MultiSignature(_, signature) => {
                    signature.to_json_hex().unwrap()
                }
                _ => panic!("expected a multi-signature certificate"),
            };

            let message = CertificateMessage::try_from(certificate).unwrap();

            assert_eq!(expected_json_hex, message.multi_signature);
        }

        #[cfg(feature = "future_snark")]
        #[test]
        fn snark_multi_signature_is_encoded_as_bytes_hex() {
            let snark_signature = fake_data::snark_aggregate_signature();
            let expected_bytes_hex = snark_signature.to_bytes_hex().unwrap();
            let mut certificate = fake_data::certificate("hash");
            let signed_entity_type = match &certificate.signature {
                CertificateSignature::MultiSignature(signed_entity_type, _) => {
                    signed_entity_type.clone()
                }
                _ => panic!("expected a multi-signature certificate"),
            };
            certificate.signature =
                CertificateSignature::MultiSignature(signed_entity_type, snark_signature);

            let message = CertificateMessage::try_from(certificate).unwrap();

            assert_eq!(expected_bytes_hex, message.multi_signature);
        }
    }
}
