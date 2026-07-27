use chrono::{DateTime, Utc};

use mithril_common::StdError;
#[cfg(feature = "future_snark")]
use mithril_common::crypto_helper::{schnorr_signature_from_hex, schnorr_signature_to_hex};
use mithril_common::entities::{
    Certificate, CertificateMetadata, CertificateSignature, Epoch,
    HexEncodedAggregateVerificationKey, HexEncodedKey, HexEncodedVerificationKeyForSnark,
    ProtocolMessage, ProtocolParameters, ProtocolVersion, SignedEntityType, StakeDistributionParty,
};
use mithril_common::messages::{
    CertificateListItemMessage, CertificateListItemMessageMetadata, CertificateMessage,
    CertificateMetadataMessagePart,
};
#[cfg(test)]
use mithril_common::{
    entities::{CardanoDbBeacon, ImmutableFileNumber},
    test::double::{fake_data, fake_keys},
};
use mithril_persistence::{
    database::Hydrator,
    sqlite::{HydrationError, Projection, SqLiteEntity},
};
#[cfg(feature = "future_snark")]
use serde::{Deserialize, Serialize};

/// JSON-serialised wrapper holding both signatures of a Lagrange-era dual genesis signature.
///
/// Stored in the `signature` column so the SQLite round-trip preserves the SNARK half. Legacy
/// Pythagoras records keep the raw Ed25519 hex string in the same column; deserialisation
/// attempts this JSON wrapper first and falls back to the raw hex when the input is not JSON.
#[cfg(feature = "future_snark")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedDualGenesisSignature {
    /// Hex-encoded Ed25519 (ed25519) genesis signature.
    ed25519: HexEncodedKey,

    /// Hex-encoded SNARK-friendly Schnorr genesis signature.
    schnorr: HexEncodedKey,
}

/// Wire-format signature of a [CertificateMessage] reconstructed from a stored [CertificateRecord].
///
/// A stored certificate carries exactly one of these signature shapes, so the variants are
/// mutually exclusive by construction.
#[cfg(feature = "future_snark")]
enum PersistedRecordSignatures {
    /// Multi-signature carried by a standard (non-genesis) certificate.
    MultiSignature(HexEncodedKey),

    /// Legacy Pythagoras-era genesis signature (Ed25519 only).
    Genesis(HexEncodedKey),

    /// Lagrange-era dual genesis signature pairing the Ed25519 and Schnorr halves.
    GenesisDual(PersistedDualGenesisSignature),
}

#[cfg(feature = "future_snark")]
impl PersistedDualGenesisSignature {
    /// Parse a persisted genesis signature column value.
    ///
    /// Attempts to decode the JSON wrapper (Lagrange dual signature) and falls back to the raw
    /// Ed25519 hex string used by Pythagoras-era records.
    fn parse_genesis_signature(raw: &str) -> Result<CertificateSignature, StdError> {
        if let Ok(payload) = serde_json::from_str::<Self>(raw) {
            let ed25519 = payload.ed25519.as_str().try_into()?;
            let schnorr = schnorr_signature_from_hex(&payload.schnorr)?;
            return Ok(CertificateSignature::GenesisDualSignature(ed25519, schnorr));
        }
        Ok(CertificateSignature::GenesisSignature(raw.try_into()?))
    }

    /// Classify a stored signature column value into its wire-format shape.
    ///
    /// Recovers the SNARK half from the JSON wrapper when present; otherwise treats the value as
    /// a legacy Ed25519-only genesis signature, or a multi-signature when the record has a parent.
    /// Takes the signature by value so the caller can move it in, avoiding a clone per certificate.
    fn split_message_signatures(
        have_parent: bool,
        signature: HexEncodedKey,
    ) -> PersistedRecordSignatures {
        if have_parent {
            PersistedRecordSignatures::MultiSignature(signature)
        } else if let Ok(payload) = serde_json::from_str::<Self>(&signature) {
            PersistedRecordSignatures::GenesisDual(payload)
        } else {
            PersistedRecordSignatures::Genesis(signature)
        }
    }
}

/// Certificate record is the representation of a stored certificate.
#[derive(Debug, PartialEq, Clone)]
pub struct CertificateRecord {
    /// Certificate id.
    pub certificate_id: String,

    /// Parent Certificate id.
    pub parent_certificate_id: Option<String>,

    /// Message that is signed.
    pub message: String,

    /// Signature of the certificate.
    /// Note: multi-signature if parent certificate id is set, genesis signature otherwise.
    pub signature: HexEncodedKey,

    /// Aggregate verification key
    /// Note: used only if signature is a multi-signature
    pub aggregate_verification_key: HexEncodedAggregateVerificationKey,

    /// Aggregate verification key for SNARK
    pub aggregate_verification_key_snark: Option<HexEncodedVerificationKeyForSnark>,

    /// Ancillary data used by the prover to produce the next certificate, hex-encoded.
    pub ancillary_prover_data: Option<HexEncodedKey>,

    /// Ancillary data used to verify the certificate, hex-encoded.
    pub ancillary_verifier_data: Option<HexEncodedKey>,

    /// Epoch of creation of the certificate.
    pub epoch: Epoch,

    /// Cardano network of the certificate.
    pub network: String,

    /// Signed entity type of the message
    pub signed_entity_type: SignedEntityType,

    /// Protocol Version (semver)
    pub protocol_version: ProtocolVersion,

    /// Protocol parameters.
    pub protocol_parameters: ProtocolParameters,

    /// Structured message that is used to create the signed message
    pub protocol_message: ProtocolMessage,

    /// The list of the active signers with their stakes
    pub signers: Vec<StakeDistributionParty>,

    /// Date and time when the certificate was initiated
    pub initiated_at: DateTime<Utc>,

    /// Date and time when the certificate was sealed
    pub sealed_at: DateTime<Utc>,
}

#[cfg(test)]
impl CertificateRecord {
    pub(crate) fn dummy_genesis(id: &str, epoch: Epoch) -> Self {
        Self {
            parent_certificate_id: None,
            signature: fake_keys::genesis_signature()[0].to_owned(),
            ..Self::dummy(id, "", epoch, SignedEntityType::genesis(epoch))
        }
    }

    pub(crate) fn dummy_db_snapshot(
        id: &str,
        parent_id: &str,
        epoch: Epoch,
        immutable_file_number: ImmutableFileNumber,
    ) -> Self {
        Self::dummy(
            id,
            parent_id,
            epoch,
            SignedEntityType::CardanoDatabase(CardanoDbBeacon::new(*epoch, immutable_file_number)),
        )
    }

    pub(crate) fn dummy(
        id: &str,
        parent_id: &str,
        epoch: Epoch,
        signed_entity_type: SignedEntityType,
    ) -> Self {
        Self {
            certificate_id: id.to_string(),
            parent_certificate_id: Some(parent_id.to_string()),
            message: "message".to_string(),
            signature: fake_keys::multi_signature()[0].to_owned(),
            aggregate_verification_key: fake_keys::aggregate_verification_key_for_concatenation()
                [0]
            .to_owned(),
            aggregate_verification_key_snark: None,
            ancillary_prover_data: None,
            ancillary_verifier_data: None,
            epoch,
            network: fake_data::network().to_string(),
            signed_entity_type,
            protocol_version: "protocol_version".to_string(),
            protocol_parameters: ProtocolParameters {
                k: 0,
                m: 0,
                phi_f: 0.0,
            },
            protocol_message: Default::default(),
            signers: vec![],
            initiated_at: DateTime::parse_from_rfc3339("2024-02-12T13:11:47Z")
                .unwrap()
                .with_timezone(&Utc),
            sealed_at: DateTime::parse_from_rfc3339("2024-02-12T13:12:57Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }
}

impl TryFrom<Certificate> for CertificateRecord {
    type Error = StdError;

    fn try_from(other: Certificate) -> Result<Self, Self::Error> {
        let signed_entity_type = other.signed_entity_type();
        let (signature, parent_certificate_id) = match other.signature {
            CertificateSignature::GenesisSignature(signature) => {
                (String::try_from(&signature)?, None)
            }
            #[cfg(feature = "future_snark")]
            CertificateSignature::GenesisDualSignature(ed_signature, schnorr_signature) => {
                let payload = PersistedDualGenesisSignature {
                    ed25519: String::try_from(&ed_signature)?,
                    schnorr: schnorr_signature_to_hex(&schnorr_signature),
                };
                (serde_json::to_string(&payload)?, None)
            }
            CertificateSignature::MultiSignature(_, signature) => {
                (String::try_from(&signature)?, Some(other.previous_hash))
            }
        };

        #[cfg(feature = "future_snark")]
        let aggregate_verification_key_snark = other
            .aggregate_verification_key_snark
            .as_ref()
            .map(String::try_from)
            .transpose()?;
        #[cfg(not(feature = "future_snark"))]
        let aggregate_verification_key_snark: Option<HexEncodedKey> = None;

        let ancillary_prover_data = other
            .ancillary_prover_data
            .as_ref()
            .map(String::try_from)
            .transpose()?;
        let ancillary_verifier_data = other
            .ancillary_verifier_data
            .as_ref()
            .map(String::try_from)
            .transpose()?;

        let certificate_record = CertificateRecord {
            certificate_id: other.hash,
            parent_certificate_id,
            message: other.signed_message,
            signature,
            aggregate_verification_key: String::try_from(&other.aggregate_verification_key)?,
            aggregate_verification_key_snark,
            ancillary_prover_data,
            ancillary_verifier_data,
            epoch: other.epoch,
            network: other.metadata.network,
            signed_entity_type,
            protocol_version: other.metadata.protocol_version,
            protocol_parameters: other.metadata.protocol_parameters,
            protocol_message: other.protocol_message,
            signers: other.metadata.signers,
            initiated_at: other.metadata.initiated_at,
            sealed_at: other.metadata.sealed_at,
        };

        Ok(certificate_record)
    }
}

impl TryFrom<CertificateRecord> for Certificate {
    type Error = StdError;

    fn try_from(other: CertificateRecord) -> Result<Self, Self::Error> {
        let certificate_metadata = CertificateMetadata::new(
            other.network,
            other.protocol_version,
            other.protocol_parameters,
            other.initiated_at,
            other.sealed_at,
            other.signers,
        );
        let (previous_hash, signature) = match other.parent_certificate_id {
            None => {
                #[cfg(feature = "future_snark")]
                let signature =
                    PersistedDualGenesisSignature::parse_genesis_signature(&other.signature)?;
                #[cfg(not(feature = "future_snark"))]
                let signature =
                    CertificateSignature::GenesisSignature(other.signature.as_str().try_into()?);
                (String::new(), signature)
            }
            Some(parent_certificate_id) => (
                parent_certificate_id,
                CertificateSignature::MultiSignature(
                    other.signed_entity_type,
                    other.signature.try_into()?,
                ),
            ),
        };

        #[cfg(feature = "future_snark")]
        let aggregate_verification_key_snark = other
            .aggregate_verification_key_snark
            .map(|hex| hex.as_str().try_into())
            .transpose()?;

        let ancillary_prover_data = other
            .ancillary_prover_data
            .map(|hex_data| hex_data.try_into())
            .transpose()?;
        let ancillary_verifier_data = other
            .ancillary_verifier_data
            .map(|hex_data| hex_data.try_into())
            .transpose()?;

        let certificate = Certificate {
            hash: other.certificate_id,
            previous_hash,
            epoch: other.epoch,
            metadata: certificate_metadata,
            signed_message: other.protocol_message.compute_hash(),
            protocol_message: other.protocol_message,
            aggregate_verification_key: other.aggregate_verification_key.try_into()?,
            #[cfg(feature = "future_snark")]
            aggregate_verification_key_snark,
            ancillary_prover_data,
            ancillary_verifier_data,
            signature,
        };

        Ok(certificate)
    }
}

impl From<CertificateRecord> for CertificateMessage {
    fn from(value: CertificateRecord) -> Self {
        #[cfg(feature = "future_snark")]
        let (multi_signature, genesis_signature, genesis_schnorr_signature) =
            match PersistedDualGenesisSignature::split_message_signatures(
                value.parent_certificate_id.is_some(),
                value.signature,
            ) {
                PersistedRecordSignatures::MultiSignature(signature) => {
                    (signature, String::new(), String::new())
                }
                PersistedRecordSignatures::Genesis(signature) => {
                    (String::new(), signature, String::new())
                }
                PersistedRecordSignatures::GenesisDual(payload) => {
                    (String::new(), payload.ed25519, payload.schnorr)
                }
            };
        #[cfg(not(feature = "future_snark"))]
        let (multi_signature, genesis_signature) = if value.parent_certificate_id.is_none() {
            (String::new(), value.signature)
        } else {
            (value.signature, String::new())
        };
        let metadata = CertificateMetadataMessagePart {
            network: value.network,
            protocol_version: value.protocol_version,
            protocol_parameters: value.protocol_parameters,
            initiated_at: value.initiated_at,
            sealed_at: value.sealed_at,
            signers: value.signers,
        };

        CertificateMessage {
            hash: value.certificate_id,
            previous_hash: value.parent_certificate_id.unwrap_or_default(),
            epoch: value.epoch,
            signed_entity_type: value.signed_entity_type.into(),
            metadata,
            protocol_message: value.protocol_message,
            signed_message: value.message,
            aggregate_verification_key: value.aggregate_verification_key,
            #[cfg(feature = "future_snark")]
            aggregate_verification_key_snark: value.aggregate_verification_key_snark,
            ancillary_prover_data: value.ancillary_prover_data,
            ancillary_verifier_data: value.ancillary_verifier_data,
            multi_signature,
            genesis_signature,
            #[cfg(feature = "future_snark")]
            genesis_schnorr_signature,
        }
    }
}

impl From<CertificateRecord> for CertificateListItemMessage {
    fn from(value: CertificateRecord) -> Self {
        let metadata = CertificateListItemMessageMetadata {
            network: value.network,
            protocol_version: value.protocol_version,
            protocol_parameters: value.protocol_parameters,
            initiated_at: value.initiated_at,
            sealed_at: value.sealed_at,
            total_signers: value.signers.len(),
        };

        CertificateListItemMessage {
            hash: value.certificate_id,
            previous_hash: value.parent_certificate_id.unwrap_or_default(),
            epoch: value.epoch,
            signed_entity_type: value.signed_entity_type.into(),
            metadata,
            protocol_message: value.protocol_message,
            signed_message: value.message,
            aggregate_verification_key: value.aggregate_verification_key,
        }
    }
}

impl SqLiteEntity for CertificateRecord {
    fn hydrate(row: sqlite::Row) -> Result<Self, HydrationError>
    where
        Self: Sized,
    {
        let certificate_id = row.read::<&str, _>(0).to_string();
        let parent_certificate_id = row.read::<Option<&str>, _>(1).map(|s| s.to_owned());
        let message = row.read::<&str, _>(2).to_string();
        let signature = row.read::<&str, _>(3).to_string();
        let aggregate_verification_key = row.read::<&str, _>(4).to_string();
        let aggregate_verification_key_snark: Option<String> =
            row.read::<Option<&str>, _>(5).map(|s| s.to_owned());
        let epoch_int = row.read::<i64, _>(6);
        let network = row.read::<&str, _>(7).to_string();
        let signed_entity_type_id = row.read::<i64, _>(8);
        let signed_entity_beacon_string = Hydrator::read_signed_entity_beacon_column(&row, 9);
        let protocol_version = row.read::<&str, _>(10).to_string();
        let protocol_parameters_string = row.read::<&str, _>(11);
        let protocol_message_string = row.read::<&str, _>(12);
        let signers_string = row.read::<&str, _>(13);
        let initiated_at = row.read::<&str, _>(14);
        let sealed_at = row.read::<&str, _>(15);
        let ancillary_prover_data = row.read::<Option<&str>, _>(16).map(|s| s.to_owned());
        let ancillary_verifier_data = row.read::<Option<&str>, _>(17).map(|s| s.to_owned());

        let certificate_record = Self {
            certificate_id,
            parent_certificate_id,
            message,
            signature,
            aggregate_verification_key,
            aggregate_verification_key_snark,
            ancillary_prover_data,
            ancillary_verifier_data,
            epoch: Epoch(epoch_int.try_into().map_err(|e| {
                HydrationError::InvalidData(format!(
                    "Could not cast i64 ({epoch_int}) to u64. Error: '{e}'"
                ))
            })?),
            network,
            signed_entity_type: Hydrator::hydrate_signed_entity_type(
                signed_entity_type_id.try_into().map_err(|e| {
                    HydrationError::InvalidData(format!(
                        "Could not cast i64 ({signed_entity_type_id}) to u16. Error: '{e}'"
                    ))
                })?,
                &signed_entity_beacon_string,
            )?,
            protocol_version,
            protocol_parameters: serde_json::from_str(protocol_parameters_string).map_err(
                |e| {
                    HydrationError::InvalidData(format!(
                        "Could not turn string '{protocol_parameters_string}' to ProtocolParameters. Error: {e}"
                    ))
                },
            )?,
            protocol_message: serde_json::from_str(protocol_message_string).map_err(
                |e| {
                    HydrationError::InvalidData(format!(
                        "Could not turn string '{protocol_message_string}' to ProtocolMessage. Error: {e}"
                    ))
                },
            )?,
            signers: serde_json::from_str(signers_string).map_err(
                |e| {
                    HydrationError::InvalidData(format!(
                        "Could not turn string '{signers_string}' to Vec<StakeDistributionParty>. Error: {e}"
                    ))
                },
            )?,
            initiated_at: DateTime::parse_from_rfc3339(initiated_at).map_err(
                |e| {
                    HydrationError::InvalidData(format!(
                        "Could not turn string '{initiated_at}' to rfc3339 Datetime. Error: {e}"
                    ))
                },
            )?.with_timezone(&Utc),
            sealed_at: DateTime::parse_from_rfc3339(sealed_at).map_err(
                |e| {
                    HydrationError::InvalidData(format!(
                        "Could not turn string '{sealed_at}' to rfc3339 Datetime. Error: {e}"
                    ))
                },
            )?.with_timezone(&Utc),
        };

        Ok(certificate_record)
    }

    fn get_projection() -> Projection {
        let mut projection = Projection::default();
        projection.add_field("certificate_id", "{:certificate:}.certificate_id", "text");
        projection.add_field(
            "parent_certificate_id",
            "{:certificate:}.parent_certificate_id",
            "text",
        );
        projection.add_field("message", "{:certificate:}.message", "text");
        projection.add_field("signature", "{:certificate:}.signature", "text");
        projection.add_field(
            "aggregate_verification_key",
            "{:certificate:}.aggregate_verification_key",
            "text",
        );
        projection.add_field(
            "aggregate_verification_key_snark",
            "{:certificate:}.aggregate_verification_key_snark",
            "text",
        );
        projection.add_field("epoch", "{:certificate:}.epoch", "integer");
        projection.add_field("network", "{:certificate:}.network", "text");
        projection.add_field(
            "signed_entity_type_id",
            "{:certificate:}.signed_entity_type_id",
            "integer",
        );
        projection.add_field(
            "signed_entity_beacon",
            "{:certificate:}.signed_entity_beacon",
            "text",
        );
        projection.add_field(
            "protocol_version",
            "{:certificate:}.protocol_version",
            "text",
        );
        projection.add_field(
            "protocol_parameters",
            "{:certificate:}.protocol_parameters",
            "text",
        );
        projection.add_field(
            "protocol_message",
            "{:certificate:}.protocol_message",
            "text",
        );
        projection.add_field("signers", "{:certificate:}.signers", "text");
        projection.add_field("initiated_at", "{:certificate:}.initiated_at", "text");
        projection.add_field("sealed_at", "{:certificate:}.sealed_at", "text");
        projection.add_field(
            "ancillary_prover_data",
            "{:certificate:}.ancillary_prover_data",
            "text",
        );
        projection.add_field(
            "ancillary_verifier_data",
            "{:certificate:}.ancillary_verifier_data",
            "text",
        );

        projection
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::test::crypto_helper::setup_certificate_chain;

    use super::*;

    #[test]
    fn test_convert_certificates() {
        let certificates = setup_certificate_chain(20, 3);
        let mut certificate_records: Vec<CertificateRecord> = Vec::new();
        for certificate in certificates.certificates_chained.clone() {
            certificate_records.push(certificate.try_into().unwrap());
        }
        let mut certificates_new: Vec<Certificate> = Vec::new();
        for certificate_record in certificate_records {
            certificates_new.push(certificate_record.try_into().unwrap());
        }
        assert_eq!(certificates.certificates_chained, certificates_new);
    }

    #[test]
    fn converting_certificate_record_to_certificate_should_not_recompute_hash() {
        let expected_hash = "my_hash";
        let record = CertificateRecord::dummy_genesis(expected_hash, Epoch(1));
        let certificate: Certificate = record.try_into().unwrap();

        assert_eq!(expected_hash, &certificate.hash);
    }

    #[cfg(feature = "future_snark")]
    mod snark_multi_signature {
        use super::*;

        #[test]
        fn snark_multi_signature_is_stored_as_bytes_hex() {
            let chain = setup_certificate_chain(5, 2);
            let mut certificate = chain
                .certificates_chained
                .iter()
                .find(|c| matches!(c.signature, CertificateSignature::MultiSignature(..)))
                .expect("chain should contain a multi-signature certificate")
                .clone();
            let signed_entity_type = match &certificate.signature {
                CertificateSignature::MultiSignature(signed_entity_type, _) => {
                    signed_entity_type.clone()
                }
                _ => unreachable!(),
            };
            certificate.signature = CertificateSignature::MultiSignature(
                signed_entity_type,
                fake_data::snark_aggregate_signature(),
            );
            let expected_bytes_hex = fake_data::snark_aggregate_signature().to_bytes_hex().unwrap();

            let record: CertificateRecord = certificate.try_into().unwrap();

            assert_eq!(expected_bytes_hex, record.signature);
        }
    }

    #[cfg(feature = "future_snark")]
    mod snark_aggregate_verification_key {
        use super::*;

        #[test]
        fn certificate_to_record_preserves_snark_aggregate_verification_key() {
            let chain = setup_certificate_chain(5, 2);
            let certificate = chain
                .certificates_chained
                .iter()
                .find(|c| c.aggregate_verification_key_snark.is_some())
                .expect("At least one certificate should have a SNARK AVK");

            let record: CertificateRecord = certificate.clone().try_into().unwrap();

            assert!(
                record.aggregate_verification_key_snark.is_some(),
                "CertificateRecord should preserve SNARK AVK from Certificate"
            );
        }

        #[test]
        fn record_to_certificate_preserves_snark_aggregate_verification_key() {
            let chain = setup_certificate_chain(5, 2);
            let original_certificate = chain
                .certificates_chained
                .iter()
                .find(|c| c.aggregate_verification_key_snark.is_some())
                .expect("At least one certificate should have a SNARK AVK");

            let record: CertificateRecord = original_certificate.clone().try_into().unwrap();
            let restored_certificate: Certificate = record.try_into().unwrap();

            assert_eq!(
                original_certificate.aggregate_verification_key_snark,
                restored_certificate.aggregate_verification_key_snark,
            );
        }

        #[test]
        fn certificate_to_record_roundtrip_with_none_snark_aggregate_verification_key() {
            let chain = setup_certificate_chain(5, 2);
            let mut certificate = chain
                .certificates_chained
                .first()
                .expect("Chain should have at least one certificate")
                .clone();
            certificate.aggregate_verification_key_snark = None;
            certificate.hash = certificate.try_compute_hash().unwrap();

            let record: CertificateRecord = certificate.clone().try_into().unwrap();
            assert!(record.aggregate_verification_key_snark.is_none());

            let restored: Certificate = record.try_into().unwrap();
            assert_eq!(
                certificate.aggregate_verification_key_snark,
                restored.aggregate_verification_key_snark,
            );
        }

        #[test]
        fn certificate_message_preserves_snark_aggregate_verification_key() {
            let chain = setup_certificate_chain(5, 2);
            let certificate = chain
                .certificates_chained
                .iter()
                .find(|c| c.aggregate_verification_key_snark.is_some())
                .expect("At least one certificate should have a SNARK AVK");

            let record: CertificateRecord = certificate.clone().try_into().unwrap();
            let expected_snark_avk = record.aggregate_verification_key_snark.clone();

            let message: CertificateMessage = record.into();

            assert_eq!(expected_snark_avk, message.aggregate_verification_key_snark,);
        }
    }

    #[cfg(feature = "future_snark")]
    mod dual_genesis_signature {
        use mithril_common::crypto_helper::{GenesisEd25519Signer, GenesisSchnorrSigner};
        use mithril_common::entities::CertificateSignature;

        use super::*;

        fn build_dual_genesis_certificate() -> Certificate {
            let chain = setup_certificate_chain(5, 2);
            let mut certificate = chain
                .certificates_chained
                .iter()
                .rev()
                .find(|c| matches!(c.signature, CertificateSignature::GenesisSignature(_)))
                .expect("chain should contain a genesis certificate")
                .clone();
            let ed25519_signer = GenesisEd25519Signer::create_deterministic_signer();
            let schnorr_signer = GenesisSchnorrSigner::create_non_deterministic_signer();
            let ed_signature = ed25519_signer.sign(certificate.signed_message.as_bytes());
            let schnorr_signature = schnorr_signer
                .sign_non_deterministic(&[0x42u8; 32])
                .expect("Schnorr sign should not fail");
            certificate.signature =
                CertificateSignature::GenesisDualSignature(ed_signature, schnorr_signature);
            certificate.hash = certificate.try_compute_hash().unwrap();
            certificate
        }

        #[test]
        fn certificate_to_record_to_certificate_preserves_dual_signature() {
            let certificate = build_dual_genesis_certificate();
            let (expected_ed25519, expected_schnorr) = match &certificate.signature {
                CertificateSignature::GenesisDualSignature(ed, schnorr) => (
                    ed.to_bytes_hex().unwrap(),
                    schnorr_signature_to_hex(schnorr),
                ),
                other => panic!("expected GenesisDualSignature, got {other:?}"),
            };

            let record: CertificateRecord = certificate.clone().try_into().unwrap();
            let restored: Certificate = record.try_into().unwrap();

            match &restored.signature {
                CertificateSignature::GenesisDualSignature(ed, schnorr) => {
                    assert_eq!(ed.to_bytes_hex().unwrap(), expected_ed25519);
                    assert_eq!(schnorr_signature_to_hex(schnorr), expected_schnorr);
                }
                other => {
                    panic!(
                        "expected the restored signature to be a GenesisDualSignature, got {other:?}"
                    )
                }
            }
            assert_eq!(certificate, restored);
        }

        #[test]
        fn certificate_record_serialises_dual_signature_as_json_wrapper() {
            let certificate = build_dual_genesis_certificate();

            let record: CertificateRecord = certificate.try_into().unwrap();

            assert!(
                record.signature.starts_with('{'),
                "dual genesis record signature column must hold the JSON wrapper, got: {}",
                record.signature
            );
        }

        #[test]
        fn certificate_message_carries_both_genesis_signatures_for_dual_record() {
            let certificate = build_dual_genesis_certificate();
            let (expected_ed25519, expected_schnorr) = match &certificate.signature {
                CertificateSignature::GenesisDualSignature(ed, schnorr) => (
                    ed.to_bytes_hex().unwrap(),
                    schnorr_signature_to_hex(schnorr),
                ),
                other => panic!("expected GenesisDualSignature, got {other:?}"),
            };

            let record: CertificateRecord = certificate.try_into().unwrap();
            let message: CertificateMessage = record.into();

            assert_eq!(message.genesis_signature, expected_ed25519);
            assert_eq!(message.genesis_schnorr_signature, expected_schnorr);
            assert!(message.multi_signature.is_empty());
        }

        #[test]
        fn legacy_pythagoras_record_still_round_trips_without_wrapper() {
            let chain = setup_certificate_chain(5, 2);
            let pythagoras_genesis = chain
                .certificates_chained
                .iter()
                .find(|c| matches!(c.signature, CertificateSignature::GenesisSignature(_)))
                .expect("chain should contain a genesis certificate")
                .clone();

            let record: CertificateRecord = pythagoras_genesis.clone().try_into().unwrap();
            assert!(!record.signature.starts_with('{'));
            let restored: Certificate = record.try_into().unwrap();

            assert_eq!(pythagoras_genesis, restored);
        }
    }
}
