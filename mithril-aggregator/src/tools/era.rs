use std::path::{Path, PathBuf};

use anyhow::anyhow;

use mithril_cardano_node_chain::entities::{TxDatumBuilder, TxDatumFieldValue};
use mithril_common::{
    StdResult,
    crypto_helper::EraMarkersSigner,
    entities::{Epoch, SupportedEra},
};
#[allow(deprecated)]
use mithril_era::adapters::LegacyEraMarkersPayloadCardanoChain;
use mithril_era::{EraMarker, adapters::EraMarkersPayloadCardanoChain};

type EraToolsResult<R> = StdResult<R>;

/// Format of the era markers stored in a transaction datum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EraMarkersDatumFormat {
    /// Era markers signed with a sequence number
    Sequenced {
        /// Sequence number of the era markers, incremented at each publication
        sequence_number: u64,
    },

    /// Deprecated era markers signed without sequence number, for the nodes that can not read
    /// the sequenced era markers yet
    Legacy,
}

pub struct EraTools {}

impl EraTools {
    pub fn new() -> Self {
        Self {}
    }

    /// Get list of supported eras
    pub fn get_supported_eras_list(&self) -> EraToolsResult<Vec<SupportedEra>> {
        Ok(SupportedEra::eras())
    }

    /// Generate TxDatum for eras with sanity check of epochs
    pub fn generate_tx_datum(
        &self,
        current_era_epoch: Epoch,
        maybe_next_era_epoch: Option<Epoch>,
        format: EraMarkersDatumFormat,
        era_markers_signer: &EraMarkersSigner,
    ) -> EraToolsResult<String> {
        if maybe_next_era_epoch.is_some()
            && maybe_next_era_epoch.unwrap_or_default() <= current_era_epoch
        {
            Err(anyhow!(
                "next era epoch must be strictly greater than the current era epoch"
            ))?;
        }

        let mut era_markers = Vec::new();
        for (index, era) in SupportedEra::eras().iter().enumerate() {
            let era_marker = match index {
                0 => EraMarker::new(&era.to_string(), Some(current_era_epoch)),
                1 => EraMarker::new(&era.to_string(), maybe_next_era_epoch),
                _ => Err(anyhow!("too many eras retrieved, can't generate tx datum"))?,
            };
            era_markers.push(era_marker);
        }
        let era_markers_payload_json_hex = match format {
            EraMarkersDatumFormat::Sequenced { sequence_number } => EraMarkersPayloadCardanoChain {
                markers: era_markers,
                sequence_number,
                signature: None,
            }
            .sign(era_markers_signer)?
            .to_json_hex()?,
            #[allow(deprecated)]
            EraMarkersDatumFormat::Legacy => LegacyEraMarkersPayloadCardanoChain {
                markers: era_markers,
                signature: None,
            }
            .sign(era_markers_signer)?
            .to_json_hex()?,
        };

        let tx_datum = TxDatumBuilder::new()
            .add_field(TxDatumFieldValue::Bytes(era_markers_payload_json_hex))
            .build()?;
        Ok(tx_datum.0)
    }

    /// Export the era keypair to a folder and returns the paths to the files (secret key, verification_key)
    pub fn create_and_save_era_keypair(keypair_path: &Path) -> StdResult<(PathBuf, PathBuf)> {
        let era_signer = EraMarkersSigner::create_non_deterministic_signer();
        let era_secret_key_path = keypair_path.join("era.sk");
        era_signer.secret_key().write_json_hex_to_file(&era_secret_key_path)?;
        let era_verification_key_path = keypair_path.join("era.vk");
        era_signer
            .verification_key()
            .write_json_hex_to_file(&era_verification_key_path)?;

        Ok((era_secret_key_path, era_verification_key_path))
    }
}

#[cfg(test)]
mod tests {
    use mithril_cardano_node_chain::entities::{TxDatum, TxDatumFieldTypeName};
    use mithril_common::{
        crypto_helper::{EraMarkersVerifierSecretKey, EraMarkersVerifierVerificationKey},
        test::TempDir,
    };
    use std::fs::read_to_string;

    use super::*;

    fn build_tools() -> EraTools {
        EraTools {}
    }

    fn get_temp_dir(dir_name: &str) -> PathBuf {
        TempDir::create("era", dir_name)
    }

    #[test]
    fn get_supported_eras_list() {
        let era_tools = build_tools();
        let supported_eras_list = era_tools
            .get_supported_eras_list()
            .expect("get_supported_eras_list should not fail");
        assert_eq!(supported_eras_list, SupportedEra::eras());
    }

    fn payload_json_hex_from_tx_datum(tx_datum: String) -> String {
        TxDatum(tx_datum)
            .get_fields_by_type(&TxDatumFieldTypeName::Bytes)
            .expect("tx datum should have bytes fields")
            .iter()
            .filter_map(|field_value| field_value.as_str())
            .collect::<Vec<&str>>()
            .join("")
    }

    #[test]
    fn generate_tx_datum_with_a_sequence_number() {
        let era_markers_signer = EraMarkersSigner::create_deterministic_signer();
        let era_tools = build_tools();

        let tx_datum = era_tools
            .generate_tx_datum(
                Epoch(1),
                None,
                EraMarkersDatumFormat::Sequenced { sequence_number: 7 },
                &era_markers_signer,
            )
            .expect("generate_tx_datum should not fail");

        let payload =
            EraMarkersPayloadCardanoChain::from_json_hex(&payload_json_hex_from_tx_datum(tx_datum))
                .expect("tx datum should hold a sequenced era markers payload");
        assert_eq!(7, payload.sequence_number);
        assert_eq!(Some(Epoch(1)), payload.markers[0].epoch);
        payload
            .verify_signature(era_markers_signer.create_verifier().to_verification_key())
            .expect("sequenced era markers payload signature should be valid");
    }

    #[test]
    #[allow(deprecated)]
    fn generate_tx_datum_in_legacy_format() {
        let era_markers_signer = EraMarkersSigner::create_deterministic_signer();
        let era_tools = build_tools();

        let tx_datum = era_tools
            .generate_tx_datum(
                Epoch(1),
                None,
                EraMarkersDatumFormat::Legacy,
                &era_markers_signer,
            )
            .expect("generate_tx_datum should not fail");

        let payload_json_hex = payload_json_hex_from_tx_datum(tx_datum);
        let payload = LegacyEraMarkersPayloadCardanoChain::from_json_hex(&payload_json_hex)
            .expect("tx datum should hold a legacy era markers payload");
        assert_eq!(Some(Epoch(1)), payload.markers[0].epoch);
        payload
            .verify_signature(era_markers_signer.create_verifier().to_verification_key())
            .expect("legacy era markers payload signature should be valid");
    }

    #[test]
    fn generate_tx_datum_wrong_epochs() {
        let era_markers_signer = EraMarkersSigner::create_deterministic_signer();
        let era_tools = build_tools();
        let _ = era_tools
            .generate_tx_datum(
                Epoch(3),
                Some(Epoch(2)),
                EraMarkersDatumFormat::Sequenced { sequence_number: 1 },
                &era_markers_signer,
            )
            .expect_err("generate_tx_datum should have failed");
    }

    #[test]
    fn test_create_and_save_era_keypair() {
        let temp_dir = get_temp_dir("test_create_and_save_era_keypair");
        let (era_secret_key_path, era_verification_key_path) =
            EraTools::create_and_save_era_keypair(&temp_dir)
                .expect("Failed to create and save era keypair");
        let era_secret_key = EraMarkersVerifierSecretKey::from_json_hex(
            &read_to_string(&era_secret_key_path).expect("Failed to read era secret key file"),
        )
        .expect("Failed to parse era secret key");
        let era_verification_key = EraMarkersVerifierVerificationKey::from_json_hex(
            &read_to_string(&era_verification_key_path)
                .expect("Failed to read era verification key file"),
        )
        .expect("Failed to parse era verification key");
        let era_verifier = EraMarkersSigner::from_secret_key(era_secret_key).create_verifier();

        let expected_era_verification_key = era_verifier.to_verification_key();
        assert_eq!(expected_era_verification_key, era_verification_key);
    }
}
