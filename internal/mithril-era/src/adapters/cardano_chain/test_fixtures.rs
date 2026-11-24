//! Fixtures shared by the tests of the era markers stored on the Cardano chain.
#![allow(deprecated)]

use mithril_common::crypto_helper::EraMarkersSigner;
use mithril_common::entities::Epoch;

use crate::EraMarker;

use super::legacy_payload::LegacyEraMarkersPayload;
use super::payload::EraMarkersPayload;

/// Era markers of the `thales` era only
pub(super) fn thales_markers() -> Vec<EraMarker> {
    vec![EraMarker::new("thales", Some(Epoch(1)))]
}

/// Era markers of the `thales` era followed by the `pythagoras` era at the given epoch
pub(super) fn pythagoras_markers(pythagoras_epoch: Option<u64>) -> Vec<EraMarker> {
    vec![
        EraMarker::new("thales", Some(Epoch(1))),
        EraMarker::new("pythagoras", pythagoras_epoch.map(Epoch)),
    ]
}

/// Era markers payload signed with the given sequence number
pub(super) fn sequenced_payload(
    markers: &[EraMarker],
    sequence_number: u64,
    era_markers_signer: &EraMarkersSigner,
) -> EraMarkersPayload {
    EraMarkersPayload {
        markers: markers.to_vec(),
        sequence_number,
        signature: None,
    }
    .sign(era_markers_signer)
    .unwrap()
}

/// Legacy era markers payload, signed without sequence number
pub(super) fn legacy_payload(
    markers: &[EraMarker],
    era_markers_signer: &EraMarkersSigner,
) -> LegacyEraMarkersPayload {
    LegacyEraMarkersPayload {
        markers: markers.to_vec(),
        signature: None,
    }
    .sign(era_markers_signer)
    .unwrap()
}
