//! Row indices of the recursive circuit's public statement.
//!
//! The circuit constrains its statement through one shared offset counter: the global root of trust
//! first, then the next state, then the accumulator. Tests build the same vector, so a row index
//! here indexes both it and the public-statement instance column.

use std::collections::BTreeMap;

/// Rows occupied by the global root-of-trust section.
pub(crate) const GLOBAL_SECTION_ROWS: usize = 5;

/// Rows occupied by the next-state section.
pub(crate) const STATE_SECTION_ROWS: usize = 7;

/// A field of the global root-of-trust section, in the order the circuit constrains it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GlobalField {
    GenesisMessage,
    GenesisVerificationKeyX,
    GenesisVerificationKeyY,
    CertificateCircuitVerificationKeyRepresentation,
    IvcCircuitVerificationKeyRepresentation,
}

impl GlobalField {
    /// Every global field, in layout order.
    pub(crate) const ALL: [Self; GLOBAL_SECTION_ROWS] = [
        Self::GenesisMessage,
        Self::GenesisVerificationKeyX,
        Self::GenesisVerificationKeyY,
        Self::CertificateCircuitVerificationKeyRepresentation,
        Self::IvcCircuitVerificationKeyRepresentation,
    ];

    /// Row of this field in the public statement.
    pub(crate) fn row(self) -> usize {
        self as usize
    }

    /// Name used in failure diagnostics.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::GenesisMessage => "global.genesis_message",
            Self::GenesisVerificationKeyX => "global.genesis_verification_key.x",
            Self::GenesisVerificationKeyY => "global.genesis_verification_key.y",
            Self::CertificateCircuitVerificationKeyRepresentation => {
                "global.certificate_circuit_verification_key_representation"
            }
            Self::IvcCircuitVerificationKeyRepresentation => {
                "global.ivc_circuit_verification_key_representation"
            }
        }
    }
}

/// A field of the next-state section, in the order the circuit constrains it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StateField {
    StepCounter,
    Message,
    MerkleTreeCommitment,
    NextMerkleTreeCommitment,
    ProtocolParameters,
    NextProtocolParameters,
    CurrentEpoch,
}

impl StateField {
    /// Every state field, in layout order.
    pub(crate) const ALL: [Self; STATE_SECTION_ROWS] = [
        Self::StepCounter,
        Self::Message,
        Self::MerkleTreeCommitment,
        Self::NextMerkleTreeCommitment,
        Self::ProtocolParameters,
        Self::NextProtocolParameters,
        Self::CurrentEpoch,
    ];

    /// Row of this field in the public statement, after the global section.
    pub(crate) fn row(self) -> usize {
        GLOBAL_SECTION_ROWS + self as usize
    }

    /// Name used in failure diagnostics.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::StepCounter => "state.step_counter",
            Self::Message => "state.message",
            Self::MerkleTreeCommitment => "state.merkle_tree_commitment",
            Self::NextMerkleTreeCommitment => "state.next_merkle_tree_commitment",
            Self::ProtocolParameters => "state.protocol_parameters",
            Self::NextProtocolParameters => "state.next_protocol_parameters",
            Self::CurrentEpoch => "state.current_epoch",
        }
    }
}

/// Row of the accumulator encoding element at `offset`, after the global and state sections.
pub(crate) fn accumulator_row(offset: usize) -> usize {
    GLOBAL_SECTION_ROWS + STATE_SECTION_ROWS + offset
}

/// Row-to-name map for every global field, for use as an expected failure signature.
pub(crate) fn all_global_rows() -> BTreeMap<usize, &'static str> {
    GlobalField::ALL
        .iter()
        .map(|field| (field.row(), field.name()))
        .collect()
}

/// Row-to-name map for every state field, for use as an expected failure signature.
pub(crate) fn all_state_rows() -> BTreeMap<usize, &'static str> {
    StateField::ALL
        .iter()
        .map(|field| (field.row(), field.name()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::halo2_ivc::{
        NativeField,
        state::State,
        tests::common::asset_readers::load_embedded_verification_context_asset,
        types::{
            EpochNumber, MerkleTreeCommitment, MessageHash, ProtocolParametersHash, StepCounter,
        },
    };

    #[test]
    fn layout_matches_the_circuit_statement_contract() {
        let verification_context = load_embedded_verification_context_asset()
            .expect("verification context asset should load");
        assert_eq!(
            verification_context.global_field_elements.len(),
            GLOBAL_SECTION_ROWS,
            "global section length changed; every expected public-input row shifts with it"
        );
        assert_eq!(
            State::genesis().as_public_input().len(),
            STATE_SECTION_ROWS,
            "state section length changed; every expected public-input row shifts with it"
        );
        for (offset, field) in GlobalField::ALL.iter().enumerate() {
            assert_eq!(
                field.row(),
                offset,
                "{} is not at global row {offset}",
                field.name()
            );
        }
        for (offset, field) in StateField::ALL.iter().enumerate() {
            assert_eq!(
                field.row(),
                GLOBAL_SECTION_ROWS + offset,
                "{} is not at state row {}",
                field.name(),
                GLOBAL_SECTION_ROWS + offset
            );
        }
        assert_eq!(
            accumulator_row(0),
            GLOBAL_SECTION_ROWS + STATE_SECTION_ROWS,
            "the accumulator section follows the global and state sections"
        );
    }

    #[test]
    fn state_public_input_order_matches_the_layout() {
        // Each variant is paired with its own sentinel, so a variant naming the wrong field fails
        // even if the declaration order and the pairs were changed together.
        const SENTINELS: [(StateField, u64); STATE_SECTION_ROWS] = [
            (StateField::StepCounter, 11),
            (StateField::Message, 22),
            (StateField::MerkleTreeCommitment, 33),
            (StateField::NextMerkleTreeCommitment, 44),
            (StateField::ProtocolParameters, 55),
            (StateField::NextProtocolParameters, 66),
            (StateField::CurrentEpoch, 77),
        ];

        assert_eq!(
            SENTINELS.map(|(field, _)| field),
            StateField::ALL,
            "every state field needs its own sentinel, so a new field cannot go untested"
        );

        let state = State::new(
            StepCounter::from_field(NativeField::from(11u64)),
            MessageHash::from_field(NativeField::from(22u64)),
            MerkleTreeCommitment::from_field(NativeField::from(33u64)),
            MerkleTreeCommitment::from_field(NativeField::from(44u64)),
            ProtocolParametersHash::from_field(NativeField::from(55u64)),
            ProtocolParametersHash::from_field(NativeField::from(66u64)),
            EpochNumber::from_field(NativeField::from(77u64)),
        );
        let public_input = state.as_public_input();

        for (field, sentinel) in SENTINELS {
            let offset = field.row() - GLOBAL_SECTION_ROWS;
            assert_eq!(
                public_input[offset],
                NativeField::from(sentinel),
                "{} is not at state offset {offset}",
                field.name()
            );
        }
    }
}
