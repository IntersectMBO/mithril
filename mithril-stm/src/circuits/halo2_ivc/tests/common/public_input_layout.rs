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
    /// Message the genesis signature was produced over.
    GenesisMessage,
    /// X coordinate of the genesis verification key.
    GenesisVerificationKeyX,
    /// Y coordinate of the genesis verification key.
    GenesisVerificationKeyY,
    /// Transcript representation of the certificate circuit verifying key.
    CertificateCircuitVerificationKeyRepresentation,
    /// Transcript representation of the recursive circuit verifying key.
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
    /// Number of recursive steps taken.
    StepCounter,
    /// Message hash the step aggregates.
    Message,
    /// Merkle-tree commitment the aggregated certificate was verified against.
    MerkleTreeCommitment,
    /// Merkle-tree commitment decoded from the message preimage.
    NextMerkleTreeCommitment,
    /// Protocol parameters in force for this step.
    ProtocolParameters,
    /// Protocol parameters decoded from the message preimage.
    NextProtocolParameters,
    /// Epoch decoded from the message preimage.
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
    use midnight_circuits::types::Instantiable;
    use proptest::prelude::*;

    use super::*;
    use crate::BaseFieldElement;
    use crate::circuits::halo2_ivc::{
        AssignedNativePoint, CircuitCurve, NativeField,
        state::{Global, State},
        tests::common::asset_readers::{
            load_embedded_genesis_benchmark_fixture, load_embedded_verification_context_asset,
        },
        types::{
            CertificateCircuitVerificationKeyRepresentation, EpochNumber,
            IvcCircuitVerificationKeyRepresentation, MerkleTreeCommitment, MessageHash,
            ProtocolParametersHash, StepCounter,
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
    fn global_public_input_order_matches_the_layout() {
        // Distinct sentinels per settable field, so a reordering of `Global::as_public_input` or a
        // name mapped to the wrong row fails here rather than producing a misleading signature.
        const SENTINELS: [(GlobalField, u64); 3] = [
            (GlobalField::GenesisMessage, 11),
            (
                GlobalField::CertificateCircuitVerificationKeyRepresentation,
                33,
            ),
            (GlobalField::IvcCircuitVerificationKeyRepresentation, 44),
        ];

        let fixture = load_embedded_genesis_benchmark_fixture()
            .expect("genesis benchmark fixture should load");
        let genesis_verification_key = fixture.genesis_verification_key;
        let global = Global {
            genesis_message: MessageHash::from_field(NativeField::from(11u64)),
            genesis_verification_key,
            certificate_circuit_verification_key_representation:
                CertificateCircuitVerificationKeyRepresentation::from_field(NativeField::from(
                    33u64,
                )),
            ivc_circuit_verification_key_representation:
                IvcCircuitVerificationKeyRepresentation::from_field(NativeField::from(44u64)),
        };
        let public_input = global.as_public_input();

        for (field, sentinel) in SENTINELS {
            assert_eq!(
                public_input[field.row()],
                NativeField::from(sentinel),
                "{} is not at global row {}",
                field.name(),
                field.row()
            );
        }

        // The remaining two rows carry the key coordinates, in that order.
        let key_coordinates = AssignedNativePoint::<CircuitCurve>::as_public_input(
            genesis_verification_key.as_jubjub_subgroup(),
        );
        assert_eq!(
            public_input[GlobalField::GenesisVerificationKeyX.row()],
            key_coordinates[0],
            "{} is not at its global row",
            GlobalField::GenesisVerificationKeyX.name()
        );
        assert_eq!(
            public_input[GlobalField::GenesisVerificationKeyY.row()],
            key_coordinates[1],
            "{} is not at its global row",
            GlobalField::GenesisVerificationKeyY.name()
        );
    }

    // The existing sentinels pin the order at 11 to 77, where the two integer fields never exceed
    // a byte. A conversion narrowing them through `u32` maps every sentinel to itself, so only a
    // full-width value distinguishes it.

    fn reduced_field_element(bytes: &[u8; 32]) -> NativeField {
        BaseFieldElement::from_raw(bytes)
            .expect("from_raw applies modulus reduction and cannot fail")
            .0
    }

    fn state_from(
        step_counter: u64,
        message: NativeField,
        merkle_tree_commitment: NativeField,
        next_merkle_tree_commitment: NativeField,
        protocol_parameters: NativeField,
        next_protocol_parameters: NativeField,
        current_epoch: u64,
    ) -> State {
        State::new(
            StepCounter::new(step_counter),
            MessageHash::from_field(message),
            MerkleTreeCommitment::from_field(merkle_tree_commitment),
            MerkleTreeCommitment::from_field(next_merkle_tree_commitment),
            ProtocolParametersHash::from_field(protocol_parameters),
            ProtocolParametersHash::from_field(next_protocol_parameters),
            EpochNumber::new(current_epoch),
        )
    }

    /// Expectations are computed here rather than read back through the field wrappers: asking a
    /// getter for the expected value would only restate that `as_public_input` calls it.
    fn assert_rows_match(
        state: &State,
        step_counter: u64,
        field_values: [NativeField; 5],
        current_epoch: u64,
    ) -> Result<(), TestCaseError> {
        let public_input = state.as_public_input();
        prop_assert_eq!(public_input.len(), STATE_SECTION_ROWS);
        prop_assert_eq!(public_input[0], NativeField::from(step_counter));
        for (offset, expected) in field_values.iter().enumerate() {
            prop_assert_eq!(public_input[offset + 1], *expected);
        }
        prop_assert_eq!(public_input[6], NativeField::from(current_epoch));
        Ok(())
    }

    proptest! {
        #[test]
        fn every_state_row_carries_its_own_field_value(
            step_counter in any::<u64>(),
            current_epoch in any::<u64>(),
            field_bytes in any::<[[u8; 32]; 5]>(),
        ) {
            let field_values = field_bytes.map(|bytes| reduced_field_element(&bytes));
            // Distinct values, so a swap between two same-typed rows shows in every case.
            for (index, value) in field_values.iter().enumerate() {
                prop_assume!(!field_values[..index].contains(value));
            }

            let state = state_from(
                step_counter,
                field_values[0],
                field_values[1],
                field_values[2],
                field_values[3],
                field_values[4],
                current_epoch,
            );
            assert_rows_match(&state, step_counter, field_values, current_epoch)?;
        }
    }

    /// The integer extremes, forced because random sampling will not reliably reach them.
    #[test]
    fn the_integer_rows_carry_their_extremes() {
        let field_values = [11u64, 22, 33, 44, 55].map(NativeField::from);

        for (step_counter, current_epoch) in
            [(0, 0), (0, u64::MAX), (u64::MAX, 0), (u64::MAX, u64::MAX)]
        {
            let state = state_from(
                step_counter,
                field_values[0],
                field_values[1],
                field_values[2],
                field_values[3],
                field_values[4],
                current_epoch,
            );
            assert_rows_match(&state, step_counter, field_values, current_epoch)
                .expect("the extreme integer rows should carry their own values");
        }
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
