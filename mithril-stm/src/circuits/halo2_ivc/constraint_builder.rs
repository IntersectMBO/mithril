//! In-circuit constraint builder for one recursive IVC step.
//!
//! `IvcConstraintBuilder` borrows the chips the recursive circuit needs from the standard library
//! and exposes the constraint logic driven by `IvcCircuit::circuit`: genesis-signature gating, the
//! state transition, and accumulator/proof verification. Reusable sub-gadgets live in the `gadgets`
//! module.

use ff::Field;
use group::Group;

use super::{
    Accumulator, ArithInstructions, AssertionInstructions, AssignedAccumulator, AssignedBit,
    AssignedForeignPoint, AssignedNative, AssignmentInstructions, BinaryInstructions, CircuitCurve,
    CircuitValue, ControlFlowInstructions, EccChip, EccInstructions, EmulatedCurve,
    EqualityInstructions, Error, ForeignWeierstrassEccChip, IvcNativeGadget, Layouter, NativeField,
    PREIMAGE_CURRENT_EPOCH_BYTES, PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES,
    PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES, PublicInputInstructions, RecursiveEmulation,
    VerifierGadget, ZeroInstructions, ZkStdLib,
    gadgets::{GenesisSchnorrSignatureInputs, combine_bytes, verify_genesis_signature},
    state::{AssignedGlobal, AssignedState, AssignedWitness},
};

/// Protocol-message fields decoded during a transition:
/// `(next_merkle_tree_commitment, next_protocol_parameters, current_epoch)`.
type DecodedProtocolMessageFields = (
    AssignedNative<NativeField>,
    AssignedNative<NativeField>,
    AssignedNative<NativeField>,
);

/// Borrows the standard library's chips and builds the recursive IVC circuit's constraints.
///
/// Constructed once per synthesis from the [`ZkStdLib`] the relation is handed; its methods emit
/// the constraints for a single IVC step.
#[derive(Clone)]
pub struct IvcConstraintBuilder<'a> {
    pub(crate) std_lib: &'a ZkStdLib,
    pub(crate) native_gadget: &'a IvcNativeGadget,
    pub(crate) jubjub_chip: &'a EccChip<CircuitCurve>,
    pub(crate) bls12_381_chip: &'a ForeignWeierstrassEccChip<
        NativeField,
        EmulatedCurve,
        EmulatedCurve,
        IvcNativeGadget,
        IvcNativeGadget,
    >,
    pub(crate) verifier_gadget: &'a VerifierGadget<RecursiveEmulation>,
}

impl<'a> IvcConstraintBuilder<'a> {
    /// Borrows the chips the recursive circuit needs from the standard library.
    ///
    /// The native gadget is reached through the BLS chip rather than built here: it is the standard
    /// library's own instance, and a separately constructed one would not share its public input
    /// counter.
    pub fn new(std_lib: &'a ZkStdLib) -> Self {
        IvcConstraintBuilder {
            std_lib,
            native_gadget: std_lib.bls12_381().scalar_field_chip(),
            jubjub_chip: std_lib.jubjub(),
            bls12_381_chip: std_lib.bls12_381(),
            verifier_gadget: std_lib.verifier(),
        }
    }

    /// Returns a bit that is true when the state is the genesis state (step counter zero).
    pub fn is_genesis(
        &self,
        layouter: &mut impl Layouter<NativeField>,
        state: &AssignedState,
    ) -> Result<AssignedBit<NativeField>, Error> {
        self.native_gadget.is_zero(layouter, &state.step_counter)
    }

    /// Verifies the genesis Schnorr signature in-circuit (delegates to the `schnorr_signature` gadget).
    pub fn is_genesis_signature_valid(
        &self,
        layouter: &mut impl Layouter<NativeField>,
        global: &AssignedGlobal,
        witness: &AssignedWitness,
    ) -> Result<AssignedBit<NativeField>, Error> {
        verify_genesis_signature(
            self.std_lib,
            layouter,
            GenesisSchnorrSignatureInputs {
                verification_key: &global.genesis_verification_key,
                message: &global.genesis_message,
                response: &witness.genesis_signature.0,
                challenge: &witness.genesis_signature.1,
            },
        )
    }

    /// Enforces a valid genesis Schnorr signature, skipping the check on non-genesis steps.
    pub fn assert_genesis(
        &self,
        layouter: &mut impl Layouter<NativeField>,
        is_not_genesis: &AssignedBit<NativeField>,
        global: &AssignedGlobal,
        witness: &AssignedWitness,
    ) -> Result<(), Error> {
        // Verify the genesis signature
        let is_genesis_signature_valid =
            self.is_genesis_signature_valid(layouter, global, witness)?;

        // Skip the genesis signature verification if it is not genesis
        let check_genesis = self.native_gadget.or(
            layouter,
            &[is_genesis_signature_valid, is_not_genesis.clone()],
        )?;
        self.native_gadget
            .assert_equal_to_fixed(layouter, &check_genesis, true)
    }

    /// Flattens the assigned global root-of-trust into its public-input field elements.
    pub fn global_as_public_input(
        &self,
        layouter: &mut impl Layouter<NativeField>,
        global: &AssignedGlobal,
    ) -> Result<Vec<AssignedNative<NativeField>>, Error> {
        let pi = [
            vec![
                global.genesis_message.clone(),
                self.jubjub_chip.x_coordinate(&global.genesis_verification_key),
                self.jubjub_chip.y_coordinate(&global.genesis_verification_key),
            ],
            self.verifier_gadget
                .as_public_input(layouter, &global.certificate_verification_key)?,
            self.verifier_gadget
                .as_public_input(layouter, &global.ivc_verification_key)?,
        ]
        .concat();
        Ok(pi)
    }

    /// Verifies the certificate-chain link between the last aggregated certificate and the new one,
    /// and returns the next state.
    pub fn transition(
        &self,
        layouter: &mut impl Layouter<NativeField>,
        is_genesis: &AssignedBit<NativeField>,
        is_not_genesis: &AssignedBit<NativeField>,
        global: &AssignedGlobal,
        state: &AssignedState,
        witness: &AssignedWitness,
    ) -> Result<AssignedState, Error> {
        let step_counter =
            self.native_gadget
                .add_constant(layouter, &state.step_counter, NativeField::ONE)?;

        let (certificate_message, certificate_merkle_tree_commitment) = (
            witness.certificate_message.clone(),
            witness.certificate_merkle_tree_commitment.clone(),
        );

        // Open message hash to check the link between certificates
        // If it is genesis, select genesis message as message; otherwise, select cert message as message.
        let message = self.native_gadget.select(
            layouter,
            is_genesis,
            &global.genesis_message,
            &certificate_message,
        )?;

        let factor = NativeField::from(256u64);
        let bases: Vec<_> = (0..32)
            .scan(NativeField::ONE, |s, _| {
                let out = *s;
                *s *= factor;
                Some(out)
            })
            .collect();

        self.assert_message_matches_preimage(layouter, &message, witness, &bases)?;

        // If it is genesis, merkle_tree_commitment = 0; otherwise, merkle_tree_commitment = certificate_merkle_tree_commitment.
        let zero = self.native_gadget.assign_fixed(layouter, NativeField::ZERO)?;
        let merkle_tree_commitment = self.native_gadget.select(
            layouter,
            is_genesis,
            &zero,
            &certificate_merkle_tree_commitment,
        )?;

        let (next_merkle_tree_commitment, next_protocol_parameters, current_epoch) =
            self.read_transition_fields_from_preimage(layouter, witness, &bases)?;

        let (is_same_epoch, is_next_epoch) =
            self.classify_epoch(layouter, &current_epoch, state)?;

        self.assert_first_step_is_next_epoch(layouter, state, &is_next_epoch)?;

        self.assert_merkle_tree_commitment_link(
            layouter,
            is_genesis,
            &merkle_tree_commitment,
            state,
            &is_same_epoch,
            &is_next_epoch,
        )?;

        let protocol_parameters = self.select_protocol_parameters(
            layouter,
            is_genesis,
            is_not_genesis,
            &is_same_epoch,
            state,
            &zero,
        )?;

        self.assert_next_values_consistency(
            layouter,
            is_genesis,
            &is_same_epoch,
            &is_next_epoch,
            &next_merkle_tree_commitment,
            &next_protocol_parameters,
            state,
        )?;

        // Return the next state
        Ok(AssignedState {
            step_counter,
            message,
            merkle_tree_commitment,
            next_merkle_tree_commitment,
            protocol_parameters,
            next_protocol_parameters,
            current_epoch,
        })
    }

    /// Asserts the selected `message` equals the SHA-256 hash of the protocol-message preimage.
    fn assert_message_matches_preimage(
        &self,
        layouter: &mut impl Layouter<NativeField>,
        message: &AssignedNative<NativeField>,
        witness: &AssignedWitness,
        bases: &[NativeField],
    ) -> Result<(), Error> {
        let hash = self.std_lib.sha2_256(layouter, &witness.message_preimage)?;
        // Compare message and hash
        let hash_native = combine_bytes(self.native_gadget, layouter, &hash, bases)?;
        self.native_gadget.assert_equal(layouter, message, &hash_native)
    }

    /// Reads the next Merkle-tree commitment, next protocol parameters, and current epoch from the
    /// protocol message preimage.
    fn read_transition_fields_from_preimage(
        &self,
        layouter: &mut impl Layouter<NativeField>,
        witness: &AssignedWitness,
        bases: &[NativeField],
    ) -> Result<DecodedProtocolMessageFields, Error> {
        // The byte ranges index the rigid protocol-message preimage assembled by
        // `mithril-common::ProtocolMessage::rigid_preimage` (label-prefixed value segments).
        // The next Merkle-tree commitment is the first 32 bytes of the aggregate-verification-key value.
        let next_merkle_tree_commitment_bytes =
            witness.message_preimage[PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES].to_vec();
        let next_protocol_parameters_bytes =
            witness.message_preimage[PREIMAGE_NEXT_PROTOCOL_PARAMETERS_BYTES].to_vec();
        let current_epoch_bytes = witness.message_preimage[PREIMAGE_CURRENT_EPOCH_BYTES].to_vec();

        // Get the field elements by linearly combining the bytes
        let next_merkle_tree_commitment = combine_bytes(
            self.native_gadget,
            layouter,
            next_merkle_tree_commitment_bytes,
            bases,
        )?;
        let next_protocol_parameters = combine_bytes(
            self.native_gadget,
            layouter,
            next_protocol_parameters_bytes,
            bases,
        )?;
        let current_epoch =
            combine_bytes(self.native_gadget, layouter, current_epoch_bytes, bases)?;
        Ok((
            next_merkle_tree_commitment,
            next_protocol_parameters,
            current_epoch,
        ))
    }

    /// Classifies the incoming epoch relative to the current state: `(is_same_epoch, is_next_epoch)`.
    fn classify_epoch(
        &self,
        layouter: &mut impl Layouter<NativeField>,
        current_epoch: &AssignedNative<NativeField>,
        state: &AssignedState,
    ) -> Result<(AssignedBit<NativeField>, AssignedBit<NativeField>), Error> {
        // current_epoch == state.current_epoch
        let is_same_epoch =
            self.native_gadget
                .is_equal(layouter, current_epoch, &state.current_epoch)?;

        //  current_epoch == state.current_epoch + 1
        let next =
            self.native_gadget
                .add_constant(layouter, &state.current_epoch, NativeField::ONE)?;
        let is_next_epoch = self.native_gadget.is_equal(layouter, current_epoch, &next)?;

        Ok((is_same_epoch, is_next_epoch))
    }

    /// If `state.step_counter == 1` (first certificate after genesis), its epoch must be the next epoch.
    fn assert_first_step_is_next_epoch(
        &self,
        layouter: &mut impl Layouter<NativeField>,
        state: &AssignedState,
        is_next_epoch: &AssignedBit<NativeField>,
    ) -> Result<(), Error> {
        // Assert true: is_not_first or is_next_epoch
        let is_first = self.native_gadget.is_equal_to_fixed(
            layouter,
            &state.step_counter,
            NativeField::ONE,
        )?;
        let is_not_first = self.native_gadget.not(layouter, &is_first)?;

        let is_valid = self
            .native_gadget
            .or(layouter, &[is_not_first, is_next_epoch.clone()])?;
        self.native_gadget.assert_equal_to_fixed(layouter, &is_valid, true)
    }

    /// Checks the current Merkle-tree commitment link; if it is genesis, the check is skipped.
    fn assert_merkle_tree_commitment_link(
        &self,
        layouter: &mut impl Layouter<NativeField>,
        is_genesis: &AssignedBit<NativeField>,
        merkle_tree_commitment: &AssignedNative<NativeField>,
        state: &AssignedState,
        is_same_epoch: &AssignedBit<NativeField>,
        is_next_epoch: &AssignedBit<NativeField>,
    ) -> Result<(), Error> {
        // Assert true: is_genesis or (is_same_epoch && merkle_tree_commitment == state.merkle_tree_commitment) or (is_next_epoch && merkle_tree_commitment == state.next_merkle_tree_commitment)
        let mut is_equal_current = self.native_gadget.is_equal(
            layouter,
            merkle_tree_commitment,
            &state.merkle_tree_commitment,
        )?;
        is_equal_current = self
            .native_gadget
            .and(layouter, &[is_equal_current, is_same_epoch.clone()])?;

        let mut is_equal_next = self.native_gadget.is_equal(
            layouter,
            merkle_tree_commitment,
            &state.next_merkle_tree_commitment,
        )?;
        is_equal_next = self
            .native_gadget
            .and(layouter, &[is_equal_next, is_next_epoch.clone()])?;

        let is_link_valid = self.native_gadget.or(
            layouter,
            &[is_genesis.clone(), is_equal_current, is_equal_next],
        )?;
        self.native_gadget
            .assert_equal_to_fixed(layouter, &is_link_valid, true)
    }

    /// Selects the next protocol parameters: genesis → 0, same-epoch → current, next-epoch → next.
    fn select_protocol_parameters(
        &self,
        layouter: &mut impl Layouter<NativeField>,
        is_genesis: &AssignedBit<NativeField>,
        is_not_genesis: &AssignedBit<NativeField>,
        is_same_epoch: &AssignedBit<NativeField>,
        state: &AssignedState,
        zero: &AssignedNative<NativeField>,
    ) -> Result<AssignedNative<NativeField>, Error> {
        let mut protocol_parameters = self.native_gadget.select(
            layouter,
            is_genesis,
            zero,
            &state.next_protocol_parameters,
        )?;
        let is_same_epoch_not_genesis = self
            .native_gadget
            .and(layouter, &[is_same_epoch.clone(), is_not_genesis.clone()])?;
        protocol_parameters = self.native_gadget.select(
            layouter,
            &is_same_epoch_not_genesis,
            &state.protocol_parameters,
            &protocol_parameters,
        )?;
        Ok(protocol_parameters)
    }

    /// Checks that the same-epoch next Merkle-tree commitment and next protocol parameters are consistent.
    #[allow(clippy::too_many_arguments)]
    fn assert_next_values_consistency(
        &self,
        layouter: &mut impl Layouter<NativeField>,
        is_genesis: &AssignedBit<NativeField>,
        is_same_epoch: &AssignedBit<NativeField>,
        is_next_epoch: &AssignedBit<NativeField>,
        next_merkle_tree_commitment: &AssignedNative<NativeField>,
        next_protocol_parameters: &AssignedNative<NativeField>,
        state: &AssignedState,
    ) -> Result<(), Error> {
        // Assert true: is_genesis or (is_same_epoch && next_merkle_tree_commitment == state.next_merkle_tree_commitment && next_protocol_parameters == state.next_protocol_parameters) or is_next_epoch
        let is_equal_mt = self.native_gadget.is_equal(
            layouter,
            next_merkle_tree_commitment,
            &state.next_merkle_tree_commitment,
        )?;
        let is_equal_pp = self.native_gadget.is_equal(
            layouter,
            next_protocol_parameters,
            &state.next_protocol_parameters,
        )?;
        let mut is_valid = self
            .native_gadget
            .and(layouter, &[is_same_epoch.clone(), is_equal_mt, is_equal_pp])?;
        is_valid = self.native_gadget.or(
            layouter,
            &[is_genesis.clone(), is_valid, is_next_epoch.clone()],
        )?;
        self.native_gadget.assert_equal_to_fixed(layouter, &is_valid, true)
    }

    /// Verifies the certificate proof and the previous IVC proof in-circuit and folds them into the
    /// next accumulator.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_prepare(
        &self,
        layouter: &mut impl Layouter<NativeField>,
        global: &AssignedGlobal,
        is_not_genesis: &AssignedBit<NativeField>,
        state: &AssignedState,
        witness: &AssignedWitness,
        certificate_proof: &CircuitValue<Vec<u8>>,
        ivc_proof: &CircuitValue<Vec<u8>>,
        acc_value: &CircuitValue<Accumulator<RecursiveEmulation>>,
    ) -> Result<AssignedAccumulator<RecursiveEmulation>, Error> {
        let id_point: AssignedForeignPoint<_, _, _> = self
            .bls12_381_chip
            .assign_fixed(layouter, EmulatedCurve::identity())?;

        let mut certificate_proof_accumulator = self.verifier_gadget.prepare(
            layouter,
            &global.certificate_verification_key,
            std::slice::from_ref(&id_point),
            &[&[
                witness.certificate_merkle_tree_commitment.clone(),
                witness.certificate_message.clone(),
            ]],
            certificate_proof.clone(),
        )?;

        // If it is genesis, we allow the prover to change the (probably
        // invalid) accumulator by a default accumulator that satisfies the invariant.
        AssignedAccumulator::scale_by_bit(
            layouter,
            self.native_gadget,
            is_not_genesis,
            &mut certificate_proof_accumulator,
        )?;
        certificate_proof_accumulator.collapse(
            layouter,
            self.bls12_381_chip,
            self.native_gadget,
        )?;

        let acc = AssignedAccumulator::assign(
            layouter,
            self.bls12_381_chip,
            self.native_gadget,
            1,
            1,
            &[],
            &global.fixed_base_names,
            acc_value.clone(),
        )?;

        // Public inputs for this IVC circuit:
        // [global, state, acc]
        let assigned_pi = [
            self.global_as_public_input(layouter, global)?,
            state.as_public_input(),
            self.verifier_gadget.as_public_input(layouter, &acc)?,
        ]
        .concat();

        // Verify a witnessed proof that ensures the validity of the previous state.
        // The proof is valid iff `ivc_proof_accumulator` satisfies the invariant.
        let mut ivc_proof_accumulator = self.verifier_gadget.prepare(
            layouter,
            &global.ivc_verification_key,
            std::slice::from_ref(&id_point),
            &[&assigned_pi],
            ivc_proof.clone(),
        )?;

        // If the previous state is genesis, we allow the prover to change the (probably
        // invalid) accumulator by a default accumulator that satisfies the invariant.
        AssignedAccumulator::scale_by_bit(
            layouter,
            self.native_gadget,
            is_not_genesis,
            &mut ivc_proof_accumulator,
        )?;
        ivc_proof_accumulator.collapse(layouter, self.bls12_381_chip, self.native_gadget)?;

        // Accumulate the certificate and IVC proof accumulators.
        let mut next_acc = self.verifier_gadget.accumulate(
            layouter,
            &[acc, certificate_proof_accumulator, ivc_proof_accumulator],
        )?;
        next_acc.collapse(layouter, self.bls12_381_chip, self.native_gadget)?;

        Ok(next_acc)
    }
}
