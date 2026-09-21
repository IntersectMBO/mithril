//! Assignment helpers that turn IVC circuit witness values into assigned layouter values.
//!
//! These free functions prepare assigned inputs for the circuit; `IvcConstraintBuilder` owns the constraint logic.

use std::collections::HashSet;

use super::{
    AssignedNative, AssignedNativePoint, AssignedScalarOfNativeCurve, AssignedVk,
    AssignmentInstructions, CERTIFICATE_FIXED_BASES_PREFIX, CircuitValue, ConstraintSystem, Error,
    EvaluationDomain, IVC_FIXED_BASES_PREFIX, Layouter, NativeField, PublicInputInstructions,
    RecursiveEmulation,
    accumulator::fixed_base_names_from_constraint_system,
    constraint_builder::IvcConstraintBuilder,
    errors::{IvcCircuitError, to_synthesis_error},
    state::{AssignedGlobal, AssignedState, AssignedWitness, Global, State, Witness},
};

/// Assigns the global root-of-trust as public input and returns its in-circuit form.
pub(crate) fn assign_global_as_public_input(
    builder: &IvcConstraintBuilder,
    layouter: &mut impl Layouter<NativeField>,
    global: &CircuitValue<Global>,
    certificate_circuit_domain: &EvaluationDomain<NativeField>,
    certificate_circuit_constraint_system: &ConstraintSystem<NativeField>,
    ivc_circuit_domain: &EvaluationDomain<NativeField>,
    ivc_circuit_constraint_system: &ConstraintSystem<NativeField>,
) -> Result<AssignedGlobal, Error> {
    let genesis_message: AssignedNative<_> = builder.native_gadget.assign_as_public_input(
        layouter,
        global.clone().map(|gl| gl.genesis_message.as_field()),
    )?;
    let genesis_verification_key: AssignedNativePoint<_> =
        builder.jubjub_chip.assign_as_public_input(
            layouter,
            global
                .clone()
                .map(|gl| *gl.genesis_verification_key.as_jubjub_subgroup()),
        )?;

    let certificate_verification_key: AssignedVk<RecursiveEmulation> =
        builder.verifier_gadget.assign_vk_as_public_input(
            layouter,
            CERTIFICATE_FIXED_BASES_PREFIX,
            certificate_circuit_domain,
            certificate_circuit_constraint_system,
            global
                .clone()
                .map(|gl| gl.certificate_circuit_verification_key_representation.as_field()),
        )?;

    // Assign for IVC proof verification
    let ivc_verification_key: AssignedVk<RecursiveEmulation> =
        builder.verifier_gadget.assign_vk_as_public_input(
            layouter,
            IVC_FIXED_BASES_PREFIX,
            ivc_circuit_domain,
            ivc_circuit_constraint_system,
            global
                .clone()
                .map(|gl| gl.ivc_circuit_verification_key_representation.as_field()),
        )?;

    let fixed_base_names = {
        let mut names = fixed_base_names_from_constraint_system(
            CERTIFICATE_FIXED_BASES_PREFIX,
            certificate_circuit_constraint_system,
        );
        names.extend(fixed_base_names_from_constraint_system(
            IVC_FIXED_BASES_PREFIX,
            ivc_circuit_constraint_system,
        ));
        // Remove repeated names for committed_instance and the generator
        let mut seen = HashSet::new();
        names.retain(|x| seen.insert(x.clone()));
        names
    };

    Ok(AssignedGlobal {
        genesis_message,
        genesis_verification_key,
        certificate_verification_key,
        ivc_verification_key,
        fixed_base_names,
    })
}

/// Assigns the circuit state values into the layouter.
pub(crate) fn assign_state(
    builder: &IvcConstraintBuilder,
    layouter: &mut impl Layouter<NativeField>,
    state: &CircuitValue<State>,
) -> Result<AssignedState, Error> {
    let values = state
        .clone()
        .map(|s| {
            vec![
                s.step_counter.as_field(),
                s.message.as_field(),
                s.merkle_tree_commitment.as_field(),
                s.next_merkle_tree_commitment.as_field(),
                s.protocol_parameters.as_field(),
                s.next_protocol_parameters.as_field(),
                s.current_epoch.as_field(),
            ]
        })
        .transpose_vec(7);

    let [
        step_counter,
        message,
        merkle_tree_commitment,
        next_merkle_tree_commitment,
        protocol_parameters,
        next_protocol_parameters,
        current_epoch,
    ]: [AssignedNative<_>; 7] = {
        builder
            .native_gadget
            .assign_many(layouter, &values)?
            .try_into()
            .map_err(|v: Vec<_>| {
                to_synthesis_error(IvcCircuitError::AssignedValueCountMismatch {
                    expected: 7,
                    actual: v.len(),
                })
            })?
    };

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

/// Constrains the assigned next state as public input.
pub(crate) fn constrain_state_as_public_input(
    builder: &IvcConstraintBuilder,
    layouter: &mut impl Layouter<NativeField>,
    state: &AssignedState,
) -> Result<(), Error> {
    for value in [
        &state.step_counter,
        &state.message,
        &state.merkle_tree_commitment,
        &state.next_merkle_tree_commitment,
        &state.protocol_parameters,
        &state.next_protocol_parameters,
        &state.current_epoch,
    ] {
        builder.native_gadget.constrain_as_public_input(layouter, value)?;
    }

    Ok(())
}

/// Assigns the step witness (genesis signature, certificate fields, and message preimage) into the
/// layouter.
pub(crate) fn assign_witness(
    builder: &IvcConstraintBuilder,
    layouter: &mut impl Layouter<NativeField>,
    witness: &CircuitValue<Witness>,
) -> Result<AssignedWitness, Error> {
    let genesis_signature = {
        let s: AssignedScalarOfNativeCurve<_> = builder.jubjub_chip.assign(
            layouter,
            witness.clone().map(|w| w.genesis_signature.response.0),
        )?;
        let c: AssignedNative<_> = builder.native_gadget.assign(
            layouter,
            witness.clone().map(|w| w.genesis_signature.challenge.0),
        )?;
        (s, c)
    };

    let [certificate_message, certificate_merkle_tree_commitment]: [AssignedNative<NativeField>;
        2] = {
        let values = witness
            .clone()
            .map(|w| {
                vec![
                    w.certificate_message.as_field(),
                    w.certificate_merkle_tree_commitment.as_field(),
                ]
            })
            .transpose_vec(2);
        builder
            .native_gadget
            .assign_many(layouter, &values)?
            .try_into()
            .map_err(|v: Vec<_>| {
                to_synthesis_error(IvcCircuitError::AssignedValueCountMismatch {
                    expected: 2,
                    actual: v.len(),
                })
            })?
    };

    let message_preimage = {
        let preimage = witness
            .clone()
            .map(|w| w.message_preimage.into_inner())
            .transpose_array();
        builder.native_gadget.assign_many(layouter, &preimage)?
    };

    Ok(AssignedWitness {
        genesis_signature,
        certificate_message,
        certificate_merkle_tree_commitment,
        message_preimage,
    })
}
