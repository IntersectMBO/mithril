use crate::StmResult;
use crate::circuits::halo2::keys::NonRecursiveCircuitVerifyingKey;
use crate::circuits::halo2_ivc::keys::RecursiveCircuitVerifyingKey;
use anyhow::anyhow;

use super::{
    Accumulator, BinaryInstructions, Circuit, CircuitValue, ComposableChip, ConstraintSystem,
    EmulatedCurve, Error, EvaluationDomain, IvcNativeGadget, Layouter, NB_ARITH_COLS,
    NB_ARITH_FIXED_COLS, NB_EDWARDS_COLS, NB_POSEIDON_ADVICE_COLS, NB_POSEIDON_FIXED_COLS,
    NB_SHA256_ADVICE_COLS, NB_SHA256_FIXED_COLS, NativeField, PublicInputInstructions,
    RECURSIVE_CIRCUIT_DEGREE, RecursiveEmulation, SimpleFloorPlanner,
    config::{IvcConfig, configure_ivc_circuit, ivc_column_pool_sizes},
    constraint_builder::IvcConstraintBuilder,
    errors::IvcCircuitError,
    nb_foreign_ecc_chip_columns,
    state::{Global, State, Witness},
    types::{CertificateProofBytes, IvcProofBytes},
    witness_assignments,
};

/// Data required to run one step of the IVC (Incrementally Verifiable Computation) circuit.
///
/// Holds the global root-of-trust, the current state, the next certificate witness,
/// the associated SNARK proofs, the latest accumulator, and the verification-key metadata
/// for both the certificate circuit and the IVC circuit itself.
#[derive(Clone, Debug)]
pub struct IvcCircuitData {
    // Persistent values throughout an ivc stream. This is the root of trust for an ivc stream.
    global: CircuitValue<Global>,
    // State values from the last aggregated certificate
    state: CircuitValue<State>,
    // Witness (mainly the next certificate to be aggregated) for deriving the next state
    witness: CircuitValue<Witness>,
    // Snark proof of the next certificate
    certificate_proof: CircuitValue<Vec<u8>>,
    // Latest IVC proof
    ivc_proof: CircuitValue<Vec<u8>>,
    // Latest Accumulator
    acc: CircuitValue<Accumulator<RecursiveEmulation>>,
    // Domain and ConstraintSystem associated with certificate circuit VerifyingKey
    certificate_circuit_domain_and_constraint_system:
        (EvaluationDomain<NativeField>, ConstraintSystem<NativeField>),
    // Domain and ConstraintSystem associated with IVC circuit VerifyingKey
    ivc_circuit_domain_and_constraint_system:
        (EvaluationDomain<NativeField>, ConstraintSystem<NativeField>),
}

impl IvcCircuitData {
    /// Validates that the IVC verification key degree matches the IVC circuit degree constant RECURSIVE_CIRCUIT_DEGREE.
    pub(crate) fn validate_ivc_verification_key_degree(
        ivc_verification_key: &RecursiveCircuitVerifyingKey,
    ) -> StmResult<()> {
        let actual = ivc_verification_key.as_ref().get_domain().k();
        if actual != RECURSIVE_CIRCUIT_DEGREE {
            return Err(anyhow!(IvcCircuitError::IvcVerificationKeyDegreeMismatch {
                expected: RECURSIVE_CIRCUIT_DEGREE,
                actual,
            }));
        }
        Ok(())
    }

    /// Validates that the column pool allocated by `configure_ivc_circuit` is large enough
    /// for every chip. Must be called before `Circuit::configure` is reached (e.g. in
    /// `try_new` and `unknown`) so that the `.expect` calls inside `configure_ivc_circuit`
    /// are guaranteed not to trigger.
    fn validate_column_counts() -> StmResult<()> {
        let (nb_advice_cols, nb_fixed_cols) = ivc_column_pool_sizes();

        for needed in [
            NB_ARITH_COLS,
            NB_EDWARDS_COLS,
            NB_POSEIDON_ADVICE_COLS,
            NB_SHA256_ADVICE_COLS,
            nb_foreign_ecc_chip_columns::<NativeField, EmulatedCurve, EmulatedCurve, IvcNativeGadget>(
            ),
        ] {
            if needed > nb_advice_cols {
                return Err(anyhow!(IvcCircuitError::InsufficientAdviceColumns {
                    needed,
                    available: nb_advice_cols,
                }));
            }
        }

        for needed in [NB_ARITH_FIXED_COLS, NB_POSEIDON_FIXED_COLS, NB_SHA256_FIXED_COLS] {
            if needed > nb_fixed_cols {
                return Err(anyhow!(IvcCircuitError::InsufficientFixedColumns {
                    needed,
                    available: nb_fixed_cols,
                }));
            }
        }

        Ok(())
    }

    /// Creates a new `IvcCircuitData` with the given witness and proof data.
    ///
    /// Validates that `ivc_verification_key` has degree `RECURSIVE_CIRCUIT_DEGREE` and that the column pool allocated by
    /// `configure_ivc_circuit` is sufficient for all chips. Returns an error containing
    /// [`IvcCircuitError::IvcVerificationKeyDegreeMismatch`] or
    /// [`IvcCircuitError::InsufficientAdviceColumns`] /
    /// [`IvcCircuitError::InsufficientFixedColumns`] if either check fails.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new(
        global: Global,
        state: State,
        witness: Witness,
        certificate_proof: CertificateProofBytes,
        ivc_proof: IvcProofBytes,
        acc: Accumulator<RecursiveEmulation>,
        certificate_verification_key: &NonRecursiveCircuitVerifyingKey,
        ivc_verification_key: &RecursiveCircuitVerifyingKey,
    ) -> StmResult<Self> {
        Self::validate_ivc_verification_key_degree(ivc_verification_key)?;
        Self::validate_column_counts()?;
        Ok(IvcCircuitData {
            global: CircuitValue::known(global),
            state: CircuitValue::known(state),
            witness: CircuitValue::known(witness),
            certificate_proof: CircuitValue::known(certificate_proof.into_vec()),
            ivc_proof: CircuitValue::known(ivc_proof.into_vec()),
            acc: CircuitValue::known(acc),
            certificate_circuit_domain_and_constraint_system: (
                certificate_verification_key.as_ref().get_domain().clone(),
                certificate_verification_key.as_ref().cs().clone(),
            ),
            ivc_circuit_domain_and_constraint_system: (
                ivc_verification_key.as_ref().get_domain().clone(),
                ivc_verification_key.as_ref().cs().clone(),
            ),
        })
    }

    /// Creates a default IVC circuit for generating the proving and verifying keys.
    pub fn unknown(
        certificate_verification_key: &NonRecursiveCircuitVerifyingKey,
    ) -> StmResult<Self> {
        Self::validate_column_counts()?;
        let mut ivc_circuit_constraint_system = ConstraintSystem::default();
        configure_ivc_circuit(&mut ivc_circuit_constraint_system);
        let ivc_circuit_domain = EvaluationDomain::new(
            ivc_circuit_constraint_system.degree() as u32,
            RECURSIVE_CIRCUIT_DEGREE,
        );

        Ok(IvcCircuitData {
            global: CircuitValue::unknown(),
            state: CircuitValue::unknown(),
            witness: CircuitValue::unknown(),
            certificate_proof: CircuitValue::unknown(),
            ivc_proof: CircuitValue::unknown(),
            acc: CircuitValue::unknown(),
            certificate_circuit_domain_and_constraint_system: (
                certificate_verification_key.as_ref().get_domain().clone(),
                certificate_verification_key.as_ref().cs().clone(),
            ),
            ivc_circuit_domain_and_constraint_system: (
                ivc_circuit_domain,
                ivc_circuit_constraint_system,
            ),
        })
    }
}

impl Circuit<NativeField> for IvcCircuitData {
    type Config = IvcConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        IvcCircuitData {
            global: CircuitValue::unknown(),
            state: CircuitValue::unknown(),
            witness: CircuitValue::unknown(),
            certificate_proof: CircuitValue::unknown(),
            ivc_proof: CircuitValue::unknown(),
            acc: CircuitValue::unknown(),
            certificate_circuit_domain_and_constraint_system: self
                .certificate_circuit_domain_and_constraint_system
                .clone(),
            ivc_circuit_domain_and_constraint_system: self
                .ivc_circuit_domain_and_constraint_system
                .clone(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<NativeField>) -> Self::Config {
        configure_ivc_circuit(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<NativeField>,
    ) -> Result<(), Error> {
        let builder = IvcConstraintBuilder::new(&config);

        // Assign global and constraint it as public input
        let global = witness_assignments::assign_global_as_public_input(
            &builder,
            &mut layouter,
            &self.global,
            &self.certificate_circuit_domain_and_constraint_system,
            &self.ivc_circuit_domain_and_constraint_system,
        )?;
        // Assign previous state
        let state = witness_assignments::assign_state(&builder, &mut layouter, &self.state)?;
        // Assign witness for the new certificate to be aggregated
        let witness = witness_assignments::assign_witness(&builder, &mut layouter, &self.witness)?;

        // If state.step_counter = 0, we are aggregating the genesis certificate
        let is_genesis = builder.is_genesis(&mut layouter, &state)?;
        let is_not_genesis = builder.native_gadget.not(&mut layouter, &is_genesis)?;

        // Verify genesis certificate
        builder.assert_genesis(&mut layouter, &is_not_genesis, &global, &witness)?;

        // Verify certificate chain link between the last aggregated certificate and the new certificate to obtain the next state
        let next_state = builder.transition(
            &mut layouter,
            &is_genesis,
            &is_not_genesis,
            &global,
            &state,
            &witness,
        )?;
        // Constrain the next state as public input
        witness_assignments::constrain_state_as_public_input(&builder, &mut layouter, &next_state)?;

        // Verify (prepare) certificate_proof and previous ivc_proof and update accumulator
        let next_acc = builder.verify_prepare(
            &mut layouter,
            &global,
            &is_not_genesis,
            &state,
            &witness,
            &self.certificate_proof,
            &self.ivc_proof,
            &self.acc,
        )?;
        // Constrain the next accumulator as public input
        builder
            .verifier_gadget
            .constrain_as_public_input(&mut layouter, &next_acc)?;

        builder.core_decomp_chip.load(&mut layouter)?;
        builder.sha2_256_chip.load(&mut layouter)
    }
}

#[cfg(test)]
mod tests {
    use midnight_proofs::dev::cost_model::circuit_model;

    use crate::{
        circuits::{
            halo2::NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
            halo2_ivc::RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        },
        codec::TryFromBytes,
    };

    use super::*;

    #[test]
    fn ivc_circuit_constraint_count() {
        let mut cs = ConstraintSystem::<NativeField>::default();
        configure_ivc_circuit(&mut cs);

        let poly_constraints: usize = cs.gates().iter().map(|g| g.polynomials().len()).sum();
        assert_eq!(
            RECURSIVE_CIRCUIT_DEGREE, 19,
            "circuit size k must not change without a deliberate decision"
        );
        assert_eq!(
            poly_constraints, 53,
            "polynomial constraint count must not silently grow"
        );
        assert_eq!(
            cs.lookups().len(),
            7,
            "lookup argument count must not silently grow"
        );
    }

    #[test]
    fn recursive_circuit_constraint_degree_stays_constant() {
        let certificate_verification_key = NonRecursiveCircuitVerifyingKey::try_from_bytes(
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        )
        .unwrap();
        let ivc_data = IvcCircuitData::unknown(&certificate_verification_key).unwrap();

        const SIZE_BLS12_KZG_COMMITMENT: usize = 48;
        const SIZE_SCALAR_FIELD_ELEMENT: usize = 32;
        let circuit_model =
            circuit_model::<_, SIZE_BLS12_KZG_COMMITMENT, SIZE_SCALAR_FIELD_ELEMENT>(&ivc_data);

        assert_eq!(circuit_model.k, RECURSIVE_CIRCUIT_DEGREE);
    }

    #[test]
    fn production_recursive_circuit_verification_key_constraint_degree_stays_constant() {
        let recursive_verifying_key = RecursiveCircuitVerifyingKey::try_from_bytes(
            RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        )
        .unwrap();

        assert_eq!(
            recursive_verifying_key.circuit_degree(),
            RECURSIVE_CIRCUIT_DEGREE,
        );
    }
}
