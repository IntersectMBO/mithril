use anyhow::anyhow;

use crate::StmResult;
use crate::circuits::halo2::keys::NonRecursiveCircuitVerifyingKey;
use crate::circuits::halo2_ivc::keys::RecursiveCircuitVerifyingKey;
use crate::codec::{TryFromBytes, TryToBytes};

use super::{
    Accumulator, BinaryInstructions, CircuitValue, ConstraintSystem, Error, EvaluationDomain,
    Layouter, NativeField, PublicInputInstructions, RECURSIVE_CIRCUIT_DEGREE, RecursiveEmulation,
    Relation, ZkStdLib, ZkStdLibArch,
    constraint_builder::IvcConstraintBuilder,
    errors::IvcCircuitError,
    state::{Global, State, Witness},
    types::{CertificateProofBytes, IvcProofBytes},
    witness_assignments,
};

/// Chips the recursive circuit enables.
///
/// Single source: the relation declares these to the standard library, and key generation
/// configures its own verifier metadata from the same value, so the two cannot drift.
pub(crate) fn recursive_circuit_architecture() -> ZkStdLibArch {
    ZkStdLibArch {
        jubjub: true,
        poseidon: true,
        sha2_256: true,
        sha2_512: false,
        keccak_256: false,
        sha3_256: false,
        secp256k1: false,
        bls12_381: true,
        base64: false,
        // With production certificate metadata, 1 to 3 range columns require k=20 instead of k=19.
        nr_pow2range_cols: 4,
        automaton: false,
        blake2b: false,
        curve25519: false,
        p256: false,
    }
}

/// The IVC (Incrementally Verifiable Computation) circuit, holding what fixes its constraint
/// system: the certificate circuit whose proofs it verifies in-circuit, and its own verifier
/// metadata.
///
/// Mirrors `CertificateCircuit`, which likewise carries only what fixes its constraint system and
/// none of a single execution's values.
#[derive(Clone, Debug)]
pub struct IvcCircuit {
    // Certificate circuit verified in-circuit: its domain and constraint system are the verifier
    // metadata, and it is what a serialized relation carries.
    certificate_verification_key: NonRecursiveCircuitVerifyingKey,
    // Domain and ConstraintSystem associated with IVC circuit VerifyingKey
    ivc_circuit_domain_and_constraint_system:
        (EvaluationDomain<NativeField>, ConstraintSystem<NativeField>),
}

impl IvcCircuit {
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

    /// Builds the circuit from both circuits' verifying keys.
    pub(crate) fn try_new(
        certificate_verification_key: &NonRecursiveCircuitVerifyingKey,
        ivc_verification_key: &RecursiveCircuitVerifyingKey,
    ) -> StmResult<Self> {
        Self::validate_ivc_verification_key_degree(ivc_verification_key)?;

        Ok(IvcCircuit {
            certificate_verification_key: certificate_verification_key.clone(),
            ivc_circuit_domain_and_constraint_system: (
                ivc_verification_key.as_ref().get_domain().clone(),
                ivc_verification_key.as_ref().cs().clone(),
            ),
        })
    }

    /// Derives its own verifier metadata from the circuit's configuration, for the key generation
    /// that has no IVC verifying key to read it from yet.
    pub(crate) fn for_key_generation(
        certificate_verification_key: &NonRecursiveCircuitVerifyingKey,
    ) -> Self {
        let mut ivc_circuit_constraint_system = ConstraintSystem::default();
        ZkStdLib::configure(
            &mut ivc_circuit_constraint_system,
            (
                recursive_circuit_architecture(),
                (RECURSIVE_CIRCUIT_DEGREE - 1) as u8,
            ),
        );
        let ivc_circuit_domain = EvaluationDomain::new(
            ivc_circuit_constraint_system.degree() as u32,
            RECURSIVE_CIRCUIT_DEGREE,
        );

        IvcCircuit {
            certificate_verification_key: certificate_verification_key.clone(),
            ivc_circuit_domain_and_constraint_system: (
                ivc_circuit_domain,
                ivc_circuit_constraint_system,
            ),
        }
    }
}

impl Relation for IvcCircuit {
    type Error = Error;
    type Instance = Vec<NativeField>;
    type Witness = IvcCircuitData;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<NativeField>, Error> {
        Ok(instance.clone())
    }

    /// The statement is constrained by the assignment helpers below as each part is derived, so the
    /// instance argument is not assigned a second time here.
    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<NativeField>,
        _instance: CircuitValue<Self::Instance>,
        witness: CircuitValue<Self::Witness>,
    ) -> Result<(), Error> {
        let builder = IvcConstraintBuilder::new(std_lib);

        // Borrowed, so each part is copied once rather than the whole witness copied once per part.
        let data = witness.as_ref();
        let global_value = data.map(|data| data.global.clone());
        let state_value = data.map(|data| data.state.clone());
        let witness_value = data.map(|data| data.witness.clone());
        let certificate_proof_value = data.map(|data| data.certificate_proof.clone());
        let ivc_proof_value = data.map(|data| data.ivc_proof.clone());
        let accumulator_value = data.map(|data| data.accumulator.clone());

        let (ivc_circuit_domain, ivc_circuit_constraint_system) =
            &self.ivc_circuit_domain_and_constraint_system;

        // Assign global and constraint it as public input
        let global = witness_assignments::assign_global_as_public_input(
            &builder,
            layouter,
            &global_value,
            self.certificate_verification_key.as_ref().get_domain(),
            self.certificate_verification_key.as_ref().cs(),
            ivc_circuit_domain,
            ivc_circuit_constraint_system,
        )?;
        // Assign previous state
        let state = witness_assignments::assign_state(&builder, layouter, &state_value)?;
        // Assign witness for the new certificate to be aggregated
        let witness = witness_assignments::assign_witness(&builder, layouter, &witness_value)?;

        // If state.step_counter = 0, we are aggregating the genesis certificate
        let is_genesis = builder.is_genesis(layouter, &state)?;
        let is_not_genesis = builder.native_gadget.not(layouter, &is_genesis)?;

        // Verify genesis certificate
        builder.assert_genesis(layouter, &is_not_genesis, &global, &witness)?;

        // Verify certificate chain link between the last aggregated certificate and the new certificate to obtain the next state
        let next_state = builder.transition(
            layouter,
            &is_genesis,
            &is_not_genesis,
            &global,
            &state,
            &witness,
        )?;
        // Constrain the next state as public input
        witness_assignments::constrain_state_as_public_input(&builder, layouter, &next_state)?;

        // Verify (prepare) certificate_proof and previous ivc_proof and update accumulator
        let next_acc = builder.verify_prepare(
            layouter,
            &global,
            &is_not_genesis,
            &state,
            &witness,
            &certificate_proof_value,
            &ivc_proof_value,
            &accumulator_value,
        )?;
        // Constrain the next accumulator as public input
        builder.verifier_gadget.constrain_as_public_input(layouter, &next_acc)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        recursive_circuit_architecture()
    }

    fn write_relation<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let bytes = self
            .certificate_verification_key
            .to_bytes_vec()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
        writer.write_all(&bytes)
    }

    fn read_relation<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut length_bytes = [0u8; 4];
        reader.read_exact(&mut length_bytes)?;
        let mut bytes = vec![0u8; u32::from_le_bytes(length_bytes) as usize];
        reader.read_exact(&mut bytes)?;

        let certificate_verification_key = NonRecursiveCircuitVerifyingKey::try_from_bytes(&bytes)
            .map_err(|error| std::io::Error::other(error.to_string()))?;

        Ok(Self::for_key_generation(&certificate_verification_key))
    }
}

/// Values of one step of the IVC (Incrementally Verifiable Computation) circuit: the witness of the
/// relation above.
///
/// Holds the global root-of-trust, the current state, the next certificate witness, the associated
/// SNARK proofs and the latest accumulator.
#[derive(Clone, Debug)]
pub struct IvcCircuitData {
    // Persistent values throughout an ivc stream. This is the root of trust for an ivc stream.
    global: Global,
    // State values from the last aggregated certificate
    state: State,
    // Witness (mainly the next certificate to be aggregated) for deriving the next state
    witness: Witness,
    // Snark proof of the next certificate
    certificate_proof: Vec<u8>,
    // Latest IVC proof
    ivc_proof: Vec<u8>,
    // Latest Accumulator
    accumulator: Accumulator<RecursiveEmulation>,
}

impl IvcCircuitData {
    /// Collects the values of a single IVC step.
    pub(crate) fn new(
        global: Global,
        state: State,
        witness: Witness,
        certificate_proof: CertificateProofBytes,
        ivc_proof: IvcProofBytes,
        accumulator: Accumulator<RecursiveEmulation>,
    ) -> Self {
        IvcCircuitData {
            global,
            state,
            witness,
            certificate_proof: certificate_proof.into_vec(),
            ivc_proof: ivc_proof.into_vec(),
            accumulator,
        }
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

    use midnight_zk_stdlib::MidnightCircuit;

    use super::*;

    fn production_certificate_verification_key() -> NonRecursiveCircuitVerifyingKey {
        NonRecursiveCircuitVerifyingKey::try_from_bytes(
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        )
        .unwrap()
    }

    #[test]
    fn ivc_circuit_constraint_count() {
        let mut cs = ConstraintSystem::<NativeField>::default();
        ZkStdLib::configure(
            &mut cs,
            (
                recursive_circuit_architecture(),
                (RECURSIVE_CIRCUIT_DEGREE - 1) as u8,
            ),
        );

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
        let certificate_verification_key = production_certificate_verification_key();
        let ivc_circuit = IvcCircuit::for_key_generation(&certificate_verification_key);
        let circuit = MidnightCircuit::from_relation(&ivc_circuit, Some(RECURSIVE_CIRCUIT_DEGREE));

        const SIZE_BLS12_KZG_COMMITMENT: usize = 48;
        const SIZE_SCALAR_FIELD_ELEMENT: usize = 32;
        let circuit_model =
            circuit_model::<_, SIZE_BLS12_KZG_COMMITMENT, SIZE_SCALAR_FIELD_ELEMENT>(&circuit);

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
