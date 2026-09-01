use anyhow::Context;
use ff::Field;
use group::Group;
use midnight_circuits::ecc::curves::CircuitCurve as CircuitCurveTrait;
use midnight_circuits::instructions::{AssignmentInstructions, PublicInputInstructions};
use midnight_circuits::types::{AssignedNative, AssignedNativePoint};
use midnight_proofs::circuit::{Layouter, Value};
use midnight_zk_stdlib::{Relation, ZkStdLib, ZkStdLibArch};

use crate::circuits::halo2::errors::StmCircuitError;
use crate::circuits::halo2::gadgets::{
    LOTTERY_BIT_BOUND, MerklePathInputs, UniqueSchnorrSignatureInputs,
    assert_lottery_index_in_bounds, assert_lottery_won, assert_strictly_increasing_lottery_index,
    verify_merkle_path, verify_unique_signature,
};
use crate::circuits::halo2::types::{CircuitBase, CircuitCurve};
use crate::circuits::halo2::witness::{CircuitInstance, CircuitWitness};
use crate::circuits::halo2::witness_assignments::{
    assign_signature_components, assign_witness_entry,
};
use crate::signature_scheme::{
    DOMAIN_SEPARATION_TAG_LOTTERY, DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE,
};
use crate::{LotteryIndex, Parameters, StmResult};

/// Halo2 relation implementing the non-recursive STM verification circuit.
///
/// Carries only the parameters that fix the constraint system; the instance and witness are
/// supplied separately to `Relation::circuit`. `IvcCircuitData` on the recursive side is named
/// for its contents instead: it bundles a concrete step's values with the verifier metadata
/// required during synthesis.
#[derive(Clone, Default, Debug)]
pub struct CertificateCircuit {
    // k in mithril: the required number of distinct lottery index slots needed to create a valid multi-signature
    k: u32,
    // m in mithril: the number of lotteries that a signer can participate in for a message
    m: u32,
    merkle_tree_depth: u32,
}

impl CertificateCircuit {
    fn checked_len_u32(actual: usize) -> u32 {
        u32::try_from(actual).unwrap_or(u32::MAX)
    }

    /// Returns the configured Merkle tree depth used to size witness path assignments.
    pub(crate) fn merkle_tree_depth(&self) -> u32 {
        self.merkle_tree_depth
    }

    /// Validates global circuit parameters before synthesis.
    ///
    /// Enforces `k < m <= 2^LOTTERY_BIT_BOUND - 1`, returning
    /// `StmCircuitError::InvalidCircuitParameters` when violated.
    pub(crate) fn validate_parameters(&self) -> Result<(), StmCircuitError> {
        let max_m = (1u32 << LOTTERY_BIT_BOUND) - 1;
        if self.k >= self.m || self.m > max_m {
            return Err(StmCircuitError::InvalidCircuitParameters {
                k: self.k,
                m: self.m,
            });
        }

        Ok(())
    }

    /// Validates that witness vector length matches the configured k.
    ///
    /// This precondition prevents shape mismatches; failures return
    /// `StmCircuitError::WitnessLengthMismatch`.
    pub(crate) fn validate_witness_length(&self, actual: usize) -> Result<(), StmCircuitError> {
        let expected_k = self.k as usize;
        if actual != expected_k {
            return Err(StmCircuitError::WitnessLengthMismatch {
                expected_k: self.k,
                actual: Self::checked_len_u32(actual),
            });
        }

        Ok(())
    }

    /// Validates witness lottery indices against circuit constraints.
    ///
    /// The circuit uses [`LOTTERY_BIT_BOUND`]-bit comparison constraints, so each
    /// index must fit in that range and must satisfy `index < m`.
    pub(crate) fn validate_lottery_index(
        &self,
        index: LotteryIndex,
    ) -> Result<(), StmCircuitError> {
        let max_supported = ((1u64 << LOTTERY_BIT_BOUND) - 1) as LotteryIndex;
        if index > max_supported {
            return Err(StmCircuitError::LotteryIndexTooLarge {
                index,
                max_supported,
            });
        }

        if index >= self.m as LotteryIndex {
            return Err(StmCircuitError::LotteryIndexOutOfBounds { index, m: self.m });
        }

        Ok(())
    }

    /// Validates Merkle sibling path length against `merkle_tree_depth`.
    ///
    /// This guards against inconsistent witness paths and returns
    /// `StmCircuitError::MerkleSiblingLengthMismatch` on mismatch.
    pub(crate) fn validate_merkle_sibling_length(
        &self,
        actual: usize,
    ) -> Result<(), StmCircuitError> {
        let expected_depth = self.merkle_tree_depth as usize;
        if actual != expected_depth {
            return Err(StmCircuitError::MerkleSiblingLengthMismatch {
                expected_depth: self.merkle_tree_depth,
                actual: Self::checked_len_u32(actual),
            });
        }

        Ok(())
    }

    /// Validates Merkle position bits length against `merkle_tree_depth`.
    ///
    /// Under the current witness shape, this cannot fail independently from sibling-length
    /// validation because both lengths derive from `x.siblings`; returns `StmCircuitError::MerklePositionLengthMismatch`.
    pub(crate) fn validate_merkle_position_length(
        &self,
        actual: usize,
    ) -> Result<(), StmCircuitError> {
        let expected_depth = self.merkle_tree_depth as usize;
        if actual != expected_depth {
            return Err(StmCircuitError::MerklePositionLengthMismatch {
                expected_depth: self.merkle_tree_depth,
                actual: Self::checked_len_u32(actual),
            });
        }

        Ok(())
    }

    /// Constructs a new `CertificateCircuit` from Mithril `Parameters`.
    ///  
    /// This constructor only validates that `k` and `m`
    /// fit into a `u32` by performing fallible `u64 -> u32` conversions. If either value  
    /// exceeds `u32::MAX`, it returns an error.  
    ///  
    /// It does **not** enforce semantic constraints such as `k < m` or other parameter  
    /// relationships; those invariants are validated later during circuit synthesis via  
    /// `validate_parameters`.
    pub fn try_new(stm_params: &Parameters, merkle_tree_depth: u32) -> StmResult<Self> {
        Ok(Self {
            k: stm_params.k.try_into().with_context(|| {
                format!(
                    "Failed to cast k as a u32. Its value ({}) is too large for the circuit.",
                    stm_params.k
                )
            })?,
            m: stm_params.m.try_into().with_context(|| {
                format!(
                    "Failed to cast m as a u32. Its value ({}) is too large for the circuit.",
                    stm_params.m
                )
            })?,
            merkle_tree_depth,
        })
    }
}

impl Relation for CertificateCircuit {
    type Error = StmCircuitError;
    type Instance = CircuitInstance;
    type Witness = CircuitWitness;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<CircuitBase>, StmCircuitError> {
        Ok(vec![instance.0.into(), instance.1.into()])
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<CircuitBase>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), StmCircuitError> {
        self.validate_parameters()?;
        let witness = witness
            .map_with_result(|witness| -> Result<_, StmCircuitError> {
                self.validate_witness_length(witness.len())?;
                witness
                    .iter()
                    .try_for_each(|entry| self.validate_lottery_index(entry.lottery_index))?;
                Ok(witness)
            })?
            .transpose_vec(self.k as usize);

        let merkle_tree_commitment: AssignedNative<CircuitBase> =
            std_lib.assign_as_public_input(layouter, instance.map(|(x, _)| x.into()))?;
        let message: AssignedNative<CircuitBase> =
            std_lib.assign_as_public_input(layouter, instance.map(|(_, x)| x.into()))?;

        // Compute H_1(merkle_tree_commitment, message)
        let hash =
            std_lib.hash_to_curve(layouter, &[merkle_tree_commitment.clone(), message.clone()])?;

        let generator: AssignedNativePoint<CircuitCurve> = std_lib.jubjub().assign_fixed(
            layouter,
            <CircuitCurve as CircuitCurveTrait>::CryptographicGroup::generator(),
        )?;

        let domain_separation_tag_signature: AssignedNative<_> = std_lib.assign_fixed(
            layouter,
            CircuitBase::from(DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE),
        )?;
        let domain_separation_tag_lottery: AssignedNative<_> =
            std_lib.assign_fixed(layouter, CircuitBase::from(DOMAIN_SEPARATION_TAG_LOTTERY))?;
        let lottery_prefix = std_lib.poseidon(
            layouter,
            &[
                domain_separation_tag_lottery.clone(),
                merkle_tree_commitment.clone(),
                message.clone(),
            ],
        )?;

        let mut previous_lottery_index: AssignedNative<_> =
            std_lib.assign(layouter, Value::known(CircuitBase::ZERO))?;
        for (i, wit) in witness.into_iter().enumerate() {
            let assigned_witness_entry =
                assign_witness_entry(self, std_lib, layouter, wit.clone())?;

            // Check lottery index order
            if i > 0 {
                assert_strictly_increasing_lottery_index(
                    std_lib,
                    layouter,
                    &previous_lottery_index,
                    &assigned_witness_entry.lottery_index,
                )?;
            }

            previous_lottery_index = assigned_witness_entry.lottery_index.clone();

            let assigned_signature_components =
                assign_signature_components(std_lib, layouter, wit)?;

            verify_merkle_path(
                std_lib,
                layouter,
                MerklePathInputs {
                    verification_key: &assigned_witness_entry.verification_key,
                    lottery_target_value: &assigned_witness_entry.lottery_target_value,
                    merkle_tree_commitment: &merkle_tree_commitment,
                    merkle_siblings: &assigned_witness_entry.merkle_path.siblings,
                    merkle_positions: &assigned_witness_entry.merkle_path.positions,
                    merkle_tree_depth: self.merkle_tree_depth,
                },
            )?;

            verify_unique_signature(
                std_lib,
                layouter,
                UniqueSchnorrSignatureInputs {
                    dst_signature: &domain_separation_tag_signature,
                    generator: &generator,
                    verification_key: &assigned_witness_entry.verification_key,
                    response: &assigned_signature_components.response,
                    challenge_in_base_field: &assigned_signature_components.challenge_in_base_field,
                    challenge_as_scalar: &assigned_signature_components.challenge_as_scalar,
                    hash: &hash,
                    commitment_point: &assigned_signature_components.commitment_point,
                },
            )?;

            assert_lottery_won(
                std_lib,
                layouter,
                &lottery_prefix,
                &assigned_signature_components.commitment_point,
                &assigned_witness_entry.lottery_index,
                &assigned_witness_entry.lottery_target_value,
            )?;
        }

        // m can be put as a public instance or a constant
        let m = std_lib.assign_fixed(layouter, CircuitBase::from(self.m as u64))?;
        assert_lottery_index_in_bounds(std_lib, layouter, &previous_lottery_index, &m)
            .map_err(StmCircuitError::from)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            jubjub: true,
            poseidon: true,
            sha2_256: false,
            sha2_512: false,
            keccak_256: false,
            sha3_256: false,
            secp256k1: false,
            bls12_381: false,
            base64: false,
            nr_pow2range_cols: 2,
            automaton: false,
            blake2b: false,
            curve25519: false,
            p256: false,
        }
    }

    fn write_relation<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.k.to_le_bytes())?;
        writer.write_all(&self.m.to_le_bytes())?;
        writer.write_all(&self.merkle_tree_depth.to_le_bytes())
    }

    fn read_relation<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        // Buffers to read 4 bytes for each `u32` field.
        let mut k_bytes = [0u8; 4];
        let mut m_bytes = [0u8; 4];
        let mut merkle_tree_depth_bytes = [0u8; 4];

        // Read the values into their corresponding buffers.
        reader.read_exact(&mut k_bytes)?;
        reader.read_exact(&mut m_bytes)?;
        reader.read_exact(&mut merkle_tree_depth_bytes)?;

        // Convert the byte arrays back into `u32` values.
        let k = u32::from_le_bytes(k_bytes);
        let m = u32::from_le_bytes(m_bytes);
        let merkle_tree_depth = u32::from_le_bytes(merkle_tree_depth_bytes);

        Ok(Self {
            k,
            m,
            merkle_tree_depth,
        })
    }
}

#[cfg(test)]
mod dst_alignment_tests {
    use crate::circuits::halo2::types::CircuitBase;
    use crate::signature_scheme::{
        BaseFieldElement, DOMAIN_SEPARATION_TAG_LOTTERY, DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE,
        compute_poseidon_digest,
    };

    use midnight_circuits::{hash::poseidon::PoseidonChip, instructions::hash::HashCPU};

    const REFERENCE_SIGNATURE_DOMAIN_TAG: BaseFieldElement =
        BaseFieldElement(CircuitBase::from_raw([0x5349_474E_5F44_5354, 0, 0, 0]));
    const REFERENCE_LOTTERY_DOMAIN_TAG: BaseFieldElement =
        BaseFieldElement(CircuitBase::from_raw([0x4C4F_5454_5F44_5354, 0, 0, 0]));

    #[test]
    fn signature_and_lottery_domain_tags_do_not_collide() {
        assert_ne!(
            DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE, DOMAIN_SEPARATION_TAG_LOTTERY,
            "signature and lottery domain separation tags must be distinct"
        );
    }

    #[test]
    fn signature_digest_matches_reference_signature_domain_tag_formula() {
        let signature_transcript_inputs = vec![
            BaseFieldElement::from(11),
            BaseFieldElement::from(22),
            BaseFieldElement::from(33),
            BaseFieldElement::from(44),
        ];

        let mut stm_inputs = vec![DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE];
        stm_inputs.extend_from_slice(&signature_transcript_inputs);
        let signature_digest_via_stm = compute_poseidon_digest(&stm_inputs);

        let mut signature_digest_manual_inputs =
            vec![CircuitBase::from(REFERENCE_SIGNATURE_DOMAIN_TAG)];
        signature_digest_manual_inputs.extend(
            signature_transcript_inputs
                .iter()
                .map(|value| CircuitBase::from(*value)),
        );

        let signature_digest_via_reference_formula = BaseFieldElement(
            PoseidonChip::<CircuitBase>::hash(&signature_digest_manual_inputs),
        );

        assert_eq!(
            signature_digest_via_stm, signature_digest_via_reference_formula,
            "signature digest computed via STM helper must match reference signature-domain formula"
        );
    }

    #[test]
    fn lottery_prefix_matches_reference_lottery_domain_tag_formula() {
        let merkle_tree_commitment = CircuitBase::from(123u64);
        let message = CircuitBase::from(456u64);

        let lottery_prefix_via_stm_constant = PoseidonChip::<CircuitBase>::hash(&[
            CircuitBase::from(DOMAIN_SEPARATION_TAG_LOTTERY),
            merkle_tree_commitment,
            message,
        ]);

        let lottery_prefix_via_reference_formula = PoseidonChip::<CircuitBase>::hash(&[
            CircuitBase::from(REFERENCE_LOTTERY_DOMAIN_TAG),
            merkle_tree_commitment,
            message,
        ]);

        assert_eq!(
            BaseFieldElement(lottery_prefix_via_stm_constant),
            BaseFieldElement(lottery_prefix_via_reference_formula),
            "lottery prefix must use the lottery domain separation tag as first Poseidon input"
        );
    }
}

#[cfg(test)]
mod circuit_creation_tests {
    use crate::circuits::halo2::circuit::CertificateCircuit;

    #[test]
    fn correct_circuit_creation() {
        let stm_params = crate::Parameters {
            m: 100,
            k: 10,
            phi_f: 0.2,
        };
        let merkle_tree_depth = 13;

        CertificateCircuit::try_new(&stm_params, merkle_tree_depth).unwrap();
    }

    #[test]
    fn circuit_creation_large_m() {
        let stm_params = crate::Parameters {
            m: u32::MAX as u64 + 1,
            k: 10,
            phi_f: 0.2,
        };
        let merkle_tree_depth = 13;

        let circuit = CertificateCircuit::try_new(&stm_params, merkle_tree_depth);

        circuit.expect_err("Creation should have failed with number of lotteries too large.");
    }

    #[test]
    fn circuit_creation_large_k() {
        let stm_params = crate::Parameters {
            m: 100,
            k: u32::MAX as u64 + 1,
            phi_f: 0.2,
        };
        let merkle_tree_depth = 13;

        let circuit = CertificateCircuit::try_new(&stm_params, merkle_tree_depth);

        circuit.expect_err("Creation should have failed with k too large.");
    }
}

#[cfg(test)]
mod non_recursive_circuit_degree_correctness {
    use midnight_zk_stdlib as zk;

    use crate::{
        Parameters,
        circuits::halo2::{
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION, circuit::CertificateCircuit,
            keys::NonRecursiveCircuitVerifyingKey,
        },
        codec::TryFromBytes,
    };

    const SMALL_CERTIFICATE_CIRCUIT_DEGREE: u32 = 13;

    const NON_RECURSIVE_CIRCUIT_DEGREE: u32 = 22;

    #[test]
    fn non_recursive_circuit_constraint_degree_stays_constant_for_small_circuit() {
        // Those parameters and merkle tree depth lead to a circuit
        // with constraints close to the next power of two
        let parameters = Parameters {
            k: 4,
            m: 10,
            phi_f: 0.2,
        };
        let merkle_tree_depth = 11;

        let circuit = CertificateCircuit::try_new(&parameters, merkle_tree_depth).unwrap();
        let circuit_cost = zk::cost_model(&circuit, None);
        assert_eq!(circuit_cost.k, SMALL_CERTIFICATE_CIRCUIT_DEGREE);

        let circuit = CertificateCircuit::try_new(&parameters, merkle_tree_depth + 1).unwrap();
        let circuit_cost = zk::cost_model(&circuit, None);
        assert_eq!(circuit_cost.k, SMALL_CERTIFICATE_CIRCUIT_DEGREE + 1);
    }

    #[test]
    fn non_recursive_circuit_constraint_degree_stays_constant_for_production_circuit() {
        let non_recursive_circuit_verifying_key = NonRecursiveCircuitVerifyingKey::try_from_bytes(
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        )
        .unwrap();

        assert_eq!(
            non_recursive_circuit_verifying_key.circuit_degree(),
            NON_RECURSIVE_CIRCUIT_DEGREE
        );
    }
}
