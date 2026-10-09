//! Derives the certificate message from the hash of the protocol message preimage, in-circuit.

use crate::circuits::halo2_ivc::{
    AssignedByte, AssignedNative, AssignmentInstructions, Error, Layouter, NativeField, ZkStdLib,
};
use crate::signature_scheme::DOMAIN_SEPARATION_TAG_SNARK_MESSAGE;

use super::combine_bytes;

/// Reduces the 32-byte SHA-256 hash of the protocol message preimage to the certificate message,
/// matching `BaseFieldElement::from_message_collision_resistant` off-circuit: the Poseidon hash, under the SNARK message tag, of
/// the hash's two 16-byte halves read as little-endian integers.
///
/// `bases` holds the powers of 256 the halves are combined with, and must have at least 16 entries.
pub(crate) fn protocol_message_hash_to_field_element(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<NativeField>,
    hash: &[AssignedByte<NativeField>],
    bases: &[NativeField],
) -> Result<AssignedNative<NativeField>, Error> {
    let message_low = combine_bytes(std_lib, layouter, &hash[0..16], bases)?;
    let message_high = combine_bytes(std_lib, layouter, &hash[16..32], bases)?;
    let domain_separation_tag: AssignedNative<NativeField> =
        std_lib.assign_fixed(layouter, DOMAIN_SEPARATION_TAG_SNARK_MESSAGE.0)?;
    std_lib.poseidon(
        layouter,
        &[domain_separation_tag, message_low, message_high],
    )
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use midnight_circuits::instructions::{AssertionInstructions, AssignmentInstructions};
    use midnight_proofs::plonk::Error;
    use midnight_zk_stdlib::ZkStdLibArch;
    use sha2::{Digest, Sha256};

    use crate::circuits::halo2::tests::test_helpers::{
        assert_relation_rejected, impl_focused_test_relation, prove_and_verify_relation,
    };
    use crate::circuits::halo2_ivc::{AssignedByte, AssignedNative, NativeField, PREIMAGE_SIZE};
    use crate::signature_scheme::BaseFieldElement;

    use super::protocol_message_hash_to_field_element;

    fn sha2_256_poseidon_used_chips() -> ZkStdLibArch {
        ZkStdLibArch {
            sha2_256: true,
            poseidon: true,
            nr_pow2range_cols: 2,
            ..ZkStdLibArch::default()
        }
    }

    impl_focused_test_relation!(
        ProtocolMessageHashRelation,
        ([u8; PREIMAGE_SIZE], NativeField),
        error = Error,
        sha2_256_poseidon_used_chips(),
        |std_lib, layouter, witness| {
            let message_preimage: Vec<AssignedByte<NativeField>> = std_lib.assign_many(
                layouter,
                &witness
                    .map(|(preimage, _)| preimage.to_vec())
                    .transpose_vec(PREIMAGE_SIZE),
            )?;
            let expected_message: AssignedNative<NativeField> =
                std_lib.assign(layouter, witness.map(|(_, message)| message))?;
            let bases: Vec<NativeField> = (0..32)
                .scan(NativeField::ONE, |base, _| {
                    let current = *base;
                    *base *= NativeField::from(256u64);
                    Some(current)
                })
                .collect();

            let hash = std_lib.sha2_256(layouter, &message_preimage)?;
            let message = protocol_message_hash_to_field_element(std_lib, layouter, &hash, &bases)?;
            std_lib.assert_equal(layouter, &message, &expected_message)
        }
    );

    /// A preimage whose SHA-256 hash is above the field modulus, so reducing the hash as a single
    /// field element would lose information.
    const PREIMAGE_WITH_A_HASH_ABOVE_THE_MODULUS: [u8; PREIMAGE_SIZE] = [0u8; PREIMAGE_SIZE];

    #[test]
    fn fixture_preimage_hashes_above_the_modulus() {
        let hash: [u8; 32] = Sha256::digest(PREIMAGE_WITH_A_HASH_ABOVE_THE_MODULUS).into();

        BaseFieldElement::from_canonical_bytes(&hash)
            .expect_err("the fixture hash should not be a canonical field element");
    }

    #[test]
    fn message_matches_its_off_circuit_reduction() {
        let preimage = PREIMAGE_WITH_A_HASH_ABOVE_THE_MODULUS;
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        let off_circuit_message = BaseFieldElement::from_message_collision_resistant(&hash).0;

        prove_and_verify_relation(
            &ProtocolMessageHashRelation,
            &(),
            (preimage, off_circuit_message),
        )
        .expect("the in-circuit message should match its off-circuit reduction");
    }

    #[test]
    fn message_is_not_the_reduced_hash() {
        let preimage = PREIMAGE_WITH_A_HASH_ABOVE_THE_MODULUS;
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        let reduced_hash = BaseFieldElement::from_raw(&hash).unwrap().0;

        assert_relation_rejected(prove_and_verify_relation(
            &ProtocolMessageHashRelation,
            &(),
            (preimage, reduced_hash),
        ));
    }
}
