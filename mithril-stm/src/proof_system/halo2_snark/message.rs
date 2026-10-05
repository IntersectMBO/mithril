use anyhow::Context;

use crate::{StmResult, signature_scheme::BaseFieldElement};

/// Build the SNARK message from the Merkle tree commitment bytes and a raw message.
///
/// The commitment bytes are converted via `from_bytes`, which requires a canonical field element
/// (rejects values >= p). The message is reduced with [`parse_and_hash_snark_message`].
///
/// # Error
/// Returns an error if the commitment bytes or the message is not exactly 32 bytes, or if the
/// commitment bytes are not a canonical field element.
pub(crate) fn build_snark_message(
    merkle_tree_commitment_bytes: &[u8],
    message: &[u8],
) -> StmResult<[BaseFieldElement; 2]> {
    let root_bytes: [u8; 32] = merkle_tree_commitment_bytes
        .try_into()
        .with_context(|| "Merkle tree commitment bytes must be exactly 32 bytes.")?;
    let root_as_base_field_element = BaseFieldElement::from_bytes(&root_bytes)
        .with_context(|| "Failed to convert Merkle tree commitment bytes to BaseFieldElement.")?;

    Ok([root_as_base_field_element, parse_and_hash_snark_message(message)?])
}

/// Reduce a 32-byte message, or its 64-character hex encoding, to one field element with
/// [`BaseFieldElement::from_message_collision_resistant`].
///
/// # Error
/// Returns an error if the message is neither 32 bytes nor 32 bytes hex encoded in 64 bytes.
pub(crate) fn parse_and_hash_snark_message(message: &[u8]) -> StmResult<BaseFieldElement> {
    let mut msg_bytes = [0u8; 32];
    match TryInto::<[u8; 32]>::try_into(message) {
        Ok(bytes) => msg_bytes = bytes,
        Err(_) => {
            // If the message is not 32 bytes, try to decode it as hex.
            hex::decode_to_slice(message, &mut msg_bytes).with_context(
                || "Message must be exactly 32 bytes hex encoded in 64 bytes if it is not exactly 32 bytes.",
            )?;
        }
    }

    Ok(BaseFieldElement::from_message_collision_resistant(
        &msg_bytes,
    ))
}

#[cfg(test)]
mod test {
    use ff::PrimeField;
    use midnight_curves::Fq as JubjubBase;
    use num_bigint::BigUint;
    use num_traits::Num;
    use proptest::prelude::*;
    use rand::random_range;

    use crate::{
        BaseFieldElement,
        proof_system::halo2_snark::{build_snark_message, message::parse_and_hash_snark_message},
        signature_scheme::{DOMAIN_SEPARATION_TAG_SNARK_MESSAGE, compute_poseidon_digest},
    };

    #[test]
    fn correct_size_message_works() {
        let merkle_tree_commitment_bytes = [0u8; 32];
        let message = [0u8; 32];

        let snark_message = build_snark_message(&merkle_tree_commitment_bytes, &message);

        assert!(
            snark_message.is_ok(),
            "Conversion of correctly sized bytes arrays should fail!"
        );
    }

    #[test]
    fn correct_size_message_but_invalid_root_bytes_fails() {
        let mut merkle_tree_commitment_bytes: Vec<u8> =
            (0..32).map(|_| random_range(0..255)).collect();
        merkle_tree_commitment_bytes[31] = 255;
        let message: Vec<u8> = (0..32).map(|_| random_range(0..255)).collect();

        let snark_message = build_snark_message(&merkle_tree_commitment_bytes, &message);

        assert!(
            snark_message.is_err(),
            "Conversion of random bytes should not create a valid field element!"
        );
    }

    #[test]
    fn wrong_size_message_fails() {
        let merkle_tree_commitment_bytes = [0u8; 32];
        let message = [0u8; 33];

        let snark_message = build_snark_message(&merkle_tree_commitment_bytes, &message);

        println!("{:?}", snark_message);

        assert!(
            snark_message.is_err(),
            "Conversion of correctly sized bytes arrays should fail!"
        );
    }

    #[test]
    fn correct_size_message_encoded_in_hex_works() {
        let merkle_tree_commitment_bytes = [0u8; 32];
        let message: Vec<u8> = (0..32).map(|_| random_range(0..255)).collect();

        let raw_snark_message = build_snark_message(&merkle_tree_commitment_bytes, &message);

        let mut encoded_message_bytes = [0u8; 64];
        hex::encode_to_slice(&message, &mut encoded_message_bytes).unwrap();
        let snark_message =
            build_snark_message(&merkle_tree_commitment_bytes, &encoded_message_bytes);

        assert!(
            snark_message.is_ok(),
            "Conversion of correctly encoded 32 bytes array shouldn't fail!"
        );
        assert_eq!(
            raw_snark_message.unwrap(),
            snark_message.unwrap(),
            "Both messages should be the same!"
        )
    }

    #[test]
    fn message_is_the_tagged_poseidon_of_its_little_endian_halves() {
        let message: [u8; 32] = std::array::from_fn(|i| i as u8);

        let mut low = [0u8; 32];
        low[..16].copy_from_slice(&message[..16]);
        let mut high = [0u8; 32];
        high[..16].copy_from_slice(&message[16..]);
        let expected = compute_poseidon_digest(&[
            DOMAIN_SEPARATION_TAG_SNARK_MESSAGE,
            BaseFieldElement::from_bytes(&low).unwrap(),
            BaseFieldElement::from_bytes(&high).unwrap(),
        ]);

        assert_eq!(expected, parse_and_hash_snark_message(&message).unwrap());
    }

    proptest! {
        // A message and the same message offset by the field modulus reduce to the same field
        // element, which made a plain modular reduction of the message malleable. Every 32-byte
        // message has such a partner: `M + p` when it fits in 32 bytes, `M - p` otherwise, since
        // `p < 2^255`.
        #[test]
        fn messages_congruent_modulo_the_field_modulus_have_different_reductions(
            message in any::<[u8; 32]>(),
        ) {
            let modulus = BigUint::from_str_radix(&JubjubBase::MODULUS[2..], 16).unwrap();
            let value = BigUint::from_bytes_le(&message);
            let partner_value = if &value + &modulus < BigUint::from(1u32) << 256 {
                value + modulus
            } else {
                value - modulus
            };
            let mut partner = [0u8; 32];
            let partner_value_bytes = partner_value.to_bytes_le();
            partner[..partner_value_bytes.len()].copy_from_slice(&partner_value_bytes);

            prop_assert_ne!(message, partner);
            prop_assert_eq!(
                BaseFieldElement::from_raw(&message).unwrap(),
                BaseFieldElement::from_raw(&partner).unwrap(),
            );
            prop_assert_ne!(
                parse_and_hash_snark_message(&message).unwrap(),
                parse_and_hash_snark_message(&partner).unwrap(),
            );
        }
    }

    #[test]
    fn wrong_size_message_encoded_in_hex_fails() {
        let merkle_tree_commitment_bytes = [0u8; 32];
        let large_message: Vec<u8> = (0..33).map(|_| random_range(0..255)).collect();
        let small_message: Vec<u8> = (0..31).map(|_| random_range(0..255)).collect();

        let mut encoded_message_bytes = [0u8; 66];
        hex::encode_to_slice(&large_message, &mut encoded_message_bytes).unwrap();
        let large_snark_message =
            build_snark_message(&merkle_tree_commitment_bytes, &encoded_message_bytes);

        let mut encoded_message_bytes = [0u8; 62];
        hex::encode_to_slice(&small_message, &mut encoded_message_bytes).unwrap();
        let small_snark_message =
            build_snark_message(&merkle_tree_commitment_bytes, &encoded_message_bytes);

        assert!(
            large_snark_message.is_err(),
            "Conversion of correctly encoded 33 bytes array should fail!"
        );
        assert!(
            small_snark_message.is_err(),
            "Conversion of correctly encoded 31 bytes array should fail!"
        );
    }
}
