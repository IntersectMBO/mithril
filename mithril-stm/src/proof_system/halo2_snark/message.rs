use anyhow::Context;

use crate::{StmResult, signature_scheme::BaseFieldElement};

/// Build the SNARK message from a Merkle tree commitment digest and a raw message.
///
/// The digest is converted via `from_bytes`, which requires a canonical field element
/// (rejects values >= p). The message is converted via `from_raw`, which interprets
/// the bytes as a little-endian integer and applies modular reduction.
///
/// # Error
/// Returns an error if the digest or the message is not exactly 32 bytes, or if the digest
/// is not a canonical field element.
pub(crate) fn build_snark_message(
    merkle_tree_commitment_digest: &[u8],
    message: &[u8],
) -> StmResult<[BaseFieldElement; 2]> {
    let root_bytes: [u8; 32] = merkle_tree_commitment_digest
        .try_into()
        .with_context(|| "Merkle tree commitment digest must be exactly 32 bytes.")?;
    let root_as_base_field_element = BaseFieldElement::from_bytes(&root_bytes)
        .with_context(|| "Failed to convert Merkle tree commitment digest to BaseFieldElement.")?;

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

    let message_as_base_field_element = BaseFieldElement::from_raw(&msg_bytes)
        .with_context(|| "Failed to convert message to BaseFieldElement.")?;

    Ok([root_as_base_field_element, message_as_base_field_element])
}

#[cfg(test)]
mod test {
    use rand::random_range;

    use crate::{BaseFieldElement, proof_system::halo2_snark::build_snark_message};

    #[test]
    fn correct_size_message_works() {
        let merkle_tree_commitment_digest = [0u8; 32];
        let message = [0u8; 32];

        let snark_message = build_snark_message(&merkle_tree_commitment_digest, &message);

        assert!(
            snark_message.is_ok(),
            "Conversion of correctly sized bytes arrays should fail!"
        );
    }

    #[test]
    fn correct_size_message_but_invalid_root_bytes_fails() {
        let mut merkle_tree_commitment_digest: Vec<u8> =
            (0..32).map(|_| random_range(0..255)).collect();
        merkle_tree_commitment_digest[31] = 255;
        let message: Vec<u8> = (0..32).map(|_| random_range(0..255)).collect();

        let snark_message = build_snark_message(&merkle_tree_commitment_digest, &message);

        assert!(
            snark_message.is_err(),
            "Conversion of random bytes should not create a valid field element!"
        );
    }

    #[test]
    fn wrong_size_message_fails() {
        let merkle_tree_commitment_digest = [0u8; 32];
        let message = [0u8; 33];

        let snark_message = build_snark_message(&merkle_tree_commitment_digest, &message);

        println!("{:?}", snark_message);

        assert!(
            snark_message.is_err(),
            "Conversion of correctly sized bytes arrays should fail!"
        );
    }

    #[test]
    fn correct_size_message_encoded_in_hex_works() {
        let merkle_tree_commitment_digest = [0u8; 32];
        let message: Vec<u8> = (0..32).map(|_| random_range(0..255)).collect();

        let message_as_base_field_element =
            BaseFieldElement::from_raw(message.as_slice().try_into().unwrap()).unwrap();

        let mut encoded_message_bytes = [0u8; 64];
        hex::encode_to_slice(&message, &mut encoded_message_bytes).unwrap();
        let snark_message =
            build_snark_message(&merkle_tree_commitment_digest, &encoded_message_bytes);

        assert!(
            snark_message.is_ok(),
            "Conversion of correctly encoded 32 bytes array shouldn't fail!"
        );
        assert_eq!(
            message_as_base_field_element,
            snark_message.unwrap()[1],
            "Both elements should be the same!"
        )
    }

    #[test]
    fn wrong_size_message_encoded_in_hex_fails() {
        let merkle_tree_commitment_digest = [0u8; 32];
        let large_message: Vec<u8> = (0..33).map(|_| random_range(0..255)).collect();
        let small_message: Vec<u8> = (0..31).map(|_| random_range(0..255)).collect();

        let mut encoded_message_bytes = [0u8; 66];
        hex::encode_to_slice(&large_message, &mut encoded_message_bytes).unwrap();
        let large_snark_message =
            build_snark_message(&merkle_tree_commitment_digest, &encoded_message_bytes);

        let mut encoded_message_bytes = [0u8; 62];
        hex::encode_to_slice(&small_message, &mut encoded_message_bytes).unwrap();
        let small_snark_message =
            build_snark_message(&merkle_tree_commitment_digest, &encoded_message_bytes);

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
