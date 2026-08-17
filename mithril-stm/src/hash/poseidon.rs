use digest::generic_array::typenum::U32;
use digest::{FixedOutput, HashMarker, Output, OutputSizeUser, Reset, Update};
use midnight_circuits::{hash::poseidon::PoseidonChip, instructions::hash::HashCPU};
use midnight_curves::Fq as JubjubBase;

/// Wrapper to implement the Digest trait for the Poseidon hash function
/// We need this implementation to keep the merkle tree implementation
/// generic over the Digest used.
///
/// This implementation differs from the usual behavior of the digest
/// update as documented in the update implementation.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct MidnightPoseidonDigest {
    buffer: Vec<u8>,
}

impl MidnightPoseidonDigest {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }
}

impl Update for MidnightPoseidonDigest {
    // The finalize function uses the from_raw method from JubjubBase
    // but this function converts a value of exactly 256 bits to a value of 255 bits
    // which means we can loose one bit of the input if not careful.
    // This is why we need to make sure that the update function input
    // always represent an element of JubjubBase before calling it.
    // A potential way to make sure we don't loose a bit of information
    // could be to only allow the update function to take a maximum of 32 bytes
    // at a time. It would be a sort of check that makes sure we're not calling
    // this function on "wrong" inputs somewhere in the code
    //
    // The function is also using a padding which deviates from the tradition usage
    // of the digest in which update([1]).update([2]) gives the same result as
    // update([1, 2]). We leave this functionality as is for now since this
    // function is only used for the merkle tree and we prefer this behavior
    fn update(&mut self, data: &[u8]) {
        // Computes the next multiple of 32 as target length
        let target_len = (data.len() + 31) & !31;
        let mut padded_data = Vec::with_capacity(target_len);
        padded_data.extend_from_slice(data);
        // Pad the data with zeros on the right to match the target length
        padded_data.resize(target_len, 0);
        self.buffer.extend_from_slice(&padded_data);
    }
}

impl OutputSizeUser for MidnightPoseidonDigest {
    type OutputSize = U32;
}

impl FixedOutput for MidnightPoseidonDigest {
    fn finalize_into(self, out: &mut Output<Self>) {
        // The data is padded during the call to the update function
        // so there should always be a multiple of 32 bytes in the buffer
        // We are taking chunks of 32 u8 so it should be fine to unwrap
        let (chunks, _remainder) = self.buffer.as_chunks::<32>();
        let poseidon_input = chunks
            .iter()
            .map(|chunk| {
                // The from_raw function performs a modular reduction so
                // it will never fail even if the buffer value exceeds
                // the value of the modulus
                // Since we should only get inputs that represent JubjubBase
                // elements, we could also switch to from_bytes_le
                JubjubBase::from_raw([
                    u64::from_le_bytes(chunk[0..8].try_into().unwrap()),
                    u64::from_le_bytes(chunk[8..16].try_into().unwrap()),
                    u64::from_le_bytes(chunk[16..24].try_into().unwrap()),
                    u64::from_le_bytes(chunk[24..32].try_into().unwrap()),
                ])
            })
            .collect::<Vec<JubjubBase>>();
        let result: JubjubBase = PoseidonChip::<JubjubBase>::hash(&poseidon_input);
        out.copy_from_slice(&result.to_bytes_le());
    }
}

impl Reset for MidnightPoseidonDigest {
    fn reset(&mut self) {
        self.buffer.clear();
    }
}

impl HashMarker for MidnightPoseidonDigest {}

#[cfg(test)]
mod tests {
    use blake2::digest::Digest;
    use midnight_circuits::{hash::poseidon::PoseidonChip, instructions::hash::HashCPU};
    use midnight_curves::Fq as JubjubBase;

    use super::MidnightPoseidonDigest;

    #[test]
    fn test_digest_impl_single_element() {
        let bytes = [0u8; 32];
        let elem = JubjubBase::from_raw([
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        ]);

        let digest_result = MidnightPoseidonDigest::digest(bytes).to_vec();
        let mut digest_result_bytes = [0u8; 32];
        digest_result_bytes.copy_from_slice(&digest_result);
        let digest_result_elem = JubjubBase::from_bytes_le(&digest_result_bytes).unwrap();
        let digest_result_poseidon = PoseidonChip::<JubjubBase>::hash(&[elem]);

        assert_eq!(digest_result_elem, digest_result_poseidon);
    }

    #[test]
    fn test_digest_impl_chain_update() {
        let bytes = [0u8; 32];
        let elem = JubjubBase::from_raw([
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        ]);

        let digest_result = MidnightPoseidonDigest::new()
            .chain_update(bytes)
            .chain_update(bytes)
            .finalize()
            .to_vec();
        let mut digest_result_bytes = [0u8; 32];
        digest_result_bytes.copy_from_slice(&digest_result);
        let digest_result_elem = JubjubBase::from_bytes_le(&digest_result_bytes).unwrap();
        let digest_result_poseidon = PoseidonChip::<JubjubBase>::hash(&[elem, elem]);

        assert_eq!(digest_result_elem, digest_result_poseidon);
    }

    #[test]
    fn test_digest_impl_single_byte() {
        let byte = 2u8;
        let elem = JubjubBase::from(byte as u64);

        let digest_result = MidnightPoseidonDigest::digest([byte]).to_vec();
        let mut digest_result_bytes = [0u8; 32];
        digest_result_bytes.copy_from_slice(&digest_result);
        let digest_result_elem = JubjubBase::from_bytes_le(&digest_result_bytes).unwrap();
        let poseidon_result = PoseidonChip::<JubjubBase>::hash(&[elem]);

        assert_eq!(digest_result_elem, poseidon_result);
    }

    #[test]
    fn test_digest_impl_empty_byte_array() {
        let digest_result = MidnightPoseidonDigest::digest([]).to_vec();
        let mut digest_result_bytes = [0u8; 32];
        digest_result_bytes.copy_from_slice(&digest_result);
        let digest_result_elem = JubjubBase::from_bytes_le(&digest_result_bytes).unwrap();
        let poseidon_result = PoseidonChip::<JubjubBase>::hash(&[]);

        assert_eq!(digest_result_elem, poseidon_result);
    }

    #[test]
    fn test_digest_impl_input_not_multiple_32() {
        let bytes = [1u8; 48];
        let zero_bytes = [0u8; 16];
        let elem1 = JubjubBase::from_raw([
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        ]);
        let elem2 = JubjubBase::from_raw([
            u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            u64::from_le_bytes(zero_bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(zero_bytes[8..16].try_into().unwrap()),
        ]);

        let digest_result = MidnightPoseidonDigest::digest(bytes).to_vec();
        let mut digest_result_bytes = [0u8; 32];
        digest_result_bytes.copy_from_slice(&digest_result);
        let digest_result_elem = JubjubBase::from_bytes_le(&digest_result_bytes).unwrap();
        let poseidon_result = PoseidonChip::<JubjubBase>::hash(&[elem1, elem2]);

        assert_eq!(digest_result_elem, poseidon_result);
    }

    #[test]
    fn test_digest_impl_chain_update_order() {
        let one = JubjubBase::from(1u64);
        let two = JubjubBase::from(2u64);
        let three = JubjubBase::from(3u64);

        let digest_result = MidnightPoseidonDigest::new()
            .chain_update([1u8])
            .chain_update([3u8])
            .chain_update([2u8])
            .finalize()
            .to_vec();
        let mut digest_result_bytes = [0u8; 32];
        digest_result_bytes.copy_from_slice(&digest_result);
        let digest_result_elem = JubjubBase::from_bytes_le(&digest_result_bytes).unwrap();
        let poseidon_result = PoseidonChip::<JubjubBase>::hash(&[one, three, two]);

        assert_eq!(digest_result_elem, poseidon_result);
    }

    #[test]
    fn test_collision_for_large_values() {
        let mut value = [0; 32];
        value[0] = 1;
        let modulus_plus_one = [
            2, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115,
        ];

        let digest_result = MidnightPoseidonDigest::new().chain_update(value).finalize().to_vec();
        let mut digest_result_bytes = [0u8; 32];
        digest_result_bytes.copy_from_slice(&digest_result);
        let digest_result_elem = JubjubBase::from_bytes_le(&digest_result_bytes).unwrap();
        let digest_result_mod = MidnightPoseidonDigest::new()
            .chain_update(modulus_plus_one)
            .finalize()
            .to_vec();
        let mut digest_result_bytes_mod = [0u8; 32];
        digest_result_bytes_mod.copy_from_slice(&digest_result_mod);
        let digest_result_elem_mod = JubjubBase::from_bytes_le(&digest_result_bytes_mod).unwrap();

        assert!(
            digest_result_elem == digest_result_elem_mod,
            "The hash of 1 and modulus + 1 give the same result!"
        );
    }

    #[cfg(test)]
    mod golden_tests {
        use super::*;

        const GOLDEN_BYTES: [u8; 32] = [
            110, 103, 7, 180, 60, 102, 100, 65, 91, 212, 214, 109, 138, 43, 27, 222, 2, 206, 234,
            218, 176, 114, 103, 100, 18, 121, 123, 177, 36, 188, 37, 95,
        ];

        fn golden_value() -> JubjubBase {
            let digest_result = MidnightPoseidonDigest::new()
                .chain_update([1u8])
                .chain_update([3u8])
                .chain_update([2u8])
                .finalize()
                .to_vec();
            let mut digest_result_bytes = [0u8; 32];
            digest_result_bytes.copy_from_slice(&digest_result);

            JubjubBase::from_bytes_le(&digest_result_bytes).unwrap()
        }

        #[test]
        fn golden_test_chain_update() {
            let value = JubjubBase::from_bytes_le(&GOLDEN_BYTES).unwrap();

            assert_eq!(golden_value(), value);
        }
    }
}
