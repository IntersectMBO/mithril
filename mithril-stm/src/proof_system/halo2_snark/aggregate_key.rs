use serde::{Deserialize, Serialize};

use crate::{
    ClosedKeyRegistration, MembershipDigest, RegistrationEntryForSnark, Stake, StmResult, codec,
    membership_commitment::{MerkleTreeCommitment, MerkleTreeError, MerkleTreeSnarkLeaf},
};

/// Byte width of the rigid-slot encoding produced by
/// [AggregateVerificationKeyForSnark::to_rigid_slot_bytes]. Matches the layout consumed by the
/// IVC test fixture's `From<AggregateVerificationKey> for Vec<u8>` and the rigid protocol
/// message slot for the next SNARK aggregate verification key.
pub const RIGID_SLOT_BYTES: usize = 44;

/// Aggregate verification key for the SNARK proof system.
///
/// This key embeds the Merkle tree commitment over the SNARK registration entries
/// (Schnorr verification keys and lottery target values), along with the total
/// registered stake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateVerificationKeyForSnark<D: MembershipDigest> {
    merkle_tree_commitment: MerkleTreeCommitment<D::SnarkHash, MerkleTreeSnarkLeaf>,
    total_stake: Stake,
}

impl<D: MembershipDigest> AggregateVerificationKeyForSnark<D> {
    /// Get the Merkle tree commitment.
    pub(crate) fn get_merkle_tree_commitment(
        &self,
    ) -> &MerkleTreeCommitment<D::SnarkHash, MerkleTreeSnarkLeaf> {
        &self.merkle_tree_commitment
    }

    /// Get the total stake.
    pub fn get_total_stake(&self) -> Stake {
        self.total_stake
    }

    /// Encode to the `RIGID_SLOT_BYTES`-byte rigid-slot layout consumed by the protocol message
    /// `next_aggregate_verification_key` rigid slot:
    ///
    /// `root_LE (32) || nr_leaves_LE_u32 (4) || total_stake_LE_u64 (8)`.
    ///
    /// The IVC circuit fixture's `From<AggregateVerificationKey> for Vec<u8>` writes a 4-byte
    /// `nr_leaves` field between the root and the total stake. This is a misconception of the
    /// IVC fixture: production [AggregateVerificationKeyForSnark] does not carry the leaf
    /// count, and the IVC circuit only consumes the first 32 bytes of the slot (the Merkle
    /// root) anyway. Until the IVC fixture is fixed to drop those 4 bytes (and the slot is
    /// shrunk to 40 bytes), the projection here writes zero in `bytes[32..36]` so the host
    /// preimage matches the IVC fixture layout byte-for-byte.
    ///
    /// Returns an error when the Merkle root does not have the expected 32-byte width.
    // TODO: Refactor the IVC fixture to drop the 4-byte leaf count and remove the zero-padding here.
    pub fn to_rigid_slot_bytes(&self) -> StmResult<[u8; RIGID_SLOT_BYTES]> {
        let root = &self.merkle_tree_commitment.root;
        if root.len() != 32 {
            return Err(MerkleTreeError::SerializationError.into());
        }
        let mut buffer = [0u8; RIGID_SLOT_BYTES];
        buffer[0..32].copy_from_slice(root);
        buffer[36..44].copy_from_slice(&self.total_stake.to_le_bytes());
        Ok(buffer)
    }

    /// Serialize the aggregate verification key for SNARK to CBOR bytes with a version prefix.
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        codec::to_cbor_bytes(self)
    }

    /// Deserialize the aggregate verification key for SNARK from bytes.
    ///
    /// Supports both CBOR-encoded (version-prefixed) and legacy formats.
    /// The legacy format starts with a raw `MerkleTreeCommitment` hash digest,
    /// so the first byte can be `0x01` which collides with the CBOR version
    /// prefix. To handle this ambiguity, this method tries CBOR decoding first
    /// and falls back to the legacy decoder if CBOR fails.
    pub fn from_bytes(bytes: &[u8]) -> StmResult<Self> {
        if codec::has_cbor_v1_prefix(bytes) {
            codec::from_cbor_bytes::<Self>(&bytes[1..]).or_else(|_| Self::from_bytes_legacy(bytes))
        } else {
            Self::from_bytes_legacy(bytes)
        }
    }

    fn from_bytes_legacy(bytes: &[u8]) -> StmResult<Self> {
        if bytes.len() < 8 {
            return Err(MerkleTreeError::SerializationError.into());
        }

        let commitment_end = bytes.len() - 8;
        let merkle_tree_commitment = MerkleTreeCommitment::from_bytes(
            bytes
                .get(..commitment_end)
                .ok_or(MerkleTreeError::SerializationError)?,
        )?;

        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(
            bytes
                .get(commitment_end..commitment_end + 8)
                .ok_or(MerkleTreeError::SerializationError)?,
        );
        let total_stake = u64::from_be_bytes(u64_bytes);

        Ok(Self {
            merkle_tree_commitment,
            total_stake,
        })
    }
}

impl<D: MembershipDigest> PartialEq for AggregateVerificationKeyForSnark<D> {
    fn eq(&self, other: &Self) -> bool {
        self.merkle_tree_commitment.root == other.merkle_tree_commitment.root
            && self.total_stake == other.total_stake
    }
}

impl<D: MembershipDigest> Eq for AggregateVerificationKeyForSnark<D> {}

impl<D: MembershipDigest> From<&ClosedKeyRegistration> for AggregateVerificationKeyForSnark<D> {
    fn from(registration: &ClosedKeyRegistration) -> Self {
        Self {
            merkle_tree_commitment: registration
                .to_merkle_tree::<D::SnarkHash, RegistrationEntryForSnark>()
                .to_merkle_tree_commitment(),
            total_stake: registration.get_total_stake(),
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::{
        Initializer, KeyRegistration, MithrilMembershipDigest, Parameters, RegistrationEntry,
        proof_system::AggregateVerificationKeyForSnark,
        proof_system::halo2_snark::aggregate_key::RIGID_SLOT_BYTES,
        proof_system::halo2_snark::clerk::SnarkClerk,
    };

    type D = MithrilMembershipDigest;

    fn setup_closed_registration(
        number_of_parties: u64,
    ) -> (Parameters, crate::ClosedKeyRegistration) {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let parameters = Parameters {
            m: 10,
            k: 5,
            phi_f: 0.8,
        };

        let mut key_registration = KeyRegistration::initialize();
        for stake in 1..=number_of_parties {
            let initializer = Initializer::new(parameters, stake, &mut rng);
            let entry = RegistrationEntry::new(
                initializer.get_verification_key_proof_of_possession_for_concatenation(),
                initializer.stake,
                #[cfg(feature = "future_snark")]
                initializer.schnorr_verification_key,
            )
            .unwrap();
            key_registration.register_by_entry(&entry).unwrap();
        }

        let closed_registration = key_registration.close_registration(&parameters).unwrap();
        (parameters, closed_registration)
    }

    mod golden {
        use super::*;

        const GOLDEN_BYTES: &[u8; 40] = &[
            44, 84, 216, 246, 141, 120, 242, 182, 103, 85, 253, 105, 87, 28, 199, 233, 121, 66, 21,
            104, 195, 7, 166, 38, 168, 15, 50, 78, 108, 149, 244, 92, 0, 0, 0, 0, 0, 0, 0, 3,
        ];

        fn golden_value() -> AggregateVerificationKeyForSnark<D> {
            let (parameters, closed_registration) = setup_closed_registration(2);
            let clerk = SnarkClerk::new_clerk_from_closed_key_registration(
                &parameters,
                &closed_registration,
            );

            clerk.compute_aggregate_verification_key_for_snark()
        }

        #[test]
        fn golden_conversions() {
            let value = AggregateVerificationKeyForSnark::<D>::from_bytes(GOLDEN_BYTES)
                .expect("This from bytes should not fail");
            assert_eq!(golden_value(), value);

            let serialized = AggregateVerificationKeyForSnark::<D>::to_bytes(&value)
                .expect("AggregateVerificationKeyForSnark serialization should not fail");
            let golden_serialized =
                AggregateVerificationKeyForSnark::<D>::to_bytes(&golden_value())
                    .expect("AggregateVerificationKeyForSnark serialization should not fail");
            assert_eq!(golden_serialized, serialized);
        }

        const GOLDEN_CBOR_BYTES: &[u8; 115] = &[
            1, 162, 118, 109, 101, 114, 107, 108, 101, 95, 116, 114, 101, 101, 95, 99, 111, 109,
            109, 105, 116, 109, 101, 110, 116, 162, 100, 114, 111, 111, 116, 152, 32, 24, 44, 24,
            84, 24, 216, 24, 246, 24, 141, 24, 120, 24, 242, 24, 182, 24, 103, 24, 85, 24, 253, 24,
            105, 24, 87, 24, 28, 24, 199, 24, 233, 24, 121, 24, 66, 21, 24, 104, 24, 195, 7, 24,
            166, 24, 38, 24, 168, 15, 24, 50, 24, 78, 24, 108, 24, 149, 24, 244, 24, 92, 102, 104,
            97, 115, 104, 101, 114, 246, 107, 116, 111, 116, 97, 108, 95, 115, 116, 97, 107, 101,
            3,
        ];

        #[test]
        fn cbor_golden_bytes_can_be_decoded() {
            let decoded = AggregateVerificationKeyForSnark::<D>::from_bytes(GOLDEN_CBOR_BYTES)
                .expect("CBOR golden bytes deserialization should not fail");
            assert_eq!(golden_value(), decoded);
        }

        #[test]
        fn cbor_encoding_is_stable() {
            let bytes = AggregateVerificationKeyForSnark::<D>::to_bytes(&golden_value())
                .expect("AggregateVerificationKeyForSnark serialization should not fail");
            assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), bytes.as_slice());
        }

        const GOLDEN_RIGID_SLOT_BYTES: &[u8; RIGID_SLOT_BYTES] = &[
            44, 84, 216, 246, 141, 120, 242, 182, 103, 85, 253, 105, 87, 28, 199, 233, 121, 66, 21,
            104, 195, 7, 166, 38, 168, 15, 50, 78, 108, 149, 244, 92, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0,
            0, 0,
        ];

        #[test]
        fn rigid_slot_encoding_is_stable() {
            let bytes = golden_value()
                .to_rigid_slot_bytes()
                .expect("AggregateVerificationKeyForSnark rigid-slot encoding should not fail");
            assert_eq!(GOLDEN_RIGID_SLOT_BYTES, &bytes);
        }
    }

    mod bytes_codec_ambiguity {
        use super::*;

        #[test]
        fn legacy_data_starting_with_0x01_falls_back_correctly() {
            let mut legacy_bytes = vec![0x01];
            legacy_bytes.extend_from_slice(&[0xAA; 31]);
            legacy_bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 42]);

            let decoded = AggregateVerificationKeyForSnark::<D>::from_bytes(&legacy_bytes)
                .expect("Legacy data starting with 0x01 should fall back to legacy decoder");
            assert_eq!(decoded.get_total_stake(), 42);
        }
    }

    mod golden_json {
        use super::*;

        const GOLDEN_JSON: &str = r#"
        {
            "merkle_tree_commitment":{
                "root":[44,84,216,246,141,120,242,182,103,85,253,105,87,28,199,233,121,66,21,104,195,7,166,38,168,15,50,78,108,149,244,92],
                "hasher":null
            },
            "total_stake":3
        }
        "#;

        fn golden_value() -> AggregateVerificationKeyForSnark<D> {
            let (parameters, closed_registration) = setup_closed_registration(2);
            let clerk = SnarkClerk::new_clerk_from_closed_key_registration(
                &parameters,
                &closed_registration,
            );

            clerk.compute_aggregate_verification_key_for_snark()
        }

        #[test]
        fn golden_conversions() {
            let value: AggregateVerificationKeyForSnark<D> = serde_json::from_str(GOLDEN_JSON)
                .expect("This JSON deserialization should not fail");

            let serialized =
                serde_json::to_string(&value).expect("This JSON serialization should not fail");
            let golden_serialized = serde_json::to_string(&golden_value())
                .expect("This JSON serialization should not fail");
            assert_eq!(golden_serialized, serialized);
        }
    }
}
