use crate::{
    crypto_helper::ProtocolPartyIdHash,
    entities::{Epoch, Stake},
};

/// Structure representing the information needed to create a prefix
/// for the Proof of Bound Possession (PoBP).
/// It is used to compute the hash value signed for the PoBP :
/// H(DST || prefix || vk)
pub(crate) struct ProofOfBoundPossessionPrefix {
    stake: Stake,
    epoch: Epoch,
    pool_id: ProtocolPartyIdHash,
}

impl ProofOfBoundPossessionPrefix {
    pub(crate) fn new(stake: Stake, epoch: Epoch, pool_id: ProtocolPartyIdHash) -> Self {
        Self {
            stake,
            epoch,
            pool_id,
        }
    }

    /// Converts a Proof of Bound Possession challenge into prefix bytes
    /// in the form:
    /// stake || epoch || pool_id
    pub(crate) fn to_prefix_bytes(&self) -> [u8; 44] {
        let mut prefix_bytes = [0u8; 44];
        prefix_bytes[0..8].copy_from_slice(&self.stake.to_be_bytes());
        prefix_bytes[8..16].copy_from_slice(&self.epoch.to_be_bytes());
        prefix_bytes[16..44].copy_from_slice(&self.pool_id);
        prefix_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_prefix_bytes_produces_expected_layout() {
        let prefix = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), [1u8; 28]);

        let bytes = prefix.to_prefix_bytes();

        let mut expected = Vec::new();
        expected.extend_from_slice(&100u64.to_be_bytes());
        expected.extend_from_slice(&5u64.to_be_bytes());
        expected.extend_from_slice(&[1u8; 28]);

        assert_eq!(expected, bytes);
    }

    #[test]
    fn to_prefix_bytes_handles_all_zero_pool_id() {
        let prefix = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), [0u8; 28]);

        let bytes = prefix.to_prefix_bytes();

        let mut expected = Vec::new();
        expected.extend_from_slice(&100u64.to_be_bytes());
        expected.extend_from_slice(&5u64.to_be_bytes());
        expected.extend_from_slice(&[0u8; 28]);

        assert_eq!(expected, bytes);
    }

    #[test]
    fn different_stakes_produce_different_bytes() {
        let a = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), [1u8; 28]);
        let b = ProofOfBoundPossessionPrefix::new(200u64, Epoch(5), [1u8; 28]);

        assert_ne!(a.to_prefix_bytes(), b.to_prefix_bytes());
    }

    #[test]
    fn different_epochs_produce_different_bytes() {
        let a = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), [1u8; 28]);
        let b = ProofOfBoundPossessionPrefix::new(100u64, Epoch(6), [1u8; 28]);

        assert_ne!(a.to_prefix_bytes(), b.to_prefix_bytes());
    }

    #[test]
    fn different_pool_ids_produce_different_bytes() {
        let a = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), [1u8; 28]);
        let b = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), [2u8; 28]);

        assert_ne!(a.to_prefix_bytes(), b.to_prefix_bytes());
    }
}
