use anyhow::Context;

use crate::{
    StdResult,
    crypto_helper::ProtocolPartyId,
    entities::{Epoch, Stake},
};

/// Structure representing the information needed to create a prefix
/// for the proof of bound possession.
/// It is used to compute the hash value signed for the Proof of Bound Possession :
/// H(DST || prefix || vk)
pub(crate) struct ProofOfBoundPossessionPrefix {
    stake: Stake,
    epoch: Epoch,
    pool_id: ProtocolPartyId,
}

impl ProofOfBoundPossessionPrefix {
    pub(crate) fn new(stake: Stake, epoch: Epoch, pool_id: ProtocolPartyId) -> Self {
        Self {
            stake,
            epoch,
            pool_id,
        }
    }

    /// Converts a proof of bound possession challenge into prefix bytes
    /// in the form:
    /// stake || epoch || len(pool_id) || pool_id
    ///
    /// Can fail if the pool id string can't fit in a u64
    pub(crate) fn to_prefix_bytes(&self) -> StdResult<Vec<u8>> {
        let mut prefix_bytes = Vec::new();
        prefix_bytes.extend_from_slice(&self.stake.to_be_bytes());
        prefix_bytes.extend_from_slice(&self.epoch.to_be_bytes());
        prefix_bytes.extend_from_slice(
            &u64::try_from(self.pool_id.as_bytes().len())
                .context("Pool ID length should fit in u64")?
                .to_be_bytes(),
        );
        prefix_bytes.extend_from_slice(&self.pool_id.as_bytes());
        Ok(prefix_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_prefix_bytes_produces_expected_layout() {
        let prefix = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), "pool1abc".to_string());

        let bytes = prefix.to_prefix_bytes().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&100u64.to_be_bytes());
        expected.extend_from_slice(&5u64.to_be_bytes());
        expected.extend_from_slice(&8u64.to_be_bytes()); // len("pool1abc")
        expected.extend_from_slice(b"pool1abc");

        assert_eq!(bytes, expected);
    }

    #[test]
    fn to_prefix_bytes_handles_empty_pool_id() {
        let prefix = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), String::new());

        let bytes = prefix.to_prefix_bytes().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&100u64.to_be_bytes());
        expected.extend_from_slice(&5u64.to_be_bytes());
        expected.extend_from_slice(&0u64.to_be_bytes());

        assert_eq!(bytes, expected);
    }

    #[test]
    fn different_stakes_produce_different_bytes() {
        let a = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), "pool1abc".to_string());
        let b = ProofOfBoundPossessionPrefix::new(200u64, Epoch(5), "pool1abc".to_string());

        assert_ne!(a.to_prefix_bytes().unwrap(), b.to_prefix_bytes().unwrap());
    }

    #[test]
    fn different_epochs_produce_different_bytes() {
        let a = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), "pool1abc".to_string());
        let b = ProofOfBoundPossessionPrefix::new(100u64, Epoch(6), "pool1abc".to_string());

        assert_ne!(a.to_prefix_bytes().unwrap(), b.to_prefix_bytes().unwrap());
    }

    #[test]
    fn different_pool_ids_produce_different_bytes() {
        let a = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), "pool1abc".to_string());
        let b = ProofOfBoundPossessionPrefix::new(100u64, Epoch(5), "pool1xyz".to_string());

        assert_ne!(a.to_prefix_bytes().unwrap(), b.to_prefix_bytes().unwrap());
    }
}
