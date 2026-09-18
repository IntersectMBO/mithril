use std::{cmp::Ordering, iter::Sum};

use anyhow::{Context, anyhow};
use blake2::{Blake2b, Blake2b512, Digest};
use blst::{
    blst_p1, blst_p2,
    min_sig::{AggregateSignature, PublicKey as BlstVk, Signature as BlstSig},
    p1_affines, p2_affines,
};
use digest::consts::U16;

use crate::{LotteryIndex, StmResult};

use super::{
    BlsSignatureError, BlsVerificationKey, blst_error_to_stm_error,
    helper::unsafe_helpers::{p1_affine_to_sig, p2_affine_to_vk, sig_to_p1, vk_from_p2_affine},
};

/// MultiSig signature, which is a wrapper over the `BlstSig` type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlsSignature(pub BlstSig);

impl BlsSignature {
    /// Verify a signature against a verification key.
    pub fn verify(&self, msg: &[u8], mvk: &BlsVerificationKey) -> StmResult<()> {
        blst_error_to_stm_error(
            self.0.validate(true).map_or_else(
                |e| e,
                |_| {
                    self.0
                        .verify(false, msg, &[], &[], &mvk.to_blst_verification_key(), false)
                },
            ),
            Some(*self),
            None,
        )
    }

    /// Dense mapping function indexed by the index to be evaluated.
    /// We hash the signature to produce a 64 bytes integer.
    /// The return value of this function refers to
    /// `ev = H("map" || msg || index || σ) <- MSP.Eval(msg,index,σ)` given in paper.
    pub(crate) fn evaluate_dense_mapping(&self, msg: &[u8], index: LotteryIndex) -> [u8; 64] {
        let hasher = Blake2b512::new()
            .chain_update(b"map")
            .chain_update(msg)
            .chain_update(index.to_le_bytes())
            .chain_update(self.to_raw_bytes())
            .finalize();

        let mut output = [0u8; 64];
        output.copy_from_slice(&hasher);

        output
    }

    /// Convert a `Signature` to its raw compressed byte representation.
    ///
    /// This exact byte layout is depended on by `SingleSignature`'s legacy decoder — it must
    /// not change.
    pub fn to_raw_bytes(self) -> [u8; 48] {
        self.0.to_bytes()
    }

    /// Convert a string of bytes into a `MspSig`.
    ///
    /// # Error
    /// Returns an error if the byte string does not represent a point in the curve.
    pub fn from_raw_bytes(bytes: &[u8]) -> StmResult<Self> {
        let bytes = bytes.get(..48).ok_or(BlsSignatureError::SerializationError)?;
        match BlstSig::sig_validate(bytes, true) {
            Ok(sig) => Ok(Self(sig)),
            Err(e) => Err(blst_error_to_stm_error(e, None, None)
                .expect_err("If deserialization is not successful, blst returns and error different to SUCCESS."))
        }
    }

    /// Compare two signatures. Used for PartialOrd impl, used to rank signatures. The comparison
    /// function can be anything, as long as it is consistent across different nodes.
    fn compare_signatures(&self, other: &Self) -> Ordering {
        let self_bytes = self.to_raw_bytes();
        let other_bytes = other.to_raw_bytes();
        let mut result = Ordering::Equal;

        for (i, j) in self_bytes.iter().zip(other_bytes.iter()) {
            result = i.cmp(j);
            if result != Ordering::Equal {
                return result;
            }
        }
        result
    }

    /// Aggregate a slice of verification keys and Signatures by first hashing the
    /// signatures into random scalars, and multiplying the signature and verification
    /// key with the resulting value. This follows the steps defined in Figure 6,
    /// `Aggregate` step.
    pub fn aggregate(
        vks: &[BlsVerificationKey],
        sigs: &[BlsSignature],
    ) -> StmResult<(BlsVerificationKey, BlsSignature)> {
        if vks.len() != sigs.len() || vks.is_empty() {
            return Err(anyhow!(BlsSignatureError::AggregateSignatureInvalid));
        }

        if vks.len() < 2 {
            return Ok((vks[0], sigs[0]));
        }

        let mut hashed_sigs = Blake2b::<U16>::new();
        for sig in sigs {
            hashed_sigs.update(sig.to_raw_bytes());
        }

        // First we generate the scalars
        let mut scalars = Vec::with_capacity(vks.len() * 128);
        let mut signatures = Vec::with_capacity(vks.len());
        for (index, sig) in sigs.iter().enumerate() {
            let mut hasher = hashed_sigs.clone();
            hasher.update(index.to_be_bytes());
            signatures.push(sig.0);
            scalars.extend_from_slice(&hasher.finalize());
        }

        let transmuted_vks: Vec<blst_p2> = vks.iter().map(vk_from_p2_affine).collect();
        let transmuted_sigs: Vec<blst_p1> = signatures.iter().map(sig_to_p1).collect();

        let grouped_vks = p2_affines::from(transmuted_vks.as_slice());
        let grouped_sigs = p1_affines::from(transmuted_sigs.as_slice());

        let aggr_vk: BlstVk = p2_affine_to_vk(&grouped_vks.mult(&scalars, 128));
        let aggr_sig: BlstSig = p1_affine_to_sig(&grouped_sigs.mult(&scalars, 128));

        Ok((BlsVerificationKey(aggr_vk), BlsSignature(aggr_sig)))
    }

    /// Verify a set of signatures with their corresponding verification keys using the
    /// aggregation mechanism of Figure 6.
    pub fn verify_aggregate(
        msg: &[u8],
        vks: &[BlsVerificationKey],
        sigs: &[BlsSignature],
    ) -> StmResult<()> {
        let (aggr_vk, aggr_sig) = Self::aggregate(vks, sigs).with_context(|| "Multi signature verification failed in aggregation of verification keys and signatures.")?;

        blst_error_to_stm_error(
            aggr_sig.0.verify(
                false,
                msg,
                &[],
                &[],
                &aggr_vk.to_blst_verification_key(),
                false,
            ),
            Some(aggr_sig),
            None,
        )
    }

    /// Batch verify several sets of signatures with their corresponding verification keys.
    pub fn batch_verify_aggregates(
        msgs: &[Vec<u8>],
        vks: &[BlsVerificationKey],
        sigs: &[BlsSignature],
    ) -> StmResult<()> {
        let batched_sig: BlstSig = match AggregateSignature::aggregate(
            &(sigs.iter().map(|sig| &sig.0).collect::<Vec<&BlstSig>>()),
            false,
        ) {
            Ok(sig) => BlstSig::from_aggregate(&sig),
            Err(e) => return blst_error_to_stm_error(e, None, None),
        };

        let p2_vks: Vec<BlstVk> = vks.iter().map(|vk| vk.to_blst_verification_key()).collect();
        let p2_vks_ref: Vec<&BlstVk> = p2_vks.iter().collect();
        let slice_msgs = msgs.iter().map(|msg| msg.as_slice()).collect::<Vec<&[u8]>>();

        blst_error_to_stm_error(
            batched_sig.aggregate_verify(false, &slice_msgs, &[], &p2_vks_ref, false),
            None,
            None,
        )
        .map_err(|_| anyhow!(BlsSignatureError::BatchInvalid))
    }
}

impl<'a> Sum<&'a Self> for BlsSignature {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        let signatures: Vec<&BlstSig> = iter.map(|x| &x.0).collect();
        assert!(!signatures.is_empty(), "One cannot add an empty vector");
        let aggregate = AggregateSignature::aggregate(&signatures, false)
            .expect("An MspSig is always a valid signature. This function only fails if signatures is empty or if the signatures are invalid, none of which can happen.")
            .to_signature();

        Self(aggregate)
    }
}

impl PartialOrd for BlsSignature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

impl Ord for BlsSignature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare_signatures(other)
    }
}

#[cfg(test)]
mod tests {
    mod golden {

        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        use crate::signature_scheme::{BlsSignature, BlsSigningKey};

        const GOLDEN_JSON: &str = r#"[132,95,124,197,185,105,193,171,114,182,52,171,205,119,202,188,2,213,61,125,219,242,10,131,53,219,53,197,157,42,152,194,234,161,244,204,2,134,47,179,176,49,200,232,120,241,180,246]"#;

        fn golden_value() -> BlsSignature {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let sk = BlsSigningKey::generate(&mut rng);
            let msg = [0u8; 32];
            sk.sign(&msg)
        }

        #[test]
        fn golden_conversions() {
            let value = serde_json::from_str(GOLDEN_JSON)
                .expect("This JSON deserialization should not fail");
            assert_eq!(golden_value(), value);

            let serialized =
                serde_json::to_string(&value).expect("This JSON serialization should not fail");
            let golden_serialized = serde_json::to_string(&golden_value())
                .expect("This JSON serialization should not fail");
            assert_eq!(golden_serialized, serialized);
        }
    }
}
