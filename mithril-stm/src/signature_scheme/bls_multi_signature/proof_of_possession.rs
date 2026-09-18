use blst::{blst_p1, min_sig::Signature as BlstSig};

use crate::StmResult;

use super::{
    BlsSignatureError, BlsSigningKey, POP, blst_error_to_stm_error,
    helper::unsafe_helpers::{compress_p1, scalar_to_pk_in_g1, uncompress_p1},
};

/// MultiSig proof of possession, which contains two elements from G1. However,
/// the two elements have different types: `k1` is represented as a BlstSig
/// as it has the same structure, and this facilitates its verification. On
/// the other hand, `k2` is a G1 point, as it does not share structure with
/// the BLS signature, and we need to have an ad-hoc verification mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlsProofOfPossession {
    k1: BlstSig,
    k2: blst_p1,
}

impl BlsProofOfPossession {
    /// Convert to its 96 byte raw representation.
    ///
    /// # Layout
    /// The layout of a `MspPoP` encoding is
    /// * K1 (G1 point)
    /// * K2 (G1 point)
    ///
    /// This exact byte layout is depended on by `BlsVerificationKeyProofOfPossession`'s raw
    /// concatenation — it must not change.
    pub fn to_raw_bytes(self) -> [u8; 96] {
        let mut pop_bytes = [0u8; 96];
        pop_bytes[..48].copy_from_slice(&self.k1.to_bytes());

        pop_bytes[48..].copy_from_slice(&compress_p1(&self.k2)[..]);
        pop_bytes
    }

    /// Deserialize a byte string to a `PublicKeyPoP`.
    pub fn from_raw_bytes(bytes: &[u8]) -> StmResult<Self> {
        let k1 = match BlstSig::from_bytes(
            bytes.get(..48).ok_or(BlsSignatureError::SerializationError)?,
        ) {
            Ok(key) => key,
            Err(e) => {
                return Err(blst_error_to_stm_error(e, None, None)
                    .expect_err("If it passed, blst returns and error different to SUCCESS."));
            }
        };

        let k2 = uncompress_p1(bytes.get(48..96).ok_or(BlsSignatureError::SerializationError)?)?;

        Ok(Self { k1, k2 })
    }

    pub(crate) fn get_k1(self) -> BlstSig {
        self.k1
    }

    pub(crate) fn get_k2(self) -> blst_p1 {
        self.k2
    }
}

impl From<&BlsSigningKey> for BlsProofOfPossession {
    /// Convert a secret key into an `MspPoP`. This is performed by computing
    /// `k1 =  H_G1(b"PoP" || mvk)` and `k2 = g1 * sk` where `H_G1` hashes into
    /// `G1` and `g1` is the generator in `G1`.
    fn from(sk: &BlsSigningKey) -> Self {
        let k1 = sk.to_blst_secret_key().sign(POP, &[], &[]);
        let k2 = scalar_to_pk_in_g1(&sk.to_blst_secret_key());
        Self { k1, k2 }
    }
}

#[cfg(test)]
mod tests {
    mod golden {

        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        use crate::signature_scheme::{BlsProofOfPossession, BlsSigningKey};

        const GOLDEN_JSON: &str = r#"[168,50,233,193,15,136,65,72,123,148,129,176,38,198,209,47,28,204,176,144,57,251,42,28,66,76,89,97,158,63,54,198,194,176,135,221,14,185,197,225,202,98,243,74,233,225,143,151,147,177,170,117,66,165,66,62,33,216,232,75,68,114,195,22,100,65,44,198,4,166,102,233,253,240,59,175,60,117,142,114,140,122,17,87,110,187,1,17,10,195,154,13,249,86,54,226]"#;

        fn golden_value() -> BlsProofOfPossession {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let sk = BlsSigningKey::generate(&mut rng);
            BlsProofOfPossession::from(&sk)
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
