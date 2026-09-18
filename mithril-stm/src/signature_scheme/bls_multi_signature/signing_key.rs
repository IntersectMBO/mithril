use blst::min_sig::SecretKey as BlstSk;
use rand_core::{CryptoRng, RngCore};

use crate::StmResult;

use super::{BlsSignature, BlsSignatureError, blst_error_to_stm_error};

/// MultiSig secret key, which is a wrapper over the BlstSk type from the blst
/// library.
#[derive(Debug, Clone)]
pub struct BlsSigningKey(pub BlstSk);

impl BlsSigningKey {
    /// Generate a secret key
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);
        BlsSigningKey(
            BlstSk::key_gen(&ikm, &[])
                .expect("Error occurs when the length of ikm < 32. This will not happen here."),
        )
    }

    /// Sign a message with the given secret key
    pub fn sign(&self, msg: &[u8]) -> BlsSignature {
        BlsSignature(self.0.sign(msg, &[], &[]))
    }

    /// Convert the secret key into its raw byte representation.
    ///
    /// This exact byte layout is depended on by `Initializer`'s legacy decoder — it must
    /// not change.
    pub fn to_raw_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Convert a string of bytes into a `SigningKey`.
    ///
    /// # Error
    /// Fails if the byte string represents a scalar larger than the group order.
    pub fn from_raw_bytes(bytes: &[u8]) -> StmResult<Self> {
        let bytes = bytes.get(..32).ok_or(BlsSignatureError::SerializationError)?;
        match BlstSk::from_bytes(bytes) {
            Ok(sk) => Ok(Self(sk)),
            Err(e) => Err(blst_error_to_stm_error(e, None, None)
                .expect_err("If deserialization is not successful, blst returns and error different to SUCCESS."))
        }
    }

    pub(crate) fn to_blst_secret_key(&self) -> BlstSk {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod golden {

        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        use super::*;

        const GOLDEN_JSON: &str = r#"[64, 129, 87, 121, 27, 239, 221, 215, 2, 103, 45, 207, 207, 201, 157, 163, 81, 47, 156, 14, 168, 24, 137, 15, 203, 106, 183, 73, 88, 14, 242, 207]"#;

        fn golden_value() -> BlsSigningKey {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            BlsSigningKey::generate(&mut rng)
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
