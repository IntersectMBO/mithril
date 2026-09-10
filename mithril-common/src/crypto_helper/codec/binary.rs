use anyhow::Context;
use hex::{FromHex, ToHex};

use crate::StdResult;

/// Traits for serializing to bytes
pub trait TryToBytes {
    /// Try to convert to a bytes vector.
    fn to_bytes_vec(&self) -> StdResult<Vec<u8>>;

    /// Try to convert to hex bytes representation
    fn to_bytes_hex(&self) -> StdResult<String> {
        Ok(self.to_bytes_vec()?.encode_hex::<String>())
    }
}

/// Traits for deserializing from bytes
pub trait TryFromBytes: Sized {
    /// Try to convert from a bytes slice.
    fn try_from_bytes(bytes: &[u8]) -> StdResult<Self>;

    /// Try to convert from hex string encoded bytes.
    fn try_from_bytes_hex(hex_string: &str) -> StdResult<Self> {
        let bytes = Vec::from_hex(hex_string)
            .with_context(|| "Could not deserialize binary from hex string")?;

        Self::try_from_bytes(&bytes)
    }
}

mod binary_mithril_stm {

    use mithril_stm::{
        AggregateSignature, AggregateVerificationKeyForConcatenation, AncillaryProverData,
        AncillaryVerifierData, Initializer, MithrilMembershipDigest, Parameters, SingleSignature,
        SingleSignatureWithRegisteredParty, VerificationKeyForConcatenation,
        VerificationKeyProofOfPossessionForConcatenation,
    };
    #[cfg(feature = "future_snark")]
    use mithril_stm::{
        AggregateVerificationKeyForSnark, StandardSchnorrSignature, VerificationKeyForSnark,
    };

    use super::*;

    type D = MithrilMembershipDigest;

    impl TryToBytes for Parameters {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            self.to_bytes()
        }
    }

    impl TryFromBytes for Parameters {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes(bytes)
        }
    }

    impl TryToBytes for SingleSignature {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            self.to_bytes()
        }
    }

    impl TryFromBytes for SingleSignature {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes::<D>(bytes)
        }
    }

    impl TryToBytes for SingleSignatureWithRegisteredParty {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            self.to_bytes()
        }
    }

    impl TryFromBytes for SingleSignatureWithRegisteredParty {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes::<D>(bytes)
        }
    }

    impl TryToBytes for AggregateSignature<D> {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            self.to_bytes()
        }
    }

    impl TryFromBytes for AggregateSignature<D> {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes(bytes)
                .with_context(|| "Could not deserialize aggregate signature from bytes")
        }
    }

    impl TryToBytes for VerificationKeyForConcatenation {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            Ok(self.to_bytes().to_vec())
        }
    }

    impl TryFromBytes for VerificationKeyForConcatenation {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes(bytes)
        }
    }

    impl TryToBytes for VerificationKeyProofOfPossessionForConcatenation {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            Ok(self.to_bytes().to_vec())
        }
    }

    impl TryFromBytes for VerificationKeyProofOfPossessionForConcatenation {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes(bytes)
        }
    }

    #[cfg(feature = "future_snark")]
    impl TryToBytes for VerificationKeyForSnark {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            Ok(self.to_bytes().to_vec())
        }
    }

    #[cfg(feature = "future_snark")]
    impl TryFromBytes for VerificationKeyForSnark {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes(bytes)
        }
    }

    impl TryToBytes for AggregateVerificationKeyForConcatenation<D> {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            self.to_bytes()
        }
    }

    impl TryFromBytes for AggregateVerificationKeyForConcatenation<D> {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes(bytes)
        }
    }

    #[cfg(feature = "future_snark")]
    impl TryToBytes for AggregateVerificationKeyForSnark<D> {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            self.to_bytes()
        }
    }

    #[cfg(feature = "future_snark")]
    impl TryFromBytes for AggregateVerificationKeyForSnark<D> {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes(bytes)
        }
    }

    #[cfg(feature = "future_snark")]
    impl TryToBytes for StandardSchnorrSignature {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            Ok(self.to_bytes().to_vec())
        }
    }

    #[cfg(feature = "future_snark")]
    impl TryFromBytes for StandardSchnorrSignature {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes(bytes)
        }
    }

    impl TryToBytes for Initializer {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            self.to_bytes()
        }
    }

    impl TryFromBytes for Initializer {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes(bytes)
        }
    }

    impl TryToBytes for AncillaryProverData {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            self.to_bytes()
        }
    }

    impl TryFromBytes for AncillaryProverData {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes(bytes)
        }
    }

    impl TryToBytes for AncillaryVerifierData {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            self.to_bytes()
        }
    }

    impl TryFromBytes for AncillaryVerifierData {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes(bytes)
        }
    }
}

mod binary_ed25519 {
    use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

    use super::*;

    impl TryToBytes for Signature {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            Ok(self.to_bytes().to_vec())
        }
    }

    impl TryFromBytes for Signature {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::try_from(bytes).map_err(|e| e.into())
        }
    }

    impl TryToBytes for SigningKey {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            Ok(self.to_bytes().to_vec())
        }
    }

    impl TryFromBytes for SigningKey {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::try_from(bytes).map_err(|e| e.into())
        }
    }

    impl TryToBytes for VerifyingKey {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            Ok(self.to_bytes().to_vec())
        }
    }

    impl TryFromBytes for VerifyingKey {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::try_from(bytes).map_err(|e| e.into())
        }
    }
}

mod binary_kes_sig {
    use anyhow::anyhow;
    use kes_summed_ed25519::kes::Sum6KesSig;

    use super::*;

    impl TryToBytes for Sum6KesSig {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            Ok(self.to_bytes().to_vec())
        }
    }

    impl TryFromBytes for Sum6KesSig {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes(bytes).map_err(|e| {
                anyhow!("{e:?}").context("Could not deserialize KES signature from bytes")
            })
        }
    }
}

mod binary_opcert {
    use crate::crypto_helper::{OpCert, OpCertWithoutColdVerificationKey, SerDeShelleyFileFormat};

    use super::*;

    impl TryToBytes for OpCert {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            self.to_cbor_bytes()
                .with_context(|| "Could not serialize OpCert to bytes")
        }
    }

    impl TryFromBytes for OpCert {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_cbor_bytes(bytes).with_context(|| "Could not deserialize OpCert from bytes")
        }
    }

    impl TryToBytes for OpCertWithoutColdVerificationKey {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            self.to_cbor_bytes()
                .with_context(|| "Could not serialize OpCertWithoutColdVerificationKey to bytes")
        }
    }

    impl TryFromBytes for OpCertWithoutColdVerificationKey {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_cbor_bytes(bytes).with_context(
                || "Could not deserialize OpCertWithoutColdVerificationKey from bytes",
            )
        }
    }
}

mod binary_mk_proof {
    use serde::{Deserialize, Serialize};

    use crate::crypto_helper::{MKMapKey, MKMapProof, MKProof};

    use super::*;

    impl<T: MKMapKey + Serialize + for<'de> Deserialize<'de>> TryToBytes for MKMapProof<T> {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            self.to_bytes()
        }
    }

    impl<T: MKMapKey + Serialize + for<'de> Deserialize<'de>> TryFromBytes for MKMapProof<T> {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes(bytes)
        }
    }

    impl TryToBytes for MKProof {
        fn to_bytes_vec(&self) -> StdResult<Vec<u8>> {
            self.to_bytes()
        }
    }

    impl TryFromBytes for MKProof {
        fn try_from_bytes(bytes: &[u8]) -> StdResult<Self> {
            Self::from_bytes(bytes)
        }
    }
}
