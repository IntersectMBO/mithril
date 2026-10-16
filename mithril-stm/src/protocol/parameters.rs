use serde::{Deserialize, Serialize};

use crate::codec;
use crate::{PhiFValue, StmResult};

use super::{ProtocolError, RegisterError};

/// Byte width of the rigid-slot encoding produced by [Parameters::to_rigid_bytes]. Matches the
/// rigid protocol message slot for the next protocol parameters.
#[cfg(feature = "snark")]
pub const RIGID_PROTOCOL_PARAMETERS_BYTES: usize = 32;

/// Used to set protocol parameters.
// todo: this is the criteria to consider parameters valid:
// Let A = max assumed adversarial stake
// Let a = A / max_stake
// Let p = φ(a)  // f needs tuning, something close to 0.2 is reasonable
// Then, we're secure if SUM[from i=k to i=m] Binomial(i successes, m experiments, p chance of success) <= 2^-100 or thereabouts.
// The latter turns to 1 - BinomialCDF(k-1,m,p)
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Parameters {
    /// Security parameter, upper bound on indices.
    pub m: u64,
    /// Quorum parameter.
    pub k: u64,
    /// `f` in phi(w) = 1 - (1 - f)^w, where w is the stake of a participant..
    pub phi_f: PhiFValue,
}

impl Parameters {
    /// Checks that the parameters are usable by the proof systems.
    pub fn validate(&self) -> StmResult<()> {
        if !(self.phi_f > 0.0 && self.phi_f <= 1.0) {
            return Err(ProtocolError::PhiFValueOutOfRange(self.phi_f).into());
        }
        if self.k == 0 {
            return Err(ProtocolError::QuorumParameterIsZero.into());
        }
        if self.k > self.m {
            return Err(ProtocolError::QuorumParameterGreaterThanSecurityParameter {
                k: self.k,
                m: self.m,
            }
            .into());
        }

        Ok(())
    }

    /// Convert to CBOR bytes with a version prefix.
    ///
    /// Legacy readers that encounter the version prefix byte will fail
    /// gracefully, while new readers will decode the CBOR payload.
    pub fn to_bytes(&self) -> StmResult<Vec<u8>> {
        codec::to_cbor_bytes(self)
    }

    /// Encode to the `RIGID_PROTOCOL_PARAMETERS_BYTES`-byte rigid-slot layout consumed by the
    /// protocol message `next_protocol_parameters` rigid slot:
    ///
    /// `m_LE_u64 (8) || k_LE_u64 (8) || phi_f_LE_f64 (8) || zero_padding (8)`.
    ///
    /// Trailing zero padding rounds the slot out to 32 bytes so the IVC SNARK gadget can consume
    /// the parameters as a fixed-size word.
    #[cfg(feature = "snark")]
    pub fn to_rigid_bytes(&self) -> [u8; RIGID_PROTOCOL_PARAMETERS_BYTES] {
        let mut buffer = [0u8; RIGID_PROTOCOL_PARAMETERS_BYTES];
        buffer[0..8].copy_from_slice(&self.m.to_le_bytes());
        buffer[8..16].copy_from_slice(&self.k.to_le_bytes());
        buffer[16..24].copy_from_slice(&self.phi_f.to_le_bytes());
        buffer
    }

    /// Extract the `Parameters` from a byte slice.
    ///
    /// Supports both the legacy big-endian byte format and the new
    /// versioned CBOR format.
    ///
    /// # Error
    /// The function fails if the given string of bytes is not of required size.
    pub fn from_bytes(bytes: &[u8]) -> StmResult<Self> {
        codec::from_versioned_bytes(bytes, Self::from_bytes_legacy)
    }

    fn from_bytes_legacy(bytes: &[u8]) -> StmResult<Self> {
        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(bytes.get(..8).ok_or(RegisterError::SerializationError)?);
        let m = u64::from_be_bytes(u64_bytes);
        u64_bytes.copy_from_slice(bytes.get(8..16).ok_or(RegisterError::SerializationError)?);
        let k = u64::from_be_bytes(u64_bytes);
        u64_bytes.copy_from_slice(bytes.get(16..24).ok_or(RegisterError::SerializationError)?);
        let phi_f = f64::from_be_bytes(u64_bytes);

        Ok(Self { m, k, phi_f })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod validate {
        use super::*;

        #[test]
        fn accepts_valid_parameters() {
            Parameters {
                m: 10,
                k: 10,
                phi_f: 1.0,
            }
            .validate()
            .expect("k equal to m and phi_f equal to 1 should be valid");
        }

        #[test]
        fn rejects_invalid_parameters() {
            for parameters in [
                Parameters {
                    m: 20,
                    k: 10,
                    phi_f: 0.0,
                },
                Parameters {
                    m: 20,
                    k: 0,
                    phi_f: 0.2,
                },
                Parameters {
                    m: 20,
                    k: 21,
                    phi_f: 0.2,
                },
            ] {
                assert!(
                    parameters.validate().is_err(),
                    "{parameters:?} should be invalid"
                );
            }
        }
    }

    mod golden {
        use super::*;

        const GOLDEN_JSON: &str = r#"
            {
                "m": 20973,
                "k": 2422,
                "phi_f": 0.2
            }
        "#;

        fn golden_value() -> Parameters {
            Parameters {
                m: 20973,
                k: 2422,
                phi_f: 0.2,
            }
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

    mod cbor {
        use super::*;

        const LEGACY_BYTES: &[u8; 24] = &[
            0, 0, 0, 0, 0, 0, 81, 237, 0, 0, 0, 0, 0, 0, 9, 118, 63, 201, 153, 153, 153, 153, 153,
            154,
        ];

        fn test_value() -> Parameters {
            Parameters {
                m: 20973,
                k: 2422,
                phi_f: 0.2,
            }
        }

        #[test]
        fn cbor_roundtrip() {
            let value = test_value();
            let bytes = value.to_bytes().expect("CBOR serialization should not fail");
            let decoded =
                Parameters::from_bytes(&bytes).expect("CBOR deserialization should not fail");
            assert_eq!(value, decoded);
        }

        #[test]
        fn legacy_bytes_can_still_be_decoded() {
            let decoded = Parameters::from_bytes(LEGACY_BYTES)
                .expect("Legacy deserialization should not fail");
            assert_eq!(test_value(), decoded);
        }

        const GOLDEN_CBOR_BYTES: &[u8; 27] = &[
            1, 163, 97, 109, 25, 81, 237, 97, 107, 25, 9, 118, 101, 112, 104, 105, 95, 102, 251,
            63, 201, 153, 153, 153, 153, 153, 154,
        ];

        #[test]
        fn cbor_golden_bytes_can_be_decoded() {
            let decoded = Parameters::from_bytes(GOLDEN_CBOR_BYTES)
                .expect("CBOR golden bytes deserialization should not fail");
            assert_eq!(test_value(), decoded);
        }

        #[test]
        fn cbor_encoding_is_stable() {
            let bytes = test_value().to_bytes().expect("CBOR serialization should not fail");
            assert_eq!(GOLDEN_CBOR_BYTES.as_slice(), bytes.as_slice());
        }
    }

    #[cfg(feature = "snark")]
    mod rigid_slot {
        use super::*;

        const GOLDEN_RIGID_BYTES: &[u8; RIGID_PROTOCOL_PARAMETERS_BYTES] = &[
            237, 81, 0, 0, 0, 0, 0, 0, 118, 9, 0, 0, 0, 0, 0, 0, 154, 153, 153, 153, 153, 153, 201,
            63, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        fn test_value() -> Parameters {
            Parameters {
                m: 20973,
                k: 2422,
                phi_f: 0.2,
            }
        }

        #[test]
        fn rigid_slot_encoding_is_stable() {
            assert_eq!(GOLDEN_RIGID_BYTES, &test_value().to_rigid_bytes());
        }

        #[test]
        fn rigid_slot_encoding_distinguishes_each_field() {
            let baseline = test_value().to_rigid_bytes();

            let mut perturbed = test_value();
            perturbed.m += 1;
            assert_ne!(baseline, perturbed.to_rigid_bytes());

            let mut perturbed = test_value();
            perturbed.k += 1;
            assert_ne!(baseline, perturbed.to_rigid_bytes());

            let mut perturbed = test_value();
            perturbed.phi_f += f64::EPSILON;
            assert_ne!(baseline, perturbed.to_rigid_bytes());
        }
    }
}
