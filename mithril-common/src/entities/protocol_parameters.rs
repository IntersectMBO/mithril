use fixed::types::U8F24;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// [ProtocolParameters] verification related errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolParametersError {
    /// Error raised when k is invalid (k must be greater than 0).
    #[error("k must be greater than 0")]
    InvalidK,

    /// Error raised when m is invalid (m must be greater than 0).
    #[error("m must be greater than 0")]
    InvalidM,

    /// Error raised when k is greater than m
    #[error("k must be less than or equal to m")]
    KGreaterThanM,

    /// Error raised when phi_f is out of range (phi_f must be in the range (0, 1]).
    #[error("phi_f must be in the range (0, 1]")]
    PhiFOutOfRange,
}

/// Protocol cryptographic parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolParameters {
    /// Quorum parameter
    pub k: u64,

    /// Security parameter (number of lotteries)
    pub m: u64,

    /// f in phi(w) = 1 - (1 - f)^w, where w is the stake of a participant
    pub phi_f: f64,
}

impl ProtocolParameters {
    /// ProtocolParameters factory
    pub fn new(k: u64, m: u64, phi_f: f64) -> ProtocolParameters {
        ProtocolParameters { k, m, phi_f }
    }

    /// phi_f_fixed is a fixed decimal representation of phi_f
    /// used for PartialEq and Hash implementation
    pub fn phi_f_fixed(&self) -> U8F24 {
        U8F24::from_num(self.phi_f)
    }

    /// Computes the hash of ProtocolParameters
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.k.to_be_bytes());
        hasher.update(self.m.to_be_bytes());
        hasher.update(self.phi_f_fixed().to_be_bytes());
        hex::encode(hasher.finalize())
    }

    /// Checks if the ProtocolParameters are valid
    pub fn check_parameters(&self) -> Result<(), ProtocolParametersError> {
        if self.k == 0 {
            return Err(ProtocolParametersError::InvalidK);
        }
        if self.m == 0 {
            return Err(ProtocolParametersError::InvalidM);
        }
        if self.k > self.m {
            return Err(ProtocolParametersError::KGreaterThanM);
        }
        if self.phi_f <= 0.0 || self.phi_f > 1.0 {
            return Err(ProtocolParametersError::PhiFOutOfRange);
        }

        Ok(())
    }
}

impl PartialEq<ProtocolParameters> for ProtocolParameters {
    fn eq(&self, other: &ProtocolParameters) -> bool {
        self.k == other.k && self.m == other.m && self.phi_f_fixed() == other.phi_f_fixed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_parameters_partialeq() {
        assert_eq!(
            ProtocolParameters::new(1000, 100, 0.123001),
            ProtocolParameters::new(1000, 100, 0.123001)
        );
        assert_ne!(
            ProtocolParameters::new(1000, 100, 0.1230011),
            ProtocolParameters::new(1000, 100, 0.1230012)
        );
        assert_ne!(
            ProtocolParameters::new(1000, 100, 0.12301),
            ProtocolParameters::new(1000, 100, 0.12300)
        );
        assert_ne!(
            ProtocolParameters::new(1001, 100, 0.12300),
            ProtocolParameters::new(1000, 100, 0.12300)
        );
        assert_ne!(
            ProtocolParameters::new(1000, 101, 0.12300),
            ProtocolParameters::new(1000, 100, 0.12300)
        );
    }

    #[test]
    fn test_protocol_parameters_compute_hash() {
        let hash_expected = "ace019657cd995b0dfbb1ce8721a1092715972c4ae0171cc636ab4a44e6e4279";

        assert_eq!(
            hash_expected,
            ProtocolParameters::new(1000, 100, 0.123).compute_hash()
        );
        assert_ne!(
            hash_expected,
            ProtocolParameters::new(2000, 100, 0.123).compute_hash()
        );
        assert_ne!(
            hash_expected,
            ProtocolParameters::new(1000, 200, 0.123).compute_hash()
        );
        assert_ne!(
            hash_expected,
            ProtocolParameters::new(1000, 100, 0.124).compute_hash()
        );
    }

    mod verify_parameters {
        use super::*;

        #[test]
        fn test_valid_parameters() {
            let params = ProtocolParameters::new(10, 100, 0.123);
            assert!(params.check_parameters().is_ok());
        }

        #[test]
        fn test_invalid_k() {
            let params = ProtocolParameters::new(0, 100, 0.123);
            assert_eq!(
                params.check_parameters(),
                Err(ProtocolParametersError::InvalidK)
            );
        }

        #[test]
        fn test_invalid_m() {
            let params = ProtocolParameters::new(100, 0, 0.123);
            assert_eq!(
                params.check_parameters(),
                Err(ProtocolParametersError::InvalidM)
            );
        }

        #[test]
        fn test_invalid_k_greater_than_m() {
            let params = ProtocolParameters::new(100, 10, 0.123);
            assert_eq!(
                params.check_parameters(),
                Err(ProtocolParametersError::KGreaterThanM)
            );
        }

        #[test]
        fn test_phi_f_out_of_range() {
            let params = ProtocolParameters::new(10, 100, 0.0);
            assert_eq!(
                params.check_parameters(),
                Err(ProtocolParametersError::PhiFOutOfRange)
            );

            let params = ProtocolParameters::new(10, 100, -0.123);
            assert_eq!(
                params.check_parameters(),
                Err(ProtocolParametersError::PhiFOutOfRange)
            );

            let params = ProtocolParameters::new(10, 100, 1.123);
            assert_eq!(
                params.check_parameters(),
                Err(ProtocolParametersError::PhiFOutOfRange)
            );
        }
    }
}
