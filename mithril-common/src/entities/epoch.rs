use std::fmt::{Display, Formatter};
use std::num::TryFromIntError;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::entities::arithmetic_operation_wrapper::{
    impl_add_to_wrapper, impl_partial_eq_to_wrapper, impl_sub_to_wrapper,
};
use crate::{StdError, StdResult};

const INVALID_EPOCH_SPECIFIER_ERROR: &str =
    "Invalid epoch: expected 'X', 'latest' or 'latest-X' where X is a positive 64-bit integer";

/// Epoch represents a Cardano epoch
#[derive(
    Debug, Copy, Clone, Default, PartialEq, Serialize, Deserialize, Hash, Eq, PartialOrd, Ord,
)]
pub struct Epoch(pub u64);

impl Epoch {
    /// The epoch offset used for signers stake distribution and verification keys retrieval.
    pub const SIGNER_RETRIEVAL_OFFSET: i64 = -1;

    /// The epoch offset used to retrieve the signers stake distribution and verification keys that's
    /// currently being signed so it can be used in the next epoch.
    pub const NEXT_SIGNER_RETRIEVAL_OFFSET: u64 = 0;

    /// The epoch offset used for signers stake distribution and verification keys recording.
    pub const SIGNER_RECORDING_OFFSET: u64 = 1;

    /// The epoch offset used for aggregator epoch settings recording.
    pub const EPOCH_SETTINGS_RECORDING_OFFSET: u64 = 2;

    /// The epoch offset used to retrieve, given the epoch at which a signer registered, the epoch
    /// at which the signer can send single signatures.
    pub const SIGNER_SIGNING_OFFSET: u64 = 2;

    /// The epoch offset used to retrieve the epoch at the end of which the snapshot of the stake distribution
    /// was taken by the Cardano node and labeled as 'Mark' snapshot during the following epoch.
    pub const CARDANO_STAKE_DISTRIBUTION_SNAPSHOT_OFFSET: u64 = 2;

    /// The epoch offset used to retrieve the epoch at which a signer has registered to the leader aggregator.
    pub const SIGNER_LEADER_SYNCHRONIZATION_OFFSET: u64 = 0;

    /// Computes a new Epoch by applying an epoch offset.
    ///
    /// Will fail if the computed epoch is negative.
    pub fn offset_by(&self, epoch_offset: i64) -> Result<Self, EpochError> {
        let epoch_new = self.0 as i64 + epoch_offset;
        if epoch_new < 0 {
            return Err(EpochError::EpochOffset(self.0, epoch_offset));
        }
        Ok(Epoch(epoch_new as u64))
    }

    /// Apply the [retrieval offset][Self::SIGNER_RETRIEVAL_OFFSET] to this epoch
    pub fn offset_to_signer_retrieval_epoch(&self) -> Result<Self, EpochError> {
        self.offset_by(Self::SIGNER_RETRIEVAL_OFFSET)
    }

    /// Apply the [retrieval offset][Self::SIGNER_RETRIEVAL_OFFSET] to this epoch, saturating at
    /// epoch zero.
    ///
    /// Unlike [offset_to_signer_retrieval_epoch][Self::offset_to_signer_retrieval_epoch], this
    /// returns epoch zero instead of failing when the offset would yield a negative epoch
    /// (i.e. at epoch zero itself).
    pub fn offset_to_signer_retrieval_epoch_saturating(&self) -> Self {
        self.offset_to_signer_retrieval_epoch().unwrap_or(Epoch(0))
    }

    /// Apply the [next signer retrieval offset][Self::NEXT_SIGNER_RETRIEVAL_OFFSET] to this epoch
    pub fn offset_to_next_signer_retrieval_epoch(&self) -> Self {
        *self + Self::NEXT_SIGNER_RETRIEVAL_OFFSET
    }

    /// Apply the [recording offset][Self::SIGNER_RECORDING_OFFSET] to this epoch
    pub fn offset_to_recording_epoch(&self) -> Self {
        *self + Self::SIGNER_RECORDING_OFFSET
    }

    /// Apply the [epoch settings recording offset][Self::EPOCH_SETTINGS_RECORDING_OFFSET] to this epoch
    pub fn offset_to_epoch_settings_recording_epoch(&self) -> Self {
        *self + Self::EPOCH_SETTINGS_RECORDING_OFFSET
    }

    /// Apply the [signer signing offset][Self::SIGNER_SIGNING_OFFSET] to this epoch
    pub fn offset_to_signer_signing_offset(&self) -> Self {
        *self + Self::SIGNER_SIGNING_OFFSET
    }

    /// Apply the [cardano stake distribution snapshot epoch offset][Self::CARDANO_STAKE_DISTRIBUTION_SNAPSHOT_OFFSET] to this epoch
    pub fn offset_to_cardano_stake_distribution_snapshot_epoch(&self) -> Self {
        *self + Self::CARDANO_STAKE_DISTRIBUTION_SNAPSHOT_OFFSET
    }

    /// Apply the [recording offset][Self::SIGNER_LEADER_SYNCHRONIZATION_OFFSET] to this epoch
    pub fn offset_to_leader_synchronization_epoch(&self) -> Self {
        *self + Self::SIGNER_LEADER_SYNCHRONIZATION_OFFSET
    }

    /// Computes the next Epoch
    pub fn next(&self) -> Self {
        *self + 1
    }

    /// Computes the previous Epoch
    pub fn previous(&self) -> Result<Self, EpochError> {
        self.offset_by(-1)
    }

    /// Check if there is a gap with another Epoch.
    pub fn has_gap_with(&self, other: &Epoch) -> bool {
        self.0.abs_diff(other.0) > 1
    }
}

impl Deref for Epoch {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Epoch {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl_add_to_wrapper!(Epoch, u64);
impl_sub_to_wrapper!(Epoch, u64);
impl_partial_eq_to_wrapper!(Epoch, u64);

impl Display for Epoch {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryInto<i64> for Epoch {
    type Error = TryFromIntError;

    fn try_into(self) -> Result<i64, Self::Error> {
        self.0.try_into()
    }
}

impl TryInto<i64> for &Epoch {
    type Error = TryFromIntError;

    fn try_into(self) -> Result<i64, Self::Error> {
        self.0.try_into()
    }
}

impl From<Epoch> for f64 {
    fn from(value: Epoch) -> f64 {
        value.0 as f64
    }
}

impl FromStr for Epoch {
    type Err = anyhow::Error;

    fn from_str(epoch_str: &str) -> Result<Self, Self::Err> {
        epoch_str.parse::<u64>().map(Epoch).with_context(|| {
            format!("Invalid epoch '{epoch_str}': must be a positive 64-bit integer")
        })
    }
}

/// EpochError is an error triggered by an [Epoch]
#[derive(Error, Debug)]
pub enum EpochError {
    /// Error raised when the [computation of an epoch using an offset][Epoch::offset_by] fails.
    #[error("epoch offset error")]
    EpochOffset(u64, i64),
}

/// Represents the different ways to specify an epoch when querying the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochSpecifier {
    /// Epoch was explicitly provided as a number (e.g., "123")
    Number(Epoch),
    /// Epoch was provided as "latest" (e.g., "latest")
    Latest,
    /// Epoch was provided as "latest-{offset}" (e.g., "latest-100")
    LatestMinusOffset(u64),
}

impl EpochSpecifier {
    /// Parses the given epoch string into an `EpochSpecifier`.
    ///
    /// Accepted values are:
    /// - a `u64` number
    /// - `latest`
    /// - `latest-{offset}` where `{offset}` is a `u64` number
    pub fn parse(epoch_str: &str) -> StdResult<Self> {
        Self::from_str(epoch_str)
    }
}

impl FromStr for EpochSpecifier {
    type Err = StdError;

    fn from_str(epoch_str: &str) -> Result<Self, Self::Err> {
        if epoch_str == "latest" {
            Ok(EpochSpecifier::Latest)
        } else if let Some(offset_str) = epoch_str.strip_prefix("latest-") {
            if offset_str.is_empty() {
                anyhow::bail!("Invalid epoch '{epoch_str}': offset cannot be empty");
            }
            let offset = offset_str.parse::<u64>().with_context(|| {
                format!("Invalid epoch '{epoch_str}': offset must be a positive 64-bit integer")
            })?;

            Ok(EpochSpecifier::LatestMinusOffset(offset))
        } else {
            epoch_str
                .parse::<Epoch>()
                .map(EpochSpecifier::Number)
                .with_context(|| INVALID_EPOCH_SPECIFIER_ERROR)
        }
    }
}

impl Display for EpochSpecifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            EpochSpecifier::Number(epoch) => write!(f, "{}", epoch),
            EpochSpecifier::Latest => {
                write!(f, "latest")
            }
            EpochSpecifier::LatestMinusOffset(offset) => {
                write!(f, "latest-{}", offset)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::entities::arithmetic_operation_wrapper::tests::test_op_assign;

    use super::*;

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Epoch(72)), "72");
        assert_eq!(format!("{}", Epoch(13224)), "13224");
    }

    #[test]
    fn test_serialize() {
        assert_eq!(serde_json::to_string(&Epoch(72)).unwrap(), "72");
    }

    #[test]
    fn test_deserialize() {
        let block_number: Epoch = serde_json::from_str("13224").unwrap();
        assert_eq!(block_number, Epoch(13224));
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn test_add() {
        assert_eq!(Epoch(4), Epoch(1) + Epoch(3));
        assert_eq!(Epoch(4), Epoch(1) + 3_u64);
        assert_eq!(Epoch(4), Epoch(1) + &3_u64);

        assert_eq!(Epoch(4), 3_u64 + Epoch(1));
        assert_eq!(Epoch(4), 3_u64 + &Epoch(1));
        assert_eq!(Epoch(4), &3_u64 + Epoch(1));
        assert_eq!(Epoch(4), &3_u64 + &Epoch(1));

        test_op_assign!(Epoch(1), +=, Epoch(3) => Epoch(4));
        test_op_assign!(Epoch(1), +=, 3_u64 => Epoch(4));
        test_op_assign!(Epoch(1), +=, &3_u64 => Epoch(4));

        test_op_assign!(1_u64, +=, Epoch(3) => 4_u64);
        test_op_assign!(1_u64, +=, &Epoch(3) => 4_u64);
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn test_sub() {
        assert_eq!(Epoch(8), Epoch(14) - Epoch(6));
        assert_eq!(Epoch(8), Epoch(14) - 6_u64);
        assert_eq!(Epoch(8), Epoch(14) - &6_u64);

        assert_eq!(Epoch(8), 6_u64 - Epoch(14));
        assert_eq!(Epoch(8), 6_u64 - &Epoch(14));
        assert_eq!(Epoch(8), &6_u64 - Epoch(14));
        assert_eq!(Epoch(8), &6_u64 - &Epoch(14));

        test_op_assign!(Epoch(14), -=, Epoch(6) => Epoch(8));
        test_op_assign!(Epoch(14), -=, 6_u64 => Epoch(8));
        test_op_assign!(Epoch(14), -=, &6_u64 => Epoch(8));

        test_op_assign!(14_u64, -=, Epoch(6) => 8_u64);
        test_op_assign!(14_u64, -=, &Epoch(6) => 8_u64);
    }

    #[test]
    fn saturating_sub() {
        assert_eq!(Epoch(0), Epoch(1) - Epoch(5));
        assert_eq!(Epoch(0), Epoch(1) - 5_u64);
    }

    #[test]
    fn test_previous() {
        assert_eq!(Epoch(2), Epoch(3).previous().unwrap());
        assert!(Epoch(0).previous().is_err());
    }

    #[test]
    fn offset_to_signer_retrieval_epoch_saturating_clamps_at_epoch_zero() {
        assert_eq!(
            Epoch(2),
            Epoch(3).offset_to_signer_retrieval_epoch_saturating()
        );
        assert_eq!(
            Epoch(0),
            Epoch(1).offset_to_signer_retrieval_epoch_saturating()
        );
        assert_eq!(
            Epoch(0),
            Epoch(0).offset_to_signer_retrieval_epoch_saturating()
        );
    }

    #[test]
    fn test_next() {
        assert_eq!(Epoch(4), Epoch(3).next());
    }

    #[test]
    fn test_eq() {
        assert_eq!(Epoch(1), Epoch(1));
        assert_eq!(Epoch(2), &Epoch(2));
        assert_eq!(&Epoch(3), Epoch(3));
        assert_eq!(&Epoch(4), &Epoch(4));

        assert_eq!(Epoch(5), 5);
        assert_eq!(Epoch(6), &6);
        assert_eq!(&Epoch(7), 7);
        assert_eq!(&Epoch(8), &8);

        assert_eq!(9, Epoch(9));
        assert_eq!(10, &Epoch(10));
        assert_eq!(&11, Epoch(11));
        assert_eq!(&12, &Epoch(12));
    }

    #[test]
    fn test_has_gap_ok() {
        assert!(Epoch(3).has_gap_with(&Epoch(5)));
        assert!(!Epoch(3).has_gap_with(&Epoch(4)));
        assert!(!Epoch(3).has_gap_with(&Epoch(3)));
        assert!(!Epoch(3).has_gap_with(&Epoch(2)));
        assert!(Epoch(3).has_gap_with(&Epoch(0)));
    }

    #[test]
    fn from_str() {
        let expected_epoch = Epoch(123);
        let from_str = Epoch::from_str("123").unwrap();
        assert_eq!(from_str, expected_epoch);

        let from_string = String::from("123").parse::<Epoch>().unwrap();
        assert_eq!(from_string, expected_epoch);

        let alternate_notation: Epoch = "123".parse().unwrap();
        assert_eq!(alternate_notation, expected_epoch);

        let invalid_epoch_err = Epoch::from_str("123.456").unwrap_err();
        assert!(
            invalid_epoch_err
                .to_string()
                .contains("Invalid epoch '123.456': must be a positive 64-bit integer")
        );

        let overflow_err = format!("1{}", u64::MAX).parse::<Epoch>().unwrap_err();
        assert!(
            overflow_err.to_string().contains(
                "Invalid epoch '118446744073709551615': must be a positive 64-bit integer"
            )
        );
    }

    #[test]
    fn display_epoch_specifier() {
        assert_eq!(format!("{}", EpochSpecifier::Number(Epoch(123))), "123");
        assert_eq!(format!("{}", EpochSpecifier::Latest), "latest");
        assert_eq!(
            format!("{}", EpochSpecifier::LatestMinusOffset(123)),
            "latest-123"
        );
    }

    mod parse_specifier {
        use super::*;

        #[test]
        fn parse_epoch_number() {
            let parsed_value = EpochSpecifier::parse("5").unwrap();
            assert_eq!(EpochSpecifier::Number(Epoch(5)), parsed_value);
        }

        #[test]
        fn parse_latest_epoch() {
            let parsed_value = EpochSpecifier::parse("latest").unwrap();
            assert_eq!(EpochSpecifier::Latest, parsed_value);
        }

        #[test]
        fn parse_latest_epoch_with_offset() {
            let parsed_value = EpochSpecifier::parse("latest-43").unwrap();
            assert_eq!(EpochSpecifier::LatestMinusOffset(43), parsed_value);
        }

        #[test]
        fn parse_invalid_str_yield_error() {
            let error = EpochSpecifier::parse("invalid_string").unwrap_err();
            assert!(error.to_string().contains(INVALID_EPOCH_SPECIFIER_ERROR));
        }

        #[test]
        fn parse_too_big_epoch_number_yield_error() {
            let error = EpochSpecifier::parse(&format!("9{}", u64::MAX)).unwrap_err();
            assert!(error.to_string().contains(INVALID_EPOCH_SPECIFIER_ERROR));
            println!("{:?}", error);
        }

        #[test]
        fn parse_latest_epoch_with_invalid_offset_yield_error() {
            let error = EpochSpecifier::parse("latest-invalid").unwrap_err();
            assert!(error.to_string().contains(
                "Invalid epoch 'latest-invalid': offset must be a positive 64-bit integer"
            ));
        }

        #[test]
        fn parse_latest_epoch_with_empty_offset_yield_error() {
            let error = EpochSpecifier::parse("latest-").unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("Invalid epoch 'latest-': offset cannot be empty")
            );
        }

        #[test]
        fn parse_latest_epoch_with_too_big_offset_yield_error() {
            let error = EpochSpecifier::parse(&format!("latest-9{}", u64::MAX)).unwrap_err();
            assert!(error.to_string().contains(
                "Invalid epoch 'latest-918446744073709551615': offset must be a positive 64-bit integer"
            ))
        }

        #[test]
        fn specifier_to_string_can_be_parsed_back() {
            for specifier in [
                EpochSpecifier::Number(Epoch(121)),
                EpochSpecifier::Latest,
                EpochSpecifier::LatestMinusOffset(121),
            ] {
                let value = EpochSpecifier::parse(&specifier.to_string()).unwrap();
                assert_eq!(value, specifier);
            }
        }
    }
}
