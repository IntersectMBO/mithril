use std::fmt::{Display, Formatter};
use std::ops::{Add, AddAssign, Deref, Sub, SubAssign};

use serde::{Deserialize, Serialize};

use crate::entities::arithmetic_operation_wrapper::impl_partial_eq_to_wrapper;

/// A discrete percentage value between 0 and 100.
///
/// Values above 100, either on construction, deserialization, or as the result of an
/// arithmetic operation, saturate to 100.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(from = "u8")]
pub struct Percentage(u8);

impl Percentage {
    /// 0%
    pub const ZERO: Self = Self(0);

    /// 100%, the maximum value of a percentage
    pub const HUNDRED: Self = Self(100);

    /// Create a new percentage, saturating to 100 if the given value is above it.
    pub const fn new(value: u8) -> Self {
        if value > Self::HUNDRED.0 {
            Self::HUNDRED
        } else {
            Self(value)
        }
    }

    /// Ratio represented by this percentage, between `0.0` and `1.0`.
    pub fn as_ratio(&self) -> f64 {
        f64::from(self.0) / f64::from(Self::HUNDRED.0)
    }
}

impl Default for Percentage {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<u8> for Percentage {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl Display for Percentage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Deref for Percentage {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Add for Percentage {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self + rhs.0
    }
}

impl Add<u8> for Percentage {
    type Output = Self;

    fn add(self, rhs: u8) -> Self::Output {
        Self::new(self.0.saturating_add(rhs))
    }
}

impl AddAssign for Percentage {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl AddAssign<u8> for Percentage {
    fn add_assign(&mut self, rhs: u8) {
        *self = *self + rhs;
    }
}

impl Sub for Percentage {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self - rhs.0
    }
}

impl Sub<u8> for Percentage {
    type Output = Self;

    fn sub(self, rhs: u8) -> Self::Output {
        Self::new(self.0.saturating_sub(rhs))
    }
}

impl SubAssign for Percentage {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl SubAssign<u8> for Percentage {
    fn sub_assign(&mut self, rhs: u8) {
        *self = *self - rhs;
    }
}

impl_partial_eq_to_wrapper!(Percentage, u8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_saturates_above_100() {
        assert_eq!(Percentage::new(0), 0);
        assert_eq!(Percentage::new(42), 42);
        assert_eq!(Percentage::new(100), 100);
        assert_eq!(Percentage::new(101), 100);
        assert_eq!(Percentage::new(u8::MAX), 100);
    }

    #[test]
    fn from_u8_saturates_above_100() {
        assert_eq!(Percentage::from(42), 42);
        assert_eq!(Percentage::from(150), 100);
    }

    #[test]
    fn test_constants() {
        assert_eq!(Percentage::ZERO, 0);
        assert_eq!(Percentage::HUNDRED, 100);
    }

    #[test]
    fn default_is_zero() {
        assert_eq!(Percentage::default(), Percentage::ZERO);
    }

    #[test]
    fn test_as_ratio() {
        assert_eq!(Percentage::ZERO.as_ratio(), 0.0);
        assert_eq!(Percentage::new(42).as_ratio(), 0.42);
        assert_eq!(Percentage::HUNDRED.as_ratio(), 1.0);
    }

    #[test]
    fn test_display() {
        assert_eq!(Percentage::new(42).to_string(), "42");
    }

    #[test]
    fn test_serialize() {
        assert_eq!(serde_json::to_string(&Percentage::new(42)).unwrap(), "42");
    }

    #[test]
    fn test_deserialize() {
        let percentage: Percentage = serde_json::from_str("42").unwrap();
        assert_eq!(percentage, 42);
    }

    #[test]
    fn deserialize_saturates_above_100() {
        let percentage: Percentage = serde_json::from_str("150").unwrap();
        assert_eq!(percentage, 100);
    }

    #[test]
    fn deserialize_fails_for_values_out_of_u8_range() {
        serde_json::from_str::<Percentage>("256").expect_err("256 is out of u8 range");
        serde_json::from_str::<Percentage>("-1").expect_err("-1 is out of u8 range");
    }

    #[test]
    fn test_add() {
        assert_eq!(Percentage::new(40) + Percentage::new(2), 42);
        assert_eq!(Percentage::new(40) + 2, 42);
    }

    #[test]
    fn add_saturates_at_100() {
        assert_eq!(Percentage::new(60) + Percentage::new(60), 100);
        assert_eq!(Percentage::new(60) + 60, 100);
        assert_eq!(Percentage::HUNDRED + u8::MAX, 100);
    }

    #[test]
    fn test_add_assign() {
        let mut percentage = Percentage::new(40);
        percentage += Percentage::new(2);
        assert_eq!(percentage, 42);

        percentage += 100;
        assert_eq!(percentage, 100);
    }

    #[test]
    fn test_sub() {
        assert_eq!(Percentage::new(44) - Percentage::new(2), 42);
        assert_eq!(Percentage::new(44) - 2, 42);
    }

    #[test]
    fn sub_saturates_at_0() {
        assert_eq!(Percentage::new(10) - Percentage::new(60), 0);
        assert_eq!(Percentage::new(10) - 60, 0);
        assert_eq!(Percentage::new(10) - u8::MAX, 0);
    }

    #[test]
    fn test_sub_assign() {
        let mut percentage = Percentage::new(44);
        percentage -= Percentage::new(2);
        assert_eq!(percentage, 42);

        percentage -= 100;
        assert_eq!(percentage, 0);
    }
}
