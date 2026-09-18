use anyhow::{Context, anyhow};
use ff::Field;
use midnight_curves::{Fq as JubjubBase, Fr as JubjubScalar};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::hash::{Hash, Hasher};
use std::ops::{Add, Mul, Neg, Sub};

use crate::StmError;
use crate::{StmResult, signature_scheme::SchnorrSignatureError};

/// Represents an element in the base field of the Jubjub curve
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, PartialOrd, Ord)]
pub struct BaseFieldElement(pub(crate) JubjubBase);

impl BaseFieldElement {
    /// Retrieves the multiplicative identity element of the base field
    pub(crate) fn get_one() -> Self {
        BaseFieldElement(JubjubBase::ONE)
    }

    #[cfg(all(test, feature = "future_snark"))]
    // TODO: remove this allow dead_code directive when function is called or future_snark is activated
    #[allow(dead_code)]
    /// Generates a new random scalar field element
    pub(crate) fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        BaseFieldElement(JubjubBase::random(rng))
    }

    /// Converts the base field element to its canonical little-endian byte representation.
    pub(crate) fn to_canonical_bytes(self) -> [u8; 32] {
        self.0.to_bytes_le()
    }

    /// Constructs a base field element from its canonical byte representation.
    ///
    /// Rejects any encoding that isn't the canonical representative below the field modulus —
    /// unlike the lenient `from_raw` constructor below, which applies modulus reduction instead.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> StmResult<Self> {
        let mut base_bytes = [0u8; 32];
        base_bytes.copy_from_slice(
            bytes
                .get(..32)
                .ok_or(SchnorrSignatureError::BaseFieldElementSerialization)?,
        );

        match JubjubBase::from_bytes_le(&base_bytes).into_option() {
            Some(base_field_element) => Ok(Self(base_field_element)),
            None => Err(anyhow!(
                SchnorrSignatureError::BaseFieldElementSerialization
            )),
        }
    }

    /// Constructs a base field element from bytes by applying modulus reduction
    /// The underlying JubjubBase conversion function used cannot fail
    pub fn from_raw(bytes: &[u8; 32]) -> StmResult<Self> {
        Ok(BaseFieldElement(JubjubBase::from_raw([
            u64::from_le_bytes(bytes[0..8].try_into()?),
            u64::from_le_bytes(bytes[8..16].try_into()?),
            u64::from_le_bytes(bytes[16..24].try_into()?),
            u64::from_le_bytes(bytes[24..32].try_into()?),
        ])))
    }
}

/// Try to convert an arbitrary slice of bytes to a BaseFieldElement by first
/// hashing the bytes using Sha256 and then converting using modulus reduction
impl TryFrom<&[u8]> for BaseFieldElement {
    type Error = StmError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let hashed_input: [u8; 32] = Sha256::digest(value).into();
        BaseFieldElement::from_raw(&hashed_input)
    }
}

impl From<u64> for BaseFieldElement {
    /// Converts a `u64` integer to a base field element
    fn from(integer: u64) -> Self {
        BaseFieldElement(JubjubBase::from(integer))
    }
}

impl From<JubjubBase> for BaseFieldElement {
    /// Converts a `JubjubBase` element to a base field element
    fn from(base: JubjubBase) -> Self {
        BaseFieldElement(base)
    }
}

impl Add for BaseFieldElement {
    type Output = BaseFieldElement;

    /// Adds two base field elements
    fn add(self, other: BaseFieldElement) -> BaseFieldElement {
        BaseFieldElement(self.0 + other.0)
    }
}

impl Neg for BaseFieldElement {
    type Output = BaseFieldElement;

    /// Negates a base field element
    fn neg(self) -> BaseFieldElement {
        BaseFieldElement(-self.0)
    }
}

impl Sub for &BaseFieldElement {
    type Output = BaseFieldElement;

    /// Subtracts one base field element from another
    fn sub(self, other: &BaseFieldElement) -> BaseFieldElement {
        BaseFieldElement(self.0 - other.0)
    }
}

impl Mul for BaseFieldElement {
    type Output = BaseFieldElement;

    /// Multiplies two base field elements
    fn mul(self, other: BaseFieldElement) -> BaseFieldElement {
        BaseFieldElement(self.0 * other.0)
    }
}

impl Mul for &BaseFieldElement {
    type Output = BaseFieldElement;

    /// Multiplies a base field element by another base field element
    fn mul(self, other: &BaseFieldElement) -> BaseFieldElement {
        BaseFieldElement(self.0 * other.0)
    }
}

/// Represents an element in the scalar field of the Jubjub curve
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ScalarFieldElement(pub(crate) JubjubScalar);

impl ScalarFieldElement {
    /// Generates a new random scalar field element
    pub(crate) fn new_random_scalar(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        ScalarFieldElement(JubjubScalar::random(rng))
    }

    /// Checks if the scalar field element is zero
    pub(crate) fn is_zero(&self) -> bool {
        if self.0 == JubjubScalar::zero() {
            return true;
        }
        false
    }

    #[cfg(all(test, feature = "future_snark"))]
    /// Retrieves the additive identity element of the scalar field
    pub(crate) fn get_zero() -> Self {
        ScalarFieldElement(JubjubScalar::ZERO)
    }

    /// Tries to generate a new random non-zero scalar field element in 100 attempts
    ///
    /// Returns an error if unable to generate a non-zero scalar after 100 attempts
    pub(crate) fn new_random_nonzero_scalar(
        rng: &mut (impl RngCore + CryptoRng),
    ) -> StmResult<Self> {
        for _ in 0..100 {
            let random_scalar = Self::new_random_scalar(rng);
            if !random_scalar.is_zero() {
                return Ok(random_scalar);
            }
        }
        Err(anyhow!(SchnorrSignatureError::RandomScalarGeneration))
    }

    /// Converts the scalar field element to its canonical byte representation.
    pub(crate) fn to_canonical_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Constructs a scalar field element from its canonical byte representation.
    ///
    /// Rejects any encoding that isn't the canonical representative below the field modulus —
    /// unlike the lenient `from_raw` constructor below, which applies modulus reduction instead.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> StmResult<Self> {
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(
            bytes
                .get(..32)
                .ok_or(SchnorrSignatureError::ScalarFieldElementSerialization)?,
        );

        match JubjubScalar::from_bytes(&scalar_bytes).into_option() {
            Some(scalar_field_element) => Ok(Self(scalar_field_element)),
            None => Err(anyhow!(
                SchnorrSignatureError::ScalarFieldElementSerialization
            )),
        }
    }

    /// Constructs a scalar field element from its byte representation
    /// while reducing modulo the scalar field modulus if necessary
    pub(crate) fn from_raw(bytes: &[u8]) -> StmResult<Self> {
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(
            bytes
                .get(..32)
                .ok_or(SchnorrSignatureError::ScalarFieldElementSerialization)?,
        );

        let mut bytes64 = [0u64; 4];
        for i in 0..4 {
            bytes64[i] =
                u64::from_le_bytes(bytes[8 * i..8 * (i + 1)].try_into().with_context(|| {
                    anyhow!(SchnorrSignatureError::ScalarFieldElementSerialization)
                })?)
        }

        Ok(Self(JubjubScalar::from_raw(bytes64)))
    }

    /// Convert a base field element to a scalar
    pub(crate) fn from_base_field(base_element: &BaseFieldElement) -> StmResult<Self> {
        let base_element_bytes = base_element.0.to_bytes_le();
        ScalarFieldElement::from_raw(&base_element_bytes)
    }
}

impl Mul for ScalarFieldElement {
    type Output = ScalarFieldElement;

    /// Multiplies two scalar field elements
    fn mul(self, other: ScalarFieldElement) -> ScalarFieldElement {
        ScalarFieldElement(self.0 * other.0)
    }
}

impl Sub for ScalarFieldElement {
    type Output = ScalarFieldElement;

    /// Subtracts one scalar field element from another
    fn sub(self, other: ScalarFieldElement) -> ScalarFieldElement {
        ScalarFieldElement(self.0 - other.0)
    }
}

impl Hash for ScalarFieldElement {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_canonical_bytes().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    mod golden {
        use super::*;

        const GOLDEN_JSON: &str = r#"[126, 191, 239, 197, 88, 151, 248, 254, 187, 143, 86, 35, 29, 62, 90, 13, 196, 71, 234, 5, 90, 124, 205, 194, 51, 192, 228, 133, 25, 140, 157, 7]"#;

        fn golden_value() -> ScalarFieldElement {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap()
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

    mod bytes_conversion {
        use super::*;

        #[test]
        fn from_bytes_fails_if_value_too_high() {
            let bytes = [255; 32];

            let value = BaseFieldElement::from_canonical_bytes(&bytes);
            value.expect_err("Bytes conversion should fail because input is higher than modulus.");

            let value = ScalarFieldElement::from_canonical_bytes(&bytes);
            value.expect_err("Bytes conversion should fail because input is higher than modulus.");
        }

        #[cfg(feature = "future_snark")]
        #[test]
        fn from_raw_recover_element_correctly() {
            let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
            let elem = BaseFieldElement::random(&mut rng);
            let elem_bytes = elem.to_canonical_bytes();

            let val1 = BaseFieldElement::from_canonical_bytes(&elem_bytes).unwrap();
            let val2 = BaseFieldElement::from_raw(&elem_bytes).unwrap();

            assert_eq!(val1, val2);
        }

        #[test]
        fn from_raw_succeed_for_max_value() {
            let bytes = [255; 32];

            let value = BaseFieldElement::from_canonical_bytes(&bytes);
            value.expect_err("Bytes conversion should fail because input is higher than modulus.");

            let value = BaseFieldElement::from_raw(&bytes);
            assert!(
                value.is_ok(),
                "The conversion should not fail when using from_raw."
            );
        }
    }

    mod base_field_arithmetic {
        use super::*;

        #[test]
        fn test_add() {
            let a = BaseFieldElement(JubjubBase::ONE);
            let b = BaseFieldElement(JubjubBase::ONE);
            let result = a + b;
            assert_eq!(result, BaseFieldElement(JubjubBase::ONE + JubjubBase::ONE));
        }

        #[test]
        fn test_add_with_zero() {
            let a = BaseFieldElement(JubjubBase::ONE);
            let zero = BaseFieldElement(JubjubBase::ZERO);
            let result = a + zero;
            assert_eq!(result, a);
        }

        #[test]
        fn test_sub_references() {
            let a = BaseFieldElement(JubjubBase::ONE + JubjubBase::ONE);
            let b = BaseFieldElement(JubjubBase::ONE);
            let result = &a - &b;
            assert_eq!(result, BaseFieldElement(JubjubBase::ONE));
        }

        #[test]
        fn test_sub_same_values() {
            let a = BaseFieldElement(JubjubBase::ONE);
            let b = BaseFieldElement(JubjubBase::ONE);
            let result = &a - &b;
            assert_eq!(result, BaseFieldElement(JubjubBase::ZERO));
        }

        #[test]
        fn test_mul_owned() {
            let a = BaseFieldElement(JubjubBase::ONE + JubjubBase::ONE);
            let b = BaseFieldElement(JubjubBase::ONE + JubjubBase::ONE);
            let result = a * b;
            let expected = JubjubBase::ONE + JubjubBase::ONE;
            assert_eq!(result, BaseFieldElement(expected * expected));
        }

        #[test]
        fn test_mul_with_one() {
            let a = BaseFieldElement(JubjubBase::ONE + JubjubBase::ONE);
            let one = BaseFieldElement::get_one();
            let result = a * one;
            assert_eq!(result, a);
        }

        #[test]
        fn test_mul_with_zero() {
            let a = BaseFieldElement(JubjubBase::ONE);
            let zero = BaseFieldElement(JubjubBase::ZERO);
            let result = a * zero;
            assert_eq!(result, BaseFieldElement(JubjubBase::ZERO));
        }

        #[test]
        fn test_mul_references() {
            let a = BaseFieldElement(JubjubBase::ONE + JubjubBase::ONE);
            let b = BaseFieldElement(JubjubBase::ONE + JubjubBase::ONE + JubjubBase::ONE);
            let result = a * b;
            let expected = (JubjubBase::ONE + JubjubBase::ONE)
                * (JubjubBase::ONE + JubjubBase::ONE + JubjubBase::ONE);
            assert_eq!(result, BaseFieldElement(expected));
        }

        #[test]
        fn test_chained_operations() {
            let a = BaseFieldElement(JubjubBase::ONE);
            let b = BaseFieldElement(JubjubBase::ONE);
            let c = BaseFieldElement(JubjubBase::ONE);
            let result = (a + b) * c;
            assert_eq!(result, BaseFieldElement(JubjubBase::ONE + JubjubBase::ONE));
        }
    }

    mod scalar_field_arithmetic {
        use super::*;

        #[test]
        fn test_mul() {
            let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
            let a = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let b = ScalarFieldElement(JubjubScalar::one());
            let result = a * b;
            assert_eq!(result, a);
        }

        #[test]
        fn test_mul_with_zero() {
            let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
            let a = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let zero = ScalarFieldElement(JubjubScalar::zero());
            let result = a * zero;
            assert!(result.is_zero());
        }

        #[test]
        fn test_mul_associativity() {
            let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
            let a = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let b = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let c = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();

            let result1 = (a * b) * c;
            let result2 = a * (b * c);
            assert_eq!(result1, result2);
        }

        #[test]
        fn test_sub() {
            let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
            let a = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let result = a - a;
            assert!(result.is_zero());
        }

        #[test]
        fn test_sub_with_zero() {
            let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
            let a = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let zero = ScalarFieldElement(JubjubScalar::zero());
            let result = a - zero;
            assert_eq!(result, a);
        }

        #[test]
        fn test_sub_specific_values() {
            let two = ScalarFieldElement(JubjubScalar::one() + JubjubScalar::one());
            let one = ScalarFieldElement(JubjubScalar::one());
            let result = two - one;
            assert_eq!(result, ScalarFieldElement(JubjubScalar::one()));
        }

        #[test]
        fn test_combined_operations() {
            let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
            let a = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let b = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let c = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();

            let left = a * (b - c);
            let right = (a * b) - (a * c);
            assert_eq!(left, right);
        }
    }
}
