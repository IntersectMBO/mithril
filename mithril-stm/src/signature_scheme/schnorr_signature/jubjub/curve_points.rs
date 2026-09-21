use anyhow::anyhow;
use group::{Group, GroupEncoding};
use midnight_circuits::instructions::HashToCurveCPU;
use midnight_circuits::{
    ecc::{hash_to_curve::HashToCurveGadget, native::EccChip},
    hash::poseidon::PoseidonChip,
    types::AssignedNative,
};
use midnight_curves::{
    EDWARDS_D, Fq as JubjubBase, JubjubAffine as JubjubAffinePoint, JubjubExtended, JubjubSubgroup,
};
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::ops::{Add, Mul};

use crate::{StmResult, signature_scheme::SchnorrSignatureError};

use super::{BaseFieldElement, ScalarFieldElement};

/// Defining a type for the CPU hash to curve gadget
pub(crate) type JubjubHashToCurveGadget = HashToCurveGadget<
    JubjubBase,
    JubjubExtended,
    AssignedNative<JubjubBase>,
    PoseidonChip<JubjubBase>,
    EccChip<JubjubExtended>,
>;

/// Represents a point in affine coordinates on the Jubjub curve
#[derive(Clone)]
pub(crate) struct AffinePoint(JubjubAffinePoint);

impl AffinePoint {
    /// Converts a projective point to its affine representation
    pub(crate) fn from_projective_point(projective_point: ProjectivePoint) -> Self {
        AffinePoint(JubjubAffinePoint::from(projective_point.0))
    }

    /// Retrieves the u-coordinate of the affine point
    pub(crate) fn get_u(&self) -> BaseFieldElement {
        BaseFieldElement(self.0.get_u())
    }

    /// Retrieves the v-coordinate of the affine point
    pub(crate) fn get_v(&self) -> BaseFieldElement {
        BaseFieldElement(self.0.get_v())
    }
}

impl From<&PrimeOrderProjectivePoint> for AffinePoint {
    /// Converts a prime order projective point to its affine representation
    fn from(prime_order_projective_point: &PrimeOrderProjectivePoint) -> Self {
        AffinePoint(JubjubAffinePoint::from(JubjubExtended::from(
            prime_order_projective_point.0,
        )))
    }
}

/// Represents a point in projective coordinates on the Jubjub curve
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProjectivePoint(pub(crate) JubjubExtended);

impl ProjectivePoint {
    /// Hashes input BaseFieldElements to a projective point on the Jubjub curve
    pub(crate) fn hash_to_projective_point(input: &[BaseFieldElement]) -> StmResult<Self> {
        let mut base_elements = Vec::with_capacity(input.len());
        for elem in input.iter() {
            base_elements.push(elem.0);
        }
        let point = JubjubHashToCurveGadget::hash_to_curve(&base_elements);
        Ok(ProjectivePoint(JubjubExtended::from(point)))
    }

    /// Retrieves the (u, v) coordinates of the projective point in affine representation
    pub(crate) fn get_coordinates(&self) -> (BaseFieldElement, BaseFieldElement) {
        let affine_point = AffinePoint::from_projective_point(*self);

        (affine_point.get_u(), affine_point.get_v())
    }

    /// Converts the projective point to its canonical compressed byte representation.
    ///
    /// Used by `UniqueSchnorrSignature`'s raw layout and this type's `Serialize` impl.
    pub(crate) fn to_canonical_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Constructs a projective point from its canonical compressed byte representation.
    ///
    /// Rejects any non-canonical encoding.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> StmResult<Self> {
        let mut projective_point_bytes = [0u8; 32];
        projective_point_bytes
            .copy_from_slice(bytes.get(..32).ok_or(SchnorrSignatureError::Serialization)?);

        match JubjubExtended::from_bytes(&projective_point_bytes).into_option() {
            Some(projective_point) => Ok(Self(projective_point)),
            None => Err(anyhow!(SchnorrSignatureError::ProjectivePointSerialization)),
        }
    }

    /// Checks if the projective point is of prime order
    pub(crate) fn is_prime_order(self) -> bool {
        self.0.is_prime_order().into()
    }
}

impl Add for ProjectivePoint {
    type Output = ProjectivePoint;

    /// Adds two projective points
    fn add(self, other: ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint(self.0 + other.0)
    }
}

impl Mul<ProjectivePoint> for ScalarFieldElement {
    type Output = ProjectivePoint;

    /// Multiplies a projective point by a scalar field element
    /// Returns the resulting projective point
    fn mul(self, point: ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint(point.0 * self.0)
    }
}

impl From<PrimeOrderProjectivePoint> for ProjectivePoint {
    /// Converts a prime order projective point to a projective point
    fn from(prime_order_projective_point: PrimeOrderProjectivePoint) -> Self {
        ProjectivePoint(JubjubExtended::from(prime_order_projective_point.0))
    }
}

impl Hash for ProjectivePoint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_canonical_bytes().hash(state);
    }
}

impl PartialOrd for ProjectivePoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProjectivePoint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_canonical_bytes().cmp(&other.to_canonical_bytes())
    }
}

/// Represents a point of prime order in projective coordinates on the Jubjub curve
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PrimeOrderProjectivePoint(pub(crate) JubjubSubgroup);

impl PrimeOrderProjectivePoint {
    /// Creates the generator point of the prime order subgroup
    pub(crate) fn create_generator() -> Self {
        PrimeOrderProjectivePoint(JubjubSubgroup::generator())
    }

    /// Checks if the given point is on the curve using its coordinates
    pub(crate) fn is_on_curve(&self) -> StmResult<PrimeOrderProjectivePoint> {
        let (x, y) = self.get_coordinates();
        let x_square = x * x;
        let y_square = y * y;

        let lhs = &y_square - &x_square;
        let rhs = (x_square * y_square) * BaseFieldElement(EDWARDS_D) + BaseFieldElement::get_one();

        if lhs != rhs {
            return Err(anyhow!(SchnorrSignatureError::PointIsNotOnCurve(Box::new(
                *self
            ))));
        }
        Ok(*self)
    }

    /// Retrieves the (u, v) coordinates of the prime order projective point in affine representation
    pub(crate) fn get_coordinates(&self) -> (BaseFieldElement, BaseFieldElement) {
        let affine_point = AffinePoint::from(self);

        (affine_point.get_u(), affine_point.get_v())
    }

    /// Tries to create a PrimeOrderProjectivePoint from coordinates and fails
    /// if the corresponding point is not of prime order or on the curve
    pub(crate) fn from_coordinates(u: BaseFieldElement, v: BaseFieldElement) -> StmResult<Self> {
        let prime_order_point =
            PrimeOrderProjectivePoint(JubjubSubgroup::from_raw_unchecked(u.0, v.0))
                .is_on_curve()?;

        let projective_point = ProjectivePoint::from(prime_order_point);
        if !projective_point.is_prime_order() {
            return Err(anyhow!(SchnorrSignatureError::PointIsNotPrimeOrder(
                Box::new(prime_order_point)
            )));
        }

        Ok(prime_order_point)
    }

    /// Converts the prime order projective point to its canonical compressed byte representation.
    ///
    /// Backs `SchnorrVerificationKey`'s `Serialize` impl via this module's `impl_serde!` macro,
    /// which is the wire format for real signer-registration JSON messages — not test-only.
    pub(crate) fn to_canonical_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Constructs a prime order projective point from its canonical compressed byte representation.
    ///
    /// Rejects any non-canonical encoding.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> StmResult<Self> {
        let mut prime_order_projective_point_bytes = [0u8; 32];
        prime_order_projective_point_bytes
            .copy_from_slice(bytes.get(..32).ok_or(SchnorrSignatureError::Serialization)?);

        match JubjubSubgroup::from_bytes(&prime_order_projective_point_bytes).into_option() {
            Some(prime_order_projective_point) => Ok(Self(prime_order_projective_point)),
            None => Err(anyhow!(
                SchnorrSignatureError::PrimeOrderProjectivePointSerialization
            )),
        }
    }
}

impl Add for PrimeOrderProjectivePoint {
    type Output = PrimeOrderProjectivePoint;

    /// Adds two prime order projective points
    fn add(self, other: PrimeOrderProjectivePoint) -> PrimeOrderProjectivePoint {
        PrimeOrderProjectivePoint(self.0 + other.0)
    }
}

impl Mul<PrimeOrderProjectivePoint> for ScalarFieldElement {
    type Output = PrimeOrderProjectivePoint;

    /// Multiplies a prime order projective point by a scalar field element
    /// Returns the resulting prime order projective point
    fn mul(self, point: PrimeOrderProjectivePoint) -> PrimeOrderProjectivePoint {
        PrimeOrderProjectivePoint(point.0 * self.0)
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    mod golden {
        use super::*;

        const GOLDEN_JSON: &str = r#"[144, 52, 95, 161, 127, 253, 49, 32, 140, 217, 231, 207, 32, 238, 244, 196, 97, 241, 47, 95, 101, 9, 70, 136, 194, 66, 187, 253, 200, 32, 218, 43]"#;

        fn golden_value() -> PrimeOrderProjectivePoint {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
            let scalar = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let point = PrimeOrderProjectivePoint::create_generator();
            PrimeOrderProjectivePoint(point.0 * scalar.0)
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

    mod golden_hash {
        use super::*;

        const GOLDEN_BYTES: &[u8] = &[
            15, 44, 110, 49, 102, 14, 172, 174, 230, 224, 30, 24, 129, 48, 80, 106, 88, 47, 98,
            132, 180, 50, 8, 88, 48, 33, 149, 193, 129, 151, 209, 239,
        ];

        fn golden_value() -> ProjectivePoint {
            let msg = [255u8; 32];
            let base_input = BaseFieldElement::try_from(msg.as_slice()).unwrap();
            ProjectivePoint::hash_to_projective_point(&[base_input]).unwrap()
        }

        #[test]
        fn golden_hash() {
            let value = ProjectivePoint::from_canonical_bytes(GOLDEN_BYTES)
                .expect("This from bytes should not fail");
            assert_eq!(golden_value(), value);
        }
    }

    mod projective_point_arithmetic {
        use super::*;

        #[test]
        fn test_add() {
            let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
            let scalar1 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let scalar2 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let base_input = BaseFieldElement::try_from(b"test_point".as_slice()).unwrap();
            let point = ProjectivePoint::hash_to_projective_point(&[base_input]).unwrap();

            let p1 = scalar1 * point;
            let p2 = scalar2 * point;
            let result = p1 + p2;
            let bytes = result.to_canonical_bytes();
            let recovered = ProjectivePoint::from_canonical_bytes(&bytes).unwrap();

            assert_eq!(result, recovered);
        }

        #[test]
        fn test_add_identity() {
            let base_input = BaseFieldElement::try_from(b"test_point".as_slice()).unwrap();
            let point = ProjectivePoint::hash_to_projective_point(&[base_input]).unwrap();
            let identity = ProjectivePoint(JubjubExtended::identity());

            let result = point + identity;

            assert_eq!(result, point);
        }

        #[test]
        fn test_add_commutativity() {
            let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
            let scalar1 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let scalar2 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let base_input = BaseFieldElement::try_from(b"test_point".as_slice()).unwrap();
            let point = ProjectivePoint::hash_to_projective_point(&[base_input]).unwrap();

            let p1 = scalar1 * point;
            let p2 = scalar2 * point;

            assert_eq!(p1 + p2, p2 + p1);
        }

        #[test]
        fn test_add_associativity() {
            let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
            let scalar1 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let scalar2 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let scalar3 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let base_input = BaseFieldElement::try_from(b"test_point".as_slice()).unwrap();
            let point = ProjectivePoint::hash_to_projective_point(&[base_input]).unwrap();

            let p1 = scalar1 * point;
            let p2 = scalar2 * point;
            let p3 = scalar3 * point;

            assert_eq!((p1 + p2) + p3, p1 + (p2 + p3));
        }

        #[test]
        fn test_scalar_mul() {
            let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
            let scalar = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let base_input = BaseFieldElement::try_from(b"test_point".as_slice()).unwrap();
            let point = ProjectivePoint::hash_to_projective_point(&[base_input]).unwrap();

            let result = scalar * point;
            let bytes = result.to_canonical_bytes();
            let recovered = ProjectivePoint::from_canonical_bytes(&bytes).unwrap();

            assert_eq!(result, recovered);
        }

        #[test]
        fn test_scalar_mul_distributivity_over_point_addition() {
            let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
            let scalar = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let base_input1 = BaseFieldElement::try_from(b"test_point_1".as_slice()).unwrap();
            let base_input2 = BaseFieldElement::try_from(b"test_point_2".as_slice()).unwrap();
            let point1 = ProjectivePoint::hash_to_projective_point(&[base_input1]).unwrap();
            let point2 = ProjectivePoint::hash_to_projective_point(&[base_input2]).unwrap();

            let left = scalar * (point1 + point2);
            let right = (scalar * point1) + (scalar * point2);

            assert_eq!(left, right);
        }

        #[test]
        fn test_scalar_mul_associativity() {
            let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
            let scalar1 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let scalar2 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let base_input = BaseFieldElement::try_from(b"test_point".as_slice()).unwrap();
            let point = ProjectivePoint::hash_to_projective_point(&[base_input]).unwrap();

            let combined_scalar = scalar1 * scalar2;
            let left = combined_scalar * point;
            let right = scalar1 * (scalar2 * point);

            assert_eq!(left, right);
        }
    }

    mod prime_order_projective_point_arithmetic {
        use super::*;

        #[test]
        fn test_add() {
            let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
            let scalar1 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let scalar2 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();

            let generator = PrimeOrderProjectivePoint::create_generator();
            let p1 = scalar1 * generator;
            let p2 = scalar2 * generator;

            let result = p1 + p2;

            let bytes = result.to_canonical_bytes();
            let recovered = PrimeOrderProjectivePoint::from_canonical_bytes(&bytes).unwrap();
            assert_eq!(result, recovered);
        }

        #[test]
        fn test_add_identity() {
            let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
            let scalar = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let generator = PrimeOrderProjectivePoint::create_generator();
            let point = scalar * generator;
            let identity = PrimeOrderProjectivePoint::default();

            let result = point + identity;
            assert_eq!(result, point);
        }

        #[test]
        fn test_add_commutativity() {
            let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
            let scalar1 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let scalar2 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();

            let generator = PrimeOrderProjectivePoint::create_generator();
            let p1 = scalar1 * generator;
            let p2 = scalar2 * generator;

            assert_eq!(p1 + p2, p2 + p1);
        }

        #[test]
        fn test_add_associativity() {
            let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
            let scalar1 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let scalar2 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let scalar3 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();

            let generator = PrimeOrderProjectivePoint::create_generator();
            let p1 = scalar1 * generator;
            let p2 = scalar2 * generator;
            let p3 = scalar3 * generator;

            assert_eq!((p1 + p2) + p3, p1 + (p2 + p3));
        }

        #[test]
        fn test_scalar_mul() {
            let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
            let scalar = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let generator = PrimeOrderProjectivePoint::create_generator();

            let result = scalar * generator;

            let bytes = result.to_canonical_bytes();
            let recovered = PrimeOrderProjectivePoint::from_canonical_bytes(&bytes).unwrap();
            assert_eq!(result, recovered);
        }

        #[test]
        fn test_scalar_mul_by_generator() {
            let scalar = ScalarFieldElement(midnight_curves::Fr::one());
            let generator = PrimeOrderProjectivePoint::create_generator();

            let result = scalar * generator;
            assert_eq!(result, generator);
        }

        #[test]
        fn test_scalar_mul_distributivity_over_point_addition() {
            let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
            let scalar = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let scalar1 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let scalar2 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();

            let generator = PrimeOrderProjectivePoint::create_generator();
            let point1 = scalar1 * generator;
            let point2 = scalar2 * generator;

            let left = scalar * (point1 + point2);
            let right = (scalar * point1) + (scalar * point2);

            assert_eq!(left, right);
        }

        #[test]
        fn test_scalar_mul_associativity() {
            let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
            let scalar1 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let scalar2 = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let generator = PrimeOrderProjectivePoint::create_generator();

            let combined_scalar = scalar1 * scalar2;
            let left = combined_scalar * generator;
            let right = scalar1 * (scalar2 * generator);

            assert_eq!(left, right);
        }

        #[test]
        fn test_point_on_curve() {
            let mut rng = ChaCha20Rng::from_seed([14u8; 32]);
            let scalar = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let generator = PrimeOrderProjectivePoint::create_generator();

            let point = scalar * generator;

            let result = point.is_on_curve().unwrap();
            assert_eq!(result, point);
        }
    }

    mod prime_order_point_conversion {
        use super::*;

        #[test]
        fn test_get_from_coordinates() {
            let mut rng = ChaCha20Rng::from_seed([14u8; 32]);
            let scalar = ScalarFieldElement::new_random_nonzero_scalar(&mut rng).unwrap();
            let generator = PrimeOrderProjectivePoint::create_generator();

            let point = scalar * generator;
            let (x, y) = point.get_coordinates();
            let result = PrimeOrderProjectivePoint::from_coordinates(x, y).unwrap();

            assert_eq!(result, point);
        }

        #[test]
        fn test_fail_from_coordinates() {
            let x = BaseFieldElement(JubjubBase::from(1u64));
            let y = BaseFieldElement(JubjubBase::from(5u64));

            let result = PrimeOrderProjectivePoint::from_coordinates(x, y);

            result.expect_err("Random coordinates do not make a point on the curve!");
        }
    }
}
