mod curve_points;
mod field_elements;
mod poseidon_digest;

pub(crate) use curve_points::*;
pub use field_elements::BaseFieldElement;
pub(crate) use field_elements::ScalarFieldElement;
pub(crate) use poseidon_digest::{
    DOMAIN_SEPARATION_TAG_CIRCUIT_VERIFICATION_KEY_DIGEST, DOMAIN_SEPARATION_TAG_LOTTERY,
    DOMAIN_SEPARATION_TAG_STANDARD_SIGNATURE, DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE,
    compute_poseidon_digest,
};

use serde::{
    de::Visitor,
    {Deserialize, Deserializer, Serialize, Serializer},
};

// ---------------------------------------------------------------------
// Serde implementation
// ---------------------------------------------------------------------

macro_rules! impl_serde {
    ($st:ty,$visitor:ident,$size:expr) => {
        impl Serialize for $st {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                use serde::ser::SerializeTuple;
                let mut seq = serializer.serialize_tuple($size)?;
                for e in self.to_bytes().iter() {
                    seq.serialize_element(e)?;
                }
                seq.end()
            }
        }

        impl<'de> Deserialize<'de> for $st {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct $visitor;

                impl<'de> Visitor<'de> for $visitor {
                    type Value = $st;

                    fn expecting(
                        &self,
                        formatter: &mut ::core::fmt::Formatter,
                    ) -> ::core::fmt::Result {
                        formatter.write_str(format!("a signature {}", stringify!($st)).as_str())
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<$st, A::Error>
                    where
                        A: serde::de::SeqAccess<'de>,
                    {
                        let mut bytes = [0u8; $size];
                        for i in 0..$size {
                            bytes[i] =
                                seq.next_element()?.ok_or(serde::de::Error::invalid_length(
                                    i,
                                    &format!("expected bytes{}", $size.to_string()).as_str(),
                                ))?;
                        }
                        <$st>::from_bytes(&bytes).map_err(|_| {
                            serde::de::Error::custom(
                                &format!("deserialization failed [{}]", stringify!($st)).as_str(),
                            )
                        })
                    }
                }

                deserializer.deserialize_tuple($size, $visitor)
            }
        }
    };
}
impl_serde!(ScalarFieldElement, ScalarFieldElementVisitor, 32);
impl_serde!(BaseFieldElement, BaseFieldElementVisitor, 32);
impl_serde!(
    PrimeOrderProjectivePoint,
    PrimeOrderProjectivePointVisitor,
    32
);
impl_serde!(ProjectivePoint, ProjectivePointVisitor, 32);
