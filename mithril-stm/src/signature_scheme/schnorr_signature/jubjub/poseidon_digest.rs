use midnight_circuits::{hash::poseidon::PoseidonChip, instructions::hash::HashCPU};
use midnight_curves::Fq as JubjubBase;

use super::BaseFieldElement;

/// Domain Separation Tag (DST) for the Poseidon hash used in unique signature contexts.
pub(crate) const DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE: BaseFieldElement =
    BaseFieldElement(JubjubBase::from_raw([
        0x5349_474E_5F44_5354, // "SIGN_DST" (ASCII), little-endian u64
        0,
        0,
        0,
    ]));

/// Domain Separation Tag (DST) for the Poseidon hash used in standard signature contexts.
pub(crate) const DOMAIN_SEPARATION_TAG_STANDARD_SIGNATURE: BaseFieldElement =
    BaseFieldElement(JubjubBase::from_raw([
        0x5354_4453_5F44_5354, // "STDS_DST" (ASCII), little-endian u64
        0,
        0,
        0,
    ]));

/// Domain Separation Tag (DST) for the lottery check. It is used as a prefix when computing
/// the eligibility value of a signature.
pub const DOMAIN_SEPARATION_TAG_LOTTERY: BaseFieldElement =
    BaseFieldElement(JubjubBase::from_raw([
        0x4C4F_5454_5F44_5354, // "LOTT_DST" (ASCII), little-endian u64
        0,
        0,
        0,
    ]));

/// Computes a Poseidon digest over the provided base field elements.
/// Returns a base field element as the digest.
pub(crate) fn compute_poseidon_digest(input: &[BaseFieldElement]) -> BaseFieldElement {
    let poseidon_input: Vec<JubjubBase> = input.iter().map(|i| i.0).collect();

    BaseFieldElement(PoseidonChip::<JubjubBase>::hash(&poseidon_input))
}

#[cfg(test)]
mod test {
    use super::{
        DOMAIN_SEPARATION_TAG_LOTTERY, DOMAIN_SEPARATION_TAG_STANDARD_SIGNATURE,
        DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE,
    };

    #[test]
    fn domain_separation_tags_are_pairwise_distinct() {
        assert_ne!(
            DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE,
            DOMAIN_SEPARATION_TAG_STANDARD_SIGNATURE
        );
        assert_ne!(
            DOMAIN_SEPARATION_TAG_UNIQUE_SIGNATURE,
            DOMAIN_SEPARATION_TAG_LOTTERY
        );
        assert_ne!(
            DOMAIN_SEPARATION_TAG_STANDARD_SIGNATURE,
            DOMAIN_SEPARATION_TAG_LOTTERY
        );
    }

    mod golden {
        use ff::Field;
        use midnight_curves::Fq as JubjubBase;
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;

        use crate::signature_scheme::{BaseFieldElement, compute_poseidon_digest};

        const GOLDEN_BYTES: &[u8; 32] = &[
            168, 249, 251, 86, 251, 84, 26, 25, 244, 24, 31, 5, 153, 234, 64, 53, 32, 67, 114, 26,
            250, 90, 108, 196, 47, 25, 60, 234, 221, 176, 255, 92,
        ];

        fn golden_value() -> BaseFieldElement {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let input = JubjubBase::random(rng);
            compute_poseidon_digest(&[BaseFieldElement(input)])
        }

        #[test]
        fn golden_hash() {
            let value = BaseFieldElement::from_bytes(GOLDEN_BYTES)
                .expect("This from bytes should not fail");
            assert_eq!(golden_value(), value);
        }
    }
}
