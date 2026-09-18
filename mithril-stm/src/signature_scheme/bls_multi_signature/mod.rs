//! BLST Multi-signature module

mod error;
pub(super) mod helper;
mod proof_of_possession;
mod signature;
mod signing_key;
mod verification_key;

pub use error::*;
pub use proof_of_possession::*;
pub use signature::*;
pub use signing_key::*;
pub use verification_key::*;

use serde::{
    de::Visitor,
    {Deserialize, Deserializer, Serialize, Serializer},
};

/// String used to generate the proofs of possession.
pub(crate) const POP: &[u8] = b"PoP";

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
                        formatter
                            .write_str(format!("a multi signature {}", stringify!($st)).as_str())
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
impl_serde!(BlsSigningKey, SigningKeyVisitor, 32);
impl_serde!(BlsVerificationKey, VerificationKeyVisitor, 96);
impl_serde!(BlsProofOfPossession, ProofOfPossessionVisitor, 96);
impl_serde!(BlsSignature, SignatureVisitor, 48);

#[cfg(test)]
mod tests {
    use blst::{blst_p1, blst_p2};
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    use super::error::BlsSignatureError;
    use super::helper::unsafe_helpers::{p1_affine_to_sig, p2_affine_to_vk};
    use crate::{KeyRegistration, RegisterError, RegistrationEntry};

    use super::*;

    impl PartialEq for BlsSigningKey {
        fn eq(&self, other: &Self) -> bool {
            self.to_blst_secret_key().to_bytes() == other.to_blst_secret_key().to_bytes()
        }
    }

    impl Eq for BlsSigningKey {}

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        #[test]
        fn test_sig(
            msg in prop::collection::vec(any::<u8>(), 1..128),
            seed in any::<[u8;32]>(),
        ) {
            let sk = BlsSigningKey::generate(&mut ChaCha20Rng::from_seed(seed));
            let vk = BlsVerificationKey::from(&sk);
            let sig = sk.sign(&msg);

            sig.verify(&msg, &vk).unwrap();
        }

        #[test]
        fn test_invalid_sig(msg in prop::collection::vec(any::<u8>(), 1..128), seed in any::<[u8;32]>()) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let sk1 = BlsSigningKey::generate(&mut rng);
            let vk1 = BlsVerificationKey::from(&sk1);
            let sk2 = BlsSigningKey::generate(&mut rng);
            let fake_sig = sk2.sign(&msg);

            let error = fake_sig.verify(&msg, &vk1).expect_err("Fake signature should not be verified");

            assert!(
                matches!(
                    error.downcast_ref::<BlsSignatureError>(),
                    Some(BlsSignatureError::SignatureInvalid(_))
                ),
                "Unexpected error: {error:?}");
        }

        #[test]
        fn test_infinity_sig(msg in prop::collection::vec(any::<u8>(), 1..128), seed in any::<[u8;32]>()) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let sk = BlsSigningKey::generate(&mut rng);
            let vk = BlsVerificationKey::from(&sk);

            let p1 = blst_p1::default();
            let sig_infinity = BlsSignature(p1_affine_to_sig(&p1));

            let error = sig_infinity.verify(&msg, &vk).expect_err("Verification should fail");
            assert!(
                matches!(
                    error.downcast_ref::<BlsSignatureError>(),
                    Some(BlsSignatureError::SignatureInfinity(_))
                ),
                "Unexpected error: {error:?}");
        }

        #[test]
        fn test_infinity_vk(seed in any::<[u8;32]>()) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let sk = BlsSigningKey::generate(&mut rng);
            let pop = BlsProofOfPossession::from(&sk);

            let p2 = blst_p2::default();
            let vk_infinity = BlsVerificationKey(p2_affine_to_vk(&p2));
            let vkpop_infinity = BlsVerificationKeyProofOfPossession { vk: vk_infinity, pop };

            let error = vkpop_infinity.verify_proof_of_possession().expect_err("VK pop infinity should fail");
            assert!(
                matches!(
                    error.downcast_ref::<BlsSignatureError>(),
                    Some(BlsSignatureError::VerificationKeyInfinity(_))
                ),
                "Unexpected error: {error:?}");
        }

        #[test]
        fn test_keyreg_with_infinity_vk(num_sigs in 2..16usize, seed in any::<[u8;32]>()) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut kr = KeyRegistration::initialize();

            let sk = BlsSigningKey::generate(&mut rng);
            let pop = BlsProofOfPossession::from(&sk);
            let p2 = blst_p2::default();
            let vk_infinity = BlsVerificationKey(p2_affine_to_vk(&p2));
            let vkpop_infinity = BlsVerificationKeyProofOfPossession { vk: vk_infinity, pop };

            for _ in 0..num_sigs {
                let sk = BlsSigningKey::generate(&mut rng);
                let vkpop = BlsVerificationKeyProofOfPossession::from(&sk);
                let entry = RegistrationEntry::new(vkpop, 1, #[cfg(feature = "future_snark")] None).expect("Registration entry should be created");
                kr.register_by_entry(&entry).expect("Valid VK pop should be registered");
            }
            let error = RegistrationEntry::new(vkpop_infinity, 1, #[cfg(feature = "future_snark")] None).expect_err("Registration entry with VK pop infinity should not be created");
            assert!(
                matches!(
                    error.downcast_ref::<RegisterError>(),
                    Some(RegisterError::ConcatenationKeyInvalid(_))
                ),
                "Unexpected error: {error:?}");
        }

        #[test]
        fn test_aggregate_sig(msg in prop::collection::vec(any::<u8>(), 1..128),
                              num_sigs in 2..16,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut mvks = Vec::new();
            let mut sigs = Vec::new();
            for _ in 0..num_sigs {
                let sk = BlsSigningKey::generate(&mut rng);
                let vk = BlsVerificationKey::from(&sk);
                let sig = sk.sign(&msg);
                assert!(sig.verify(&msg, &vk).is_ok());
                sigs.push(sig);
                mvks.push(vk);
            }

            let result = BlsSignature::verify_aggregate(&msg, &mvks, &sigs);
            assert!(result.is_ok(), "Aggregate verification failed {result:?}");
        }

        #[test]
        fn test_eval_sanity_check(msg in prop::collection::vec(any::<u8>(), 1..128),
                                  idx in any::<u64>(),
                                  seed in any::<[u8;32]>()) {
            let sk = BlsSigningKey::generate(&mut ChaCha20Rng::from_seed(seed));
            let sig = sk.sign(&msg);
            sig.evaluate_dense_mapping(&msg, idx);
        }

        #[test]
        fn serialize_deserialize_vk(seed in any::<u64>()) {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            let sk = BlsSigningKey::generate(&mut rng);
            let vk = BlsVerificationKey::from(&sk);
            let vk_bytes = vk.to_bytes();
            let vk2 = BlsVerificationKey::from_bytes(&vk_bytes).unwrap();
            assert_eq!(vk, vk2);
            let vkpop = BlsVerificationKeyProofOfPossession::from(&sk);
            let vkpop_bytes = vkpop.to_raw_bytes();
            let vkpop2: BlsVerificationKeyProofOfPossession = BlsVerificationKeyProofOfPossession::from_raw_bytes(&vkpop_bytes).unwrap();
            assert_eq!(vkpop, vkpop2);
        }

        #[test]
        fn serialize_deserialize_sk(seed in any::<u64>()) {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            let sk = BlsSigningKey::generate(&mut rng);
            let sk_bytes: [u8; 32] = sk.to_bytes();
            let sk2 = BlsSigningKey::from_bytes(&sk_bytes).unwrap();
            assert_eq!(sk, sk2);
        }
    }

    mod slow {
        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(300))]

            #[test]
            fn batch_verify(num_batches in 2..10usize,
                            seed in any::<[u8;32]>(),
            ) {
                let mut rng = ChaCha20Rng::from_seed(seed);
                let num_sigs = 10;
                let mut batch_msgs = Vec::new();
                let mut batch_vk = Vec::new();
                let mut batch_sig = Vec::new();
                for _ in 0..num_batches {
                    let mut msg = [0u8; 32];
                    rng.fill_bytes(&mut msg);
                    let mut mvks = Vec::new();
                    let mut sigs = Vec::new();
                    for _ in 0..num_sigs {
                        let sk = BlsSigningKey::generate(&mut rng);
                        let vk = BlsVerificationKey::from(&sk);
                        let sig = sk.sign(&msg);
                        sigs.push(sig);
                        mvks.push(vk);
                    }
                    assert!(BlsSignature::verify_aggregate(&msg, &mvks, &sigs).is_ok());
                    let (agg_vk, agg_sig) = BlsSignature::aggregate(&mvks, &sigs).unwrap();
                    batch_msgs.push(msg.to_vec());
                    batch_vk.push(agg_vk);
                    batch_sig.push(agg_sig);
                }
                assert!(BlsSignature::batch_verify_aggregates(&batch_msgs, &batch_vk, &batch_sig).is_ok());

                // If we have an invalid signature, the batch verification will fail
                let mut msg = [0u8; 32];
                rng.fill_bytes(&mut msg);
                let sk = BlsSigningKey::generate(&mut rng);
                let fake_sig = sk.sign(&msg);
                batch_sig[0] = fake_sig;

                let error = BlsSignature::batch_verify_aggregates(&batch_msgs, &batch_vk, &batch_sig).expect_err("Batch verify should fail");
                assert!(
                    matches!(
                        error.downcast_ref::<BlsSignatureError>(),
                        Some(BlsSignatureError::BatchInvalid)
                    ),
                    "Unexpected error: {error:?}"
                );
            }
        }
    }
}
