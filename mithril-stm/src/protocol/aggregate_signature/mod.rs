mod aggregate_key;
mod ancillary_data;
mod clerk;
mod error;
mod genesis;
#[cfg(feature = "future_snark")]
mod preimage;
mod signature;

pub use aggregate_key::AggregateVerificationKey;
pub use ancillary_data::{
    AncillaryGenesisData, AncillaryProofInput, AncillaryProofOutput, AncillaryProverData,
    AncillaryVerifierData,
};
pub use clerk::Clerk;
pub use error::{AggregateSignatureError, AggregationError};
pub use genesis::GenesisVerificationKeyBundle;

#[cfg(feature = "future_snark")]
pub use preimage::GenesisMessagePreimage;
pub use signature::{AggregateSignature, AggregateSignatureType};

#[cfg(test)]
mod tests {
    use proptest::{
        collection::{hash_map, vec},
        prelude::*,
        test_runner::{RngAlgorithm::ChaCha, TestRng},
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};
    use std::collections::{HashMap, HashSet};

    use crate::{
        Initializer, KeyRegistration, MithrilMembershipDigest, Parameters, RegistrationEntry,
        Signer, SingleSignature, Stake, StmResult, membership_commitment::MerkleBatchPath,
    };

    use super::{
        AggregateSignature, AggregateSignatureType, AggregateVerificationKey, AggregationError,
        AncillaryProofInput, AncillaryProofOutput, Clerk,
    };

    type Sig = AggregateSignature<D>;
    type D = MithrilMembershipDigest;

    pub(crate) fn setup_equal_parties(params: Parameters, nparties: usize) -> Vec<Signer<D>> {
        let stake = vec![1; nparties];
        setup_parties(params, stake)
    }

    fn setup_equal_parties_with_rng(
        params: Parameters,
        nparties: usize,
        rng: &mut ChaCha20Rng,
    ) -> Vec<Signer<D>> {
        setup_parties_with_rng(params, vec![1; nparties], rng)
    }

    fn setup_parties(params: Parameters, stake: Vec<Stake>) -> Vec<Signer<D>> {
        let mut trng = TestRng::deterministic_rng(ChaCha);
        let mut rng = ChaCha20Rng::from_seed(trng.random());
        setup_parties_with_rng(params, stake, &mut rng)
    }

    fn setup_parties_with_rng(
        params: Parameters,
        stake: Vec<Stake>,
        rng: &mut ChaCha20Rng,
    ) -> Vec<Signer<D>> {
        let mut kr = KeyRegistration::initialize();

        #[allow(clippy::needless_collect)]
        let ps = stake
            .into_iter()
            .map(|stake| {
                let p = Initializer::new(params, stake, rng);
                let entry: RegistrationEntry = p.clone().try_into().unwrap();
                kr.register_by_entry(&entry).unwrap();
                p
            })
            .collect::<Vec<_>>();
        let closed_reg = kr.close_registration(&params).unwrap();
        ps.into_iter()
            .map(|p| p.try_create_signer(&closed_reg.clone()).unwrap())
            .collect()
    }

    #[cfg(feature = "future_snark")]
    pub(crate) fn setup_party_without_snark_keys(params: Parameters, stake: Stake) -> Signer<D> {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let mut initializer = Initializer::new(params, stake, &mut rng);
        initializer.schnorr_signing_key = None;
        initializer.schnorr_verification_key = None;

        let entry: RegistrationEntry = initializer.clone().try_into().unwrap();
        let mut kr = KeyRegistration::initialize();
        kr.register_by_entry(&entry).unwrap();
        let closed_reg = kr.close_registration(&params).unwrap();

        initializer.try_create_signer(&closed_reg).unwrap()
    }

    /// Generate a vector of stakes that should sum to `honest_stake`
    /// when ignoring the indices in `adversaries`
    fn arb_honest_for_adversaries(
        num_parties: usize,
        honest_stake: Stake,
        adversaries: HashMap<usize, Stake>,
    ) -> impl Strategy<Value = Vec<Stake>> {
        vec(1..honest_stake, num_parties).prop_map(move |parties| {
            let honest_sum = parties.iter().enumerate().fold(0, |acc, (i, s)| {
                if !adversaries.contains_key(&i) {
                    acc + s
                } else {
                    acc
                }
            });

            parties
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    if let Some(a) = adversaries.get(&i) {
                        *a
                    } else {
                        (*s * honest_stake) / honest_sum
                    }
                })
                .collect()
        })
    }

    /// Generate a vector of `num_parties` stakes summing to `num_parties * total_stake`,
    /// plus a subset S of 0..num_parties such that the sum of the stakes at indices
    /// in S is adversary_stake * N
    fn arb_parties_with_adversaries(
        num_parties: usize,
        num_adversaries: usize,
        total_stake: Stake,
        adversary_stake: Stake,
    ) -> impl Strategy<Value = (HashSet<usize>, Vec<Stake>)> {
        hash_map(0..num_parties, 1..total_stake, num_adversaries).prop_flat_map(
            move |adversaries| {
                let adversary_sum: Stake = adversaries.values().sum();
                let adversaries_normed = adversaries
                    .iter()
                    .map(|(a, stake)| (*a, (stake * adversary_stake) / adversary_sum))
                    .collect();

                let adversaries = adversaries.into_keys().collect();
                (
                    Just(adversaries),
                    arb_honest_for_adversaries(
                        num_parties,
                        total_stake - adversary_stake,
                        adversaries_normed,
                    ),
                )
            },
        )
    }

    fn find_signatures(msg: &[u8], ps: &[Signer<D>], is: &[usize]) -> Vec<SingleSignature> {
        let mut sigs = Vec::new();
        for i in is {
            if let Ok(sig) = ps[*i].create_single_signature(msg) {
                sigs.push(sig);
            }
        }
        sigs
    }

    /// Pick N between min and max, and then
    /// generate a vector of N stakes summing to N * tstake,
    /// plus a subset S of 0..N such that the sum of the stakes at indices
    /// in S is astake * N
    fn arb_parties_adversary_stake(
        min: usize,
        max: usize,
        tstake: Stake,
        astake: Stake,
    ) -> impl Strategy<Value = (HashSet<usize>, Vec<Stake>)> {
        (min..max)
            .prop_flat_map(|n| (Just(n), 1..=n / 2))
            .prop_flat_map(move |(n, nadv)| {
                arb_parties_with_adversaries(n, nadv, tstake * n as Stake, astake * n as Stake)
            })
    }

    #[derive(Debug)]
    struct ProofTest {
        msig: StmResult<(Sig, AncillaryProofOutput)>,
        clerk: Clerk<D>,
        msg: [u8; 16],
    }
    /// Run the protocol up to aggregation. This will produce a valid aggregation of signatures.
    /// The following tests mutate this aggregation so that the proof is no longer valid.
    fn arb_proof_setup(max_parties: usize) -> impl Strategy<Value = ProofTest> {
        any::<[u8; 16]>().prop_flat_map(move |msg| {
            (2..max_parties).prop_map(move |n| {
                let params = Parameters {
                    m: 5,
                    k: 5,
                    phi_f: 1.0,
                };
                let ps = setup_equal_parties(params, n);
                let clerk = Clerk::new_clerk_from_signer(&ps[0]);

                let all_ps: Vec<usize> = (0..n).collect();
                let sigs = find_signatures(&msg, &ps, &all_ps);

                let aggr_sig_type = AggregateSignatureType::Concatenation;
                let msig = clerk.aggregate_signatures_with_type(
                    &sigs,
                    &msg,
                    aggr_sig_type,
                    AncillaryProofInput::dummy(),
                );
                ProofTest { msig, clerk, msg }
            })
        })
    }

    fn with_proof_mod<F>(mut tc: ProofTest, f: F)
    where
        F: Fn(&mut Sig, &mut Clerk<D>, &mut [u8; 16]),
    {
        match tc.msig {
            Ok((mut aggr, ancillary_proof_output)) => {
                f(&mut aggr, &mut tc.clerk, &mut tc.msg);
                assert!(
                    aggr.verify(
                        &tc.msg,
                        &tc.clerk.compute_aggregate_verification_key(),
                        &tc.clerk.get_concatenation_clerk().parameters,
                        ancillary_proof_output.verifier_data().cloned(),
                        None,
                    )
                    .is_err()
                )
            }
            Err(e) => unreachable!("Reached an unexpected error: {:?}", e),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5))]

        #[test]
        /// Test that when a quorum is found, the aggregate signature can be verified by anyone with
        /// access to the avk and the parameters.
        fn test_aggregate_sig(nparties in 2_usize..30,
                              m in 10_u64..20,
                              k in 1_u64..5,
                              msg in any::<[u8; 16]>()) {
            let params = Parameters { m, k, phi_f: 0.2 };
            let ps = setup_equal_parties(params, nparties);
            let clerk = Clerk::new_clerk_from_signer(&ps[0]);
            let aggr_sig_type = AggregateSignatureType::Concatenation;

            let all_ps: Vec<usize> = (0..nparties).collect();
            let sigs = find_signatures(&msg, &ps, &all_ps);
            let msig = clerk.aggregate_signatures_with_type(&sigs, &msg, aggr_sig_type, AncillaryProofInput::dummy());

            match msig {
                Ok((aggr, ancillary_proof_output)) => {
                    println!("Aggregate ok");
                    assert!(aggr.verify(&msg, &clerk.compute_aggregate_verification_key(), &params, ancillary_proof_output.verifier_data().cloned(), None).is_ok());
                }
                Err(error) => match error.downcast_ref::<AggregationError>() {
                    Some(AggregationError::NotEnoughSignatures(n, k)) => {
                        println!("Not enough signatures");
                        assert!(n < &params.k && k == &params.k)
                    },
                    Some(AggregationError::UnsupportedProofSystem(aggregate_signature_type)) => {
                        panic!("Unsupported proof system: {:?}", aggregate_signature_type);
                    },
                    _ => {
                        panic!("Unexpected error during aggregation: {:?}", error);
                    }
                },
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        #[test]
        /// Test that when a party creates a signature it can be verified
        fn test_sig(msg in any::<[u8;16]>()) {
            let params = Parameters { m: 1, k: 1, phi_f: 0.2 };
            let ps = setup_equal_parties(params, 1);
            let clerk = Clerk::new_clerk_from_signer(&ps[0]);
            let avk: AggregateVerificationKey<D> = clerk.compute_aggregate_verification_key();

            if let Ok(sig) = ps[0].create_single_signature(&msg) {
                assert!(sig.verify(&params, &ps[0].get_bls_verification_key(), &ps[0].concatenation_proof_signer.stake, &avk, &msg, #[cfg(feature = "future_snark")] None).is_ok());
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]
        #[test]
        fn test_parameters_serialize_deserialize(m in any::<u64>(), k in any::<u64>(), phi_f in any::<f64>()) {
            let params = Parameters { m, k, phi_f };

            let bytes = params.to_bytes().expect("Parameters serialization should not fail");
            let deserialised = Parameters::from_bytes(&bytes);
            assert!(deserialised.is_ok())
        }

        #[test]
        fn test_initializer_serialize_deserialize(seed in any::<[u8;32]>()) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let params = Parameters { m: 1, k: 1, phi_f: 1.0 };
            let stake = rng.next_u64();
            let initializer = Initializer::new(params, stake, &mut rng);

            let bytes = initializer.to_bytes().expect("Initializer serialization should not fail");
            assert!(Initializer::from_bytes(&bytes).is_ok());
        }

        #[test]
        fn test_sig_serialize_deserialize(msg in any::<[u8;16]>()) {
            let params = Parameters { m: 1, k: 1, phi_f: 0.2 };
            let ps = setup_equal_parties(params, 1);
            let clerk = Clerk::new_clerk_from_signer(&ps[0]);
            let avk: AggregateVerificationKey<D> = clerk.compute_aggregate_verification_key();

            if let Ok(sig) = ps[0].create_single_signature(&msg) {
                let bytes = sig.to_bytes().expect("SingleSignature serialization should not fail");
                let sig_deser = SingleSignature::from_bytes::<D>(&bytes).unwrap();
                assert!(sig_deser.verify(&params, &ps[0].get_bls_verification_key(), &ps[0].concatenation_proof_signer.stake, &avk, &msg, #[cfg(feature = "future_snark")] None).is_ok());
            }
        }

        #[test]
        fn test_multisig_serialize_deserialize(nparties in 2_usize..10,
                                          msg in any::<[u8;16]>()) {
            let params = Parameters { m: 10, k: 5, phi_f: 1.0 };
            let ps = setup_equal_parties(params, nparties);
            let clerk = Clerk::new_clerk_from_signer(&ps[0]);
            let aggr_sig_type = AggregateSignatureType::Concatenation;

            let all_ps: Vec<usize> = (0..nparties).collect();
            let sigs = find_signatures(&msg, &ps, &all_ps);
            let msig = clerk.aggregate_signatures_with_type(&sigs, &msg, aggr_sig_type, AncillaryProofInput::dummy());
            if let Ok((aggr, ancillary_proof_output)) = msig {
                    let bytes: Vec<u8> = aggr.to_bytes().expect("AggregateSignature serialization should not fail");
                    let aggr2: AggregateSignature<D> = AggregateSignature::from_bytes(&bytes).unwrap();
                    assert!(aggr2.verify(&msg, &clerk.compute_aggregate_verification_key(), &params, ancillary_proof_output.verifier_data().cloned(), None).is_ok());
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        // Each of the tests below corresponds to falsifying a conjunct in the
        // definition of a valid signature
        #[test]
        fn test_invalid_proof_quorum(tc in arb_proof_setup(10)) {
            with_proof_mod(tc, |_aggr, clerk, _msg| {
                clerk.update_k(clerk.get_concatenation_clerk().parameters.k + 7);
            })
        }
        // todo: fn test_invalid_proof_individual_sig
        #[test]
        fn test_invalid_proof_index_bound(tc in arb_proof_setup(10)) {
            with_proof_mod(tc, |_aggr, clerk, _msg| {
                clerk.update_m(1);
            })
        }

        #[test]
        fn test_invalid_proof_index_unique(tc in arb_proof_setup(10)) {
            with_proof_mod(tc, |aggr, clerk, _msg| {
                let mut concatenation_proof = AggregateSignature::to_concatenation_proof(aggr).unwrap().to_owned();
                for sig_reg in concatenation_proof.signatures.iter_mut() {
                    let mut new_indices = sig_reg.sig.get_concatenation_signature_indices();
                    for index in new_indices.iter_mut() {
                        *index %= clerk.get_concatenation_clerk().parameters.k - 1
                    }
                    sig_reg.sig.set_concatenation_signature_indices(&new_indices);
                }
                *aggr = AggregateSignature::Concatenation(Box::new(concatenation_proof));
            })
        }

        #[test]
        fn test_invalid_proof_path(tc in arb_proof_setup(10)) {
            with_proof_mod(tc, |aggr, _, _msg| {
                let mut concatenation_proof = AggregateSignature::to_concatenation_proof(aggr).unwrap().to_owned();
                let p = concatenation_proof.batch_proof.clone();
                let mut index_list = p.indices.clone();
                let values = p.values;
                let batch_proof = {
                    index_list[0] += 1;
                    MerkleBatchPath {
                        values,
                        indices: index_list,
                        hasher: Default::default()
                    }
                };
                concatenation_proof.batch_proof = batch_proof;
                *aggr = AggregateSignature::Concatenation(Box::new(concatenation_proof));
            })
        }
    }

    mod slow {
        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(5))]

            #[test]
            /// Test that batch verification of certificates works
            fn batch_verify(nparties in 2_usize..15,
                                  m in 10_u64..20,
                                  k in 1_u64..4,
                                  seed in any::<[u8;32]>(),
                                  batch_size in 2..10,
            ) {
                let aggr_sig_type = AggregateSignatureType::Concatenation;
                let mut rng = ChaCha20Rng::from_seed(seed);
                let mut aggr_avks: Vec<AggregateVerificationKey<D>> = Vec::new();
                let mut aggr_stms = Vec::new();
                let mut batch_msgs = Vec::new();
                let mut batch_params = Vec::new();
                let mut batch_ancillary_verifier_datas = Vec::new();
                let mut batch_genesis_verification_key_bundles = Vec::new();
                for _ in 0..batch_size {
                    let mut msg = [0u8; 32];
                    rng.fill_bytes(&mut msg);
                    let params = Parameters { m, k, phi_f: 0.95 };
                    let ps = setup_equal_parties_with_rng(params, nparties, &mut rng);
                    let clerk = Clerk::new_clerk_from_signer(&ps[0]);

                    let all_ps: Vec<usize> = (0..nparties).collect();
                    let sigs = find_signatures(&msg, &ps, &all_ps);
                    let msig = clerk.aggregate_signatures_with_type(&sigs, &msg, aggr_sig_type, AncillaryProofInput::dummy());

                    match msig {
                        Ok((aggr, ancillary_proof_output)) => {
                            aggr_avks.push(clerk.compute_aggregate_verification_key());
                            aggr_stms.push(aggr);
                            batch_msgs.push(msg.to_vec());
                            batch_params.push(params);
                            batch_ancillary_verifier_datas.push(ancillary_proof_output.verifier_data().cloned());
                            batch_genesis_verification_key_bundles.push(None);
                        }
                        Err(error) => { assert!(
                            matches!(
                                error.downcast_ref::<AggregationError>(),
                                Some(AggregationError::NotEnoughSignatures{..})
                            ),
                            "Unexpected error: {error:?}");
                        }
                    }
                }

                assert!(AggregateSignature::batch_verify(&aggr_stms, &batch_msgs, &aggr_avks, &batch_params, &batch_ancillary_verifier_datas, &batch_genesis_verification_key_bundles).is_ok());

                if aggr_stms.len() >= 2 {
                    let mut swapped_msgs = batch_msgs.clone();
                    swapped_msgs.swap(0, 1);
                    assert!(
                        AggregateSignature::batch_verify(&aggr_stms, &swapped_msgs, &aggr_avks, &batch_params, &batch_ancillary_verifier_datas, &batch_genesis_verification_key_bundles).is_err(),
                        "Batch verify should reject swapped messages"
                    );

                    let wrong_avk = {
                        let wrong_params = Parameters { m, k, phi_f: 0.95 };
                        let mut rng_wrong = ChaCha20Rng::from_seed([0xdeu8; 32]);
                        let mut kr = KeyRegistration::initialize();
                        let p = Initializer::new(wrong_params, 1 as Stake, &mut rng_wrong);
                        let entry: RegistrationEntry = p.clone().try_into().unwrap();
                        kr.register_by_entry(&entry).unwrap();
                        let closed_reg = kr.close_registration(&wrong_params).unwrap();
                        AggregateVerificationKey::from(&closed_reg)
                    };
                    let mut wrong_avks = aggr_avks.clone();
                    wrong_avks[0] = wrong_avk;
                    assert!(
                        AggregateSignature::batch_verify(&aggr_stms, &batch_msgs, &wrong_avks, &batch_params, &batch_ancillary_verifier_datas, &batch_genesis_verification_key_bundles).is_err(),
                        "Batch verify should reject a wrong avk"
                    );
                }

                let mut msg = [0u8; 32];
                rng.fill_bytes(&mut msg);
                let params = Parameters { m, k, phi_f: 0.8 };
                let ps = setup_equal_parties(params, nparties);
                let clerk = Clerk::new_clerk_from_signer(&ps[0]);

                let all_ps: Vec<usize> = (0..nparties).collect();
                let sigs = find_signatures(&msg, &ps, &all_ps);
                let (fake_msig, _ancillary_proof_output) = clerk.aggregate_signatures_with_type(&sigs, &msg, aggr_sig_type, AncillaryProofInput::dummy()).unwrap();

                aggr_stms[0] = fake_msig;
                assert!(AggregateSignature::batch_verify(&aggr_stms, &batch_msgs, &aggr_avks, &batch_params, &batch_ancillary_verifier_datas, &batch_genesis_verification_key_bundles).is_err());
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(5))]

            #[test]
            /// Test that when the adversaries do not hold sufficient stake, they can not form a quorum
            fn test_adversary_quorum(
                (adversaries, parties) in arb_parties_adversary_stake(4, 15, 16, 4),
                msg in any::<[u8;16]>(),
            ) {
                // Test sanity check:
                // Check that the adversarial party has less than 40% of the total stake.
                let (good, bad) = parties.iter().enumerate().fold((0,0), |(acc1, acc2), (i, st)| {
                    if adversaries.contains(&i) {
                        (acc1, acc2 + *st)
                    } else {
                        (acc1 + *st, acc2)
                    }
                });
                assert!(bad as f64 / ((good + bad) as f64) < 0.4);

                let params = Parameters { m: 2642, k: 357, phi_f: 0.2 }; // From Table 1
                let ps = setup_parties(params, parties);

                let sigs =  find_signatures(&msg, &ps, &adversaries.into_iter().collect::<Vec<_>>());

                assert!(sigs.len() < params.k as usize);

                let clerk = Clerk::new_clerk_from_signer(&ps[0]);
                let aggr_sig_type = AggregateSignatureType::Concatenation;

                let error = clerk.aggregate_signatures_with_type(&sigs, &msg, aggr_sig_type, AncillaryProofInput::dummy()).expect_err("Not enough quorum should fail!");
                assert!(
                    matches!(
                        error.downcast_ref::<AggregationError>(),
                        Some(AggregationError::NotEnoughSignatures{..})
                    ),
                    "Unexpected error: {error:?}"
                );
            }
        }
    }
}
