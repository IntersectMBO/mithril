use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rayon::prelude::*;

use mithril_stm::{
    AggregateSignature, AggregateSignatureType, AncillaryGenesisData, AncillaryProofInput, Clerk,
    Initializer, KeyRegistration, MembershipDigest, MithrilMembershipDigest, Parameters, Signer,
};

/// This benchmark framework is not ideal. We really have to think what is the best mechanism for
/// benchmarking these signatures, over which parameters, how many times to run them, etc:
/// * Registration depends on the number of parties (should be constant, as it is a lookup table)
/// * Signing depends on the parameter `m`, as it defines the number of lotteries a user can play
/// * Aggregation depends on `k`.
fn stm_benches<D: MembershipDigest>(
    c: &mut Criterion,
    nr_parties: usize,
    params: Parameters,
    hashing_alg: &str,
) {
    let mut group = c.benchmark_group(format!("STM/{hashing_alg}"));
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut msg = [0u8; 16];
    rng.fill_bytes(&mut msg);

    let param_string = format!(
        "k: {}, m: {}, nr_parties: {}",
        params.k, params.m, nr_parties
    );

    let stakes = (0..nr_parties)
        .map(|_| 1 + (rng.next_u64() % 9999))
        .collect::<Vec<_>>();

    let mut initializers: Vec<Initializer> = Vec::with_capacity(nr_parties);
    for stake in stakes {
        initializers.push(Initializer::new(params, stake, &mut rng));
    }
    let mut key_reg = KeyRegistration::initialize();

    group.bench_function(BenchmarkId::new("Key registration", &param_string), |b| {
        b.iter(|| {
            // We need to initialise the key_reg at each iteration
            key_reg = KeyRegistration::initialize();
            for p in initializers.iter() {
                key_reg
                    .register(
                        p.stake,
                        &p.get_verification_key_proof_of_possession_for_concatenation(),
                        #[cfg(feature = "future_snark")]
                        p.schnorr_verification_key,
                    )
                    .unwrap();
            }
        })
    });

    let closed_reg = key_reg.close_registration(&params).unwrap();

    let signers: Vec<Signer<D>> = initializers
        .into_par_iter()
        .map(|p| p.try_create_signer(&closed_reg).unwrap())
        .collect();

    group.bench_function(BenchmarkId::new("Play all lotteries", &param_string), |b| {
        b.iter(|| {
            signers[0].create_single_signature(&msg).unwrap();
        })
    });

    let sigs = signers
        .par_iter()
        .filter_map(|p| p.create_single_signature(&msg).ok())
        .collect::<Vec<_>>();
    let clerk = Clerk::new_clerk_from_signer(&signers[0]);
    let aggregate_signature_type = AggregateSignatureType::Concatenation;

    group.bench_function(BenchmarkId::new("Aggregation", &param_string), |b| {
        b.iter(|| {
            clerk.aggregate_signatures_with_type(
                &sigs,
                &msg,
                aggregate_signature_type,
                AncillaryProofInput::new(
                    None,
                    AncillaryGenesisData::new(
                        #[cfg(feature = "future_snark")]
                        Vec::new(),
                        #[cfg(feature = "future_snark")]
                        None,
                        #[cfg(feature = "future_snark")]
                        None,
                    ),
                    #[cfg(feature = "future_snark")]
                    Vec::new(),
                ),
            )
        })
    });
}

fn batch_benches<D>(
    c: &mut Criterion,
    array_batches: &[usize],
    nr_parties: usize,
    params: Parameters,
    hashing_alg: &str,
) where
    D: MembershipDigest,
{
    let mut group = c.benchmark_group(format!("STM/{hashing_alg}"));
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let param_string = format!(
        "k: {}, m: {}, nr_parties: {}",
        params.k, params.m, nr_parties
    );

    for &nr_batches in array_batches {
        let batch_string = format!("{param_string}/batch size: {nr_batches}");

        let mut batch_msgs = Vec::with_capacity(nr_batches);
        let mut batch_params = Vec::with_capacity(nr_batches);
        let mut batch_stms: Vec<AggregateSignature<D>> = Vec::with_capacity(nr_batches);
        let mut batch_avks = Vec::with_capacity(nr_batches);
        let mut batch_ancillary_verifier_datas = Vec::with_capacity(nr_batches);
        let mut batch_genesis_verification_key_bundles = Vec::with_capacity(nr_batches);

        for _ in 0..nr_batches {
            let mut msg = [0u8; 32];
            rng.fill_bytes(&mut msg);
            batch_msgs.push(msg.to_vec());
            batch_params.push(params);

            let stakes = (0..nr_parties)
                .map(|_| 1 + (rng.next_u64() % 9999))
                .collect::<Vec<_>>();

            let mut initializers: Vec<Initializer> = Vec::with_capacity(nr_parties);
            for stake in stakes {
                initializers.push(Initializer::new(params, stake, &mut rng));
            }
            let mut key_reg = KeyRegistration::initialize();
            for p in initializers.iter() {
                key_reg
                    .register(
                        p.stake,
                        &p.get_verification_key_proof_of_possession_for_concatenation(),
                        #[cfg(feature = "future_snark")]
                        p.schnorr_verification_key,
                    )
                    .unwrap();
            }

            let closed_reg = key_reg.close_registration(&params).unwrap();

            let signers = initializers
                .into_par_iter()
                .map(|p| p.try_create_signer(&closed_reg).unwrap())
                .collect::<Vec<Signer<D>>>();

            let sigs = signers
                .par_iter()
                .filter_map(|p| p.create_single_signature(&msg).ok())
                .collect::<Vec<_>>();

            let clerk = Clerk::new_clerk_from_signer(&signers[0]);
            let aggregate_signature_type = AggregateSignatureType::Concatenation;
            let (msig, ancillary_proof_output) = clerk
                .aggregate_signatures_with_type(
                    &sigs,
                    &msg,
                    aggregate_signature_type,
                    AncillaryProofInput::new(
                        None,
                        AncillaryGenesisData::new(
                            #[cfg(feature = "future_snark")]
                            Vec::new(),
                            #[cfg(feature = "future_snark")]
                            None,
                            #[cfg(feature = "future_snark")]
                            None,
                        ),
                        #[cfg(feature = "future_snark")]
                        Vec::new(),
                    ),
                )
                .unwrap();

            batch_avks.push(clerk.compute_aggregate_verification_key());
            batch_stms.push(msig);
            batch_ancillary_verifier_datas.push(ancillary_proof_output.verifier_data().cloned());
            batch_genesis_verification_key_bundles.push(None);
        }

        group.bench_function(BenchmarkId::new("Batch Verification", batch_string), |b| {
            b.iter(|| {
                AggregateSignature::batch_verify(
                    &batch_stms,
                    &batch_msgs,
                    &batch_avks,
                    &batch_params,
                    &batch_ancillary_verifier_datas,
                    &batch_genesis_verification_key_bundles,
                )
                .is_ok()
            })
        });
    }
}

fn batch_stm_benches_blake_300(c: &mut Criterion) {
    batch_benches::<MithrilMembershipDigest>(
        c,
        &[1, 10, 20, 100],
        300,
        Parameters {
            m: 150,
            k: 25,
            phi_f: 0.4,
        },
        "Blake2b",
    );
}

fn stm_benches_blake_300(c: &mut Criterion) {
    stm_benches::<MithrilMembershipDigest>(
        c,
        300,
        Parameters {
            m: 150,
            k: 25,
            phi_f: 0.2,
        },
        "Blake2b",
    );
}

fn batch_stm_benches_blake_2000(c: &mut Criterion) {
    batch_benches::<MithrilMembershipDigest>(
        c,
        &[1, 10, 20, 100],
        2000,
        Parameters {
            m: 1523,
            k: 250,
            phi_f: 0.4,
        },
        "Blake2b",
    );
}

fn stm_benches_blake_2000(c: &mut Criterion) {
    stm_benches::<MithrilMembershipDigest>(
        c,
        2000,
        Parameters {
            m: 1523,
            k: 250,
            phi_f: 0.2,
        },
        "Blake2b",
    );
}

criterion_group!(name = benches;
                 config = Criterion::default().nresamples(1000);
                 targets =
    stm_benches_blake_300,
    stm_benches_blake_2000,
    batch_stm_benches_blake_300,
    batch_stm_benches_blake_2000,
);
criterion_main!(benches);
