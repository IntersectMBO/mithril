use blake2::{Blake2b, Digest, digest::consts::U64};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use mithril_stm::{BlsSignature, BlsSigningKey, BlsVerificationKey};

fn batch_benches(c: &mut Criterion, array_batches: &[usize], nr_sigs: usize) {
    let mut group = c.benchmark_group("MultiSig".to_string());
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut batch_msgs = Vec::new();
    let mut batch_vk = Vec::new();
    let mut batch_sig = Vec::new();

    for &nr_batches in array_batches {
        let batch_string = format!("Batch size: {nr_batches}");

        for _ in 0..nr_batches {
            let mut msg = [0u8; 32];
            rng.fill_bytes(&mut msg);
            let mut mvks = Vec::new();
            let mut sigs = Vec::new();
            for _ in 0..nr_sigs {
                let sk = BlsSigningKey::generate(&mut rng);
                let vk = BlsVerificationKey::from(&sk);
                let sig = sk.sign(&msg);
                sigs.push(sig);
                mvks.push(vk);
            }
            let (agg_vk, agg_sig) = BlsSignature::aggregate(&mvks, &sigs).unwrap();
            batch_msgs.push(msg.to_vec());
            batch_vk.push(agg_vk);
            batch_sig.push(agg_sig);
        }

        group.bench_function(BenchmarkId::new("Batch Verification", batch_string), |b| {
            b.iter(|| {
                BlsSignature::batch_verify_aggregates(&batch_msgs, &batch_vk, &batch_sig).is_ok()
            })
        });
    }
}

fn aggregate_and_verify(c: &mut Criterion, nr_sigs: usize) {
    let mut group = c.benchmark_group("BLS".to_string());
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);
    let mut mvks = Vec::new();
    let mut msks = Vec::new();
    let mut sigs = Vec::new();
    for _ in 0..nr_sigs {
        let sk = BlsSigningKey::generate(&mut rng);
        let vk = BlsVerificationKey::from(&sk);
        let sig = sk.sign(&msg);
        sigs.push(sig);
        msks.push(sk);
        mvks.push(vk);
    }

    group.bench_function(BenchmarkId::new("Signature", nr_sigs), |b| {
        b.iter(|| {
            for sk in msks.iter() {
                let _ = sk.sign(&msg);
            }
        })
    });

    group.bench_function(BenchmarkId::new("Verification", nr_sigs), |b| {
        b.iter(|| {
            for (vk, sig) in mvks.iter().zip(sigs.iter()) {
                assert!(sig.verify(&msg, vk).is_ok());
            }
        })
    });

    group.bench_function(BenchmarkId::new("Batch Verification", nr_sigs), |b| {
        b.iter(|| {
            for sig in sigs.iter() {
                let mut hasher = Blake2b::<U64>::new();
                hasher.update(sig.to_raw_bytes());
                hasher.finalize();
            }
            let (agg_vk, agg_sig) = BlsSignature::aggregate(&mvks, &sigs).unwrap();
            assert!(agg_sig.verify(&msg, &agg_vk).is_ok())
        })
    });
}

fn batch_multi_sig_benches(c: &mut Criterion) {
    batch_benches(c, &[1, 10, 20, 50, 100], 300);
}
fn batch_bls_benches(c: &mut Criterion) {
    aggregate_and_verify(c, 1000);
}

criterion_group!(name = benches;
                 config = Criterion::default().nresamples(1000);
                 targets =
    batch_multi_sig_benches,
    batch_bls_benches
);
criterion_main!(benches);
