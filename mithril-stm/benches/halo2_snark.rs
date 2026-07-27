use std::time::Instant;

use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use std::time::Duration;

use mithril_stm::circuits::halo2::bench::helpers::BenchEnv;

struct Tier {
    name: &'static str,
    circuit_degree: u32,
    k: u32,
}

const TIERS: &[Tier] = &[
    Tier {
        name: "small",
        circuit_degree: 13,
        k: 3,
    },
    Tier {
        name: "medium",
        circuit_degree: 16,
        k: 32,
    },
    Tier {
        name: "large",
        circuit_degree: 21,
        k: 1024,
    },
    Tier {
        name: "production",
        circuit_degree: 22,
        k: 1944,
    },
];

/// Returns true if no filter was passed, or if the filter matches `tier`.
///
/// Criterion skips `b.iter()` for non-matching benchmarks but still calls all
/// benchmark functions and their setup code. This guard skips expensive
/// `BenchEnv::new` for tiers that would not be benchmarked anyway.
fn tier_is_selected(tier: &str) -> bool {
    std::env::args()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .map(|filter| filter.contains(tier))
        .unwrap_or(true)
}

/// Criterion-based benchmark for small/medium tiers (10 samples, flat sampling).
fn bench_tier_criterion(c: &mut Criterion, tier: &Tier, measurement_time_secs: u64) {
    let m = tier.k * 10;
    let env = BenchEnv::new(tier.circuit_degree, tier.k, m).expect("BenchEnv::new should not fail");
    env.print_circuit_cost();

    let witness = env.build_witness().expect("build_witness should not fail");
    let proof = env.prove(&witness).expect("prove should not fail");
    println!("VK size: {} bytes", env.vk_size_bytes());
    println!("Proof size: {} bytes", proof.len());

    let group_name = format!("certificate/{}", tier.name);

    let mut slow_group = c.benchmark_group(&group_name);
    slow_group.sampling_mode(SamplingMode::Flat);
    slow_group.sample_size(10);
    slow_group.measurement_time(Duration::from_secs(measurement_time_secs));
    slow_group.bench_function("setup", |b| {
        b.iter(|| env.setup_keys_for_bench());
    });
    slow_group.bench_function("prove", |b| {
        b.iter(|| env.prove(&witness).expect("prove should not fail"));
    });
    slow_group.bench_function("verify", |b| {
        b.iter(|| env.verify(&proof, &witness).expect("verify should not fail"));
    });
    slow_group.finish();
}

/// Single timed run for large/production tiers where 10 Criterion samples would be too costly.
fn bench_tier_single_run(tier: &Tier) {
    let m = tier.k * 10;
    let env = BenchEnv::new(tier.circuit_degree, tier.k, m).expect("BenchEnv::new should not fail");
    env.print_circuit_cost();
    println!("VK size: {} bytes", env.vk_size_bytes());

    let t = Instant::now();
    let _keys = env.setup_keys_for_bench();
    println!("certificate/{}/setup  time: {:?}", tier.name, t.elapsed());

    let witness = env.build_witness().expect("build_witness should not fail");

    let t = Instant::now();
    let proof = env.prove(&witness).expect("prove should not fail");
    println!("certificate/{}/prove  time: {:?}", tier.name, t.elapsed());
    println!("Proof size: {} bytes", proof.len());

    let t = Instant::now();
    env.verify(&proof, &witness).expect("verify should not fail");
    println!("certificate/{}/verify time: {:?}", tier.name, t.elapsed());
}

fn bench_small(c: &mut Criterion) {
    if !tier_is_selected("small") {
        return;
    }
    bench_tier_criterion(c, &TIERS[0], 10);
}

fn bench_medium(c: &mut Criterion) {
    if !tier_is_selected("medium") {
        return;
    }
    bench_tier_criterion(c, &TIERS[1], 60);
}

fn bench_large(_c: &mut Criterion) {
    if !tier_is_selected("large") {
        return;
    }
    bench_tier_single_run(&TIERS[2]);
}

fn bench_production(_c: &mut Criterion) {
    if !tier_is_selected("production") {
        return;
    }
    bench_tier_single_run(&TIERS[3]);
}

criterion_group!(name = benches;
                 config = Criterion::default();
                 targets = bench_small, bench_medium, bench_large, bench_production);
criterion_main!(benches);
