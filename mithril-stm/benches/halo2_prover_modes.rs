use std::time::Instant;

use mithril_stm::circuits::halo2::bench::helpers::{BenchEnv, compute_circuit_degree};

fn fmt_ms(ms: u128) -> String {
    if ms >= 1000 {
        format!("~{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("~{}ms", ms)
    }
}

/// E2E constant: number of certificates generated in a standard Mithril e2e test run.
/// Derived from the protocol using k=70 or k=140, which produces ~80 certificates.
const E2E_CERT_COUNT: u128 = 80;

struct Tier {
    k: u32,
    m: u32,
}

const TIERS: &[Tier] = &[
    Tier { k: 1, m: 10 },
    Tier { k: 2, m: 20 },
    Tier { k: 5, m: 50 },
    Tier { k: 10, m: 100 },
    Tier { k: 20, m: 200 },
    Tier { k: 50, m: 500 },
    Tier { k: 100, m: 1000 },
];

fn main() {
    println!("mithril-stm halo2_prover_modes — release mode, num_signers = 3000");
    println!();
    println!("E2E formula:");
    println!(
        "  E2E (mock prover) ≈ mock_circuit_gen + {} × mock_prove",
        E2E_CERT_COUNT
    );
    println!("  E2E (real prover) ≈ {} × proof_gen", E2E_CERT_COUNT);
    println!();

    println!(
        "{:<12} {:<4} {:<4} {:<22} {:<22} {:<22} {:<22} {:<22} {:<22} {:<20}",
        "params",
        "k",
        "K",
        "mock_circuit_gen",
        "mock_prove",
        "mock_verify",
        "e2e_mock",
        "proof_gen",
        "proof_verify",
        "e2e_real"
    );
    println!("{}", "-".repeat(180));

    for tier in TIERS {
        let circuit_degree = match compute_circuit_degree(tier.k, tier.m) {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "k={} m={}: failed to compute circuit degree: {e}",
                    tier.k, tier.m
                );
                continue;
            }
        };

        let env = match BenchEnv::new(circuit_degree, tier.k, tier.m) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("k={} m={}: BenchEnv::new failed: {e}", tier.k, tier.m);
                continue;
            }
        };

        let witness = match env.build_witness() {
            Ok(w) => w,
            Err(e) => {
                eprintln!("k={} m={}: build_witness failed: {e}", tier.k, tier.m);
                continue;
            }
        };

        // --- Mock prover ---
        let mock = match env.mock_run(&witness) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("k={} m={}: mock_run failed: {e}", tier.k, tier.m);
                continue;
            }
        };

        let e2e_mock_ms =
            mock.circuit_gen.as_millis() + E2E_CERT_COUNT * mock.mock_prove.as_millis();

        // --- Real prover ---
        let t = Instant::now();
        let proof = match env.prove(&witness) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("k={} m={}: prove failed: {e}", tier.k, tier.m);
                continue;
            }
        };
        let proof_gen = t.elapsed();

        let t = Instant::now();
        if let Err(e) = env.verify(&proof, &witness) {
            eprintln!("k={} m={}: verify failed: {e}", tier.k, tier.m);
            continue;
        }
        let proof_verify = t.elapsed();

        let e2e_real_ms = E2E_CERT_COUNT * proof_gen.as_millis();

        println!(
            "{:<12} {:<4} {:<4} {:<22} {:<22} {:<22} {:<22} {:<22} {:<22} {:<20}",
            format!("k={} m={}", tier.k, tier.m),
            tier.k,
            circuit_degree,
            format!("{:.3?}", mock.circuit_gen),
            format!("{:.3?}", mock.mock_prove),
            format!("{:.3?}", mock.mock_verify),
            fmt_ms(e2e_mock_ms),
            format!("{:.3?}", proof_gen),
            format!("{:.3?}", proof_verify),
            fmt_ms(e2e_real_ms),
        );
    }
}
