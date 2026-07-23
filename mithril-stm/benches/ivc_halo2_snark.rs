//! Benchmarks for the recursive IVC circuit, driven end-to-end by the production-backed
//! [`IvcBenchEnv`] façade (`mithril-stm/src/circuits/halo2_ivc/bench_helpers.rs`). Every timed operation
//! delegates to the façade, so the measurements exercise the same code paths run in production.
//!
//! ## Running
//!
//! ```text
//! cargo bench -p mithril-stm --features future_snark,benchmark-internals --bench ivc_halo2_snark -- <id-or-prefix>
//! ```
//!
//! `<id-or-prefix>` is a single **literal** substring of a benchmark id (e.g. `ivc/same_epoch/prove` or
//! `ivc/genesis/prove/poseidon`). Run `--list` to print the ids.
//!
//! ## CLI contract (restricted, fail-closed)
//!
//! Every benchmark is *manually timed* — a single observation each, gathered into consolidated tables (a
//! per-path prove/verify/fold table and a setup cold-vs-warm table) — because a recursive proof at
//! `RECURSIVE_CIRCUIT_DEGREE` costs tens of seconds and building an environment runs a full recursive
//! keygen (minutes, GB-scale RAM). So the harness validates its CLI itself, up front, before constructing
//! anything:
//!
//! - `--list` prints every benchmark id and returns — it never builds the environment (no keygen).
//! - `--test` and `--profile-time` are rejected: they would force a full recursive keygen for the shared
//!   environment. Use the façade's `#[ignore]` smoke test (`facade_prepares_proves_and_verifies_all_paths`)
//!   for a once-through sanity run instead.
//! - Only a few valueless flags (`--bench`, `--verbose`, `--quiet`, `--nocapture`) plus the control flags
//!   above are accepted; every other option — including value-taking ones — is rejected, so nothing can
//!   swallow the next token. A single literal positional filter is allowed (no regex, no `--exact`).

use std::hint::black_box;
use std::time::{Duration, Instant};

use mithril_stm::circuits::halo2_ivc::{
    bench_cli::{self, BenchCli},
    bench_helpers::{IvcBenchEnv, PreparedStep, TransitionPath},
};
use tempfile::TempDir;

/// The three transition paths and their id segments.
const PATHS: &[(TransitionPath, &str)] = &[
    (TransitionPath::Genesis, "genesis"),
    (TransitionPath::SameEpoch, "same_epoch"),
    (TransitionPath::NextEpoch, "next_epoch"),
];

fn die(message: &str) -> ! {
    eprintln!("ivc_halo2_snark: {message}");
    std::process::exit(2);
}

/// All benchmark ids for one transition path. Genesis has no accumulator fold (passthrough).
fn ids_for(path: TransitionPath, name: &str) -> Vec<String> {
    let mut ids = vec![
        format!("ivc/{name}/prove/poseidon"),
        format!("ivc/{name}/prove/blake2b"),
        format!("ivc/{name}/verify/full"),
        format!("ivc/{name}/verify/kzg_opening"),
    ];
    if !matches!(path, TransitionPath::Genesis) {
        ids.push(format!("ivc/{name}/fold"));
    }
    ids
}

/// Setup cold/warm benchmark ids (item 8). Each measures its cache **cold then warm**; they build their
/// own throwaway caches and do NOT use the shared per-path environment.
const SETUP_IDS: &[&str] = &["ivc/setup/srs", "ivc/setup/keys"];

/// All benchmark ids exposed by this harness: per-path prove/verify/fold, plus the setup ids.
fn all_ids() -> Vec<String> {
    PATHS
        .iter()
        .flat_map(|(path, name)| ids_for(*path, name))
        .chain(SETUP_IDS.iter().map(|id| id.to_string()))
        .collect()
}

/// A benchmark id runs iff no filter was given, or the literal filter is a substring of the full id.
fn selected(filter: Option<&str>, full_id: &str) -> bool {
    filter.map(|f| full_id.contains(f)).unwrap_or(true)
}

/// True if any per-path benchmark (prove/verify/fold) is selected — those share the recursive-keygen env.
fn any_path_bench_selected(filter: Option<&str>) -> bool {
    PATHS.iter().any(|(path, name)| path_selected(filter, *path, name))
}

/// True if any setup (cold/warm) benchmark is selected.
fn any_setup_bench_selected(filter: Option<&str>) -> bool {
    SETUP_IDS.iter().any(|id| selected(filter, id))
}

/// True if any benchmark for this path is selected (so its fixture is worth preparing).
fn path_selected(filter: Option<&str>, path: TransitionPath, name: &str) -> bool {
    ids_for(path, name).iter().any(|id| selected(filter, id))
}

fn print_usage() {
    println!(
        "Recursive IVC circuit benchmarks (façade-driven).\n\n\
         Usage: cargo bench ... --bench ivc_halo2_snark -- [<literal-id-or-prefix>]\n\n\
         Pass a single literal id or prefix to select benchmarks; omit it to run all. Use --list to see \
         the ids. --test and --profile-time are unsupported (they force a recursive keygen).\n\n\
         Cost: a no-filter run does the shared per-path recursive keygen AND the setup keys keygen, then \
         all proofs (~tens of minutes, GB-scale RAM). Filter to a path or id to scope the work."
    );
    print_all_ids();
}

fn print_all_ids() {
    println!("Benchmark ids (each manually timed — a single observation, not run under --list):");
    for id in all_ids() {
        println!("  {id}");
    }
}

/// Single-observation timings for one transition path. `None` = the id was filtered out, or (for
/// `fold` on genesis) not applicable — genesis is an accumulator passthrough.
struct PathTimings {
    name: &'static str,
    proof_size: usize,
    prove_poseidon: Option<Duration>,
    prove_blake2b: Option<Duration>,
    verify_full: Option<Duration>,
    verify_kzg_opening: Option<Duration>,
    fold: Option<Duration>,
}

/// Times one operation once (a single observation) when `run` is true, else returns `None`. The result
/// is `black_box`-ed so the work is not optimised away.
fn timed<T>(run: bool, operation: impl FnOnce() -> T) -> Option<Duration> {
    if !run {
        return None;
    }
    let start = Instant::now();
    black_box(operation());
    Some(start.elapsed())
}

/// Measures every selected operation for one path — prove (both transcripts), verify (full + isolated
/// KZG opening), and the off-circuit accumulator fold — each a single observation, all delegating to
/// the façade. Genesis has no fold (accumulator passthrough). Excludes the untimed fixture preparation.
fn measure_path(
    filter: Option<&str>,
    is_genesis: bool,
    name: &'static str,
    env: &IvcBenchEnv,
    step: &PreparedStep,
) -> PathTimings {
    PathTimings {
        name,
        proof_size: step.proof_size(),
        prove_poseidon: timed(
            selected(filter, &format!("ivc/{name}/prove/poseidon")),
            || env.prove_poseidon(step).expect("poseidon prove should succeed"),
        ),
        prove_blake2b: timed(
            selected(filter, &format!("ivc/{name}/prove/blake2b")),
            || env.prove_blake2b(step).expect("blake2b prove should succeed"),
        ),
        verify_full: timed(selected(filter, &format!("ivc/{name}/verify/full")), || {
            env.verify_full(step).expect("full verification should succeed")
        }),
        verify_kzg_opening: timed(
            selected(filter, &format!("ivc/{name}/verify/kzg_opening")),
            || env.verify_kzg_opening(step).expect("kzg opening should succeed"),
        ),
        fold: if is_genesis {
            None
        } else {
            timed(selected(filter, &format!("ivc/{name}/fold")), || {
                env.fold_accumulators(step).expect("non-genesis fold present")
            })
        },
    }
}

/// Formats one cell: seconds for the multi-second prover, milliseconds otherwise; `—` when unmeasured.
fn cell(duration: Option<Duration>) -> String {
    match duration {
        None => "—".to_string(),
        Some(d) if d.as_secs_f64() >= 1.0 => format!("{:.3} s", d.as_secs_f64()),
        Some(d) => format!("{:.3} ms", d.as_secs_f64() * 1000.0),
    }
}

/// Prints the consolidated report: the one-off setup (cold environment build) then a per-path table.
/// Every number is a single observation — a coarse baseline for the SNARK book, not a statistic.
fn print_report(setup: Duration, rows: &[PathTimings]) {
    println!(
        "\nIVC recursive circuit (degree 19) — single observation per cell; one keygen shared across paths"
    );
    println!(
        "setup (cold environment: unsafe SRS + certificate/IVC keygen + fixed bases + verifier/global \
         init): {:.3} s\n",
        setup.as_secs_f64()
    );
    println!(
        "{:<12} {:>13} {:>13} {:>12} {:>12} {:>11} {:>9}",
        "path", "prove/pos", "prove/blake", "verify/full", "verify/kzg", "fold", "proof"
    );
    for row in rows {
        println!(
            "{:<12} {:>13} {:>13} {:>12} {:>12} {:>11} {:>9}",
            row.name,
            cell(row.prove_poseidon),
            cell(row.prove_blake2b),
            cell(row.verify_full),
            cell(row.verify_kzg_opening),
            cell(row.fold),
            format!("{} B", row.proof_size),
        );
    }
    println!(
        "\nproof = committed verification proof size (the freshly generated Poseidon/Blake2b proofs share \
         this fixed format/size)."
    );
}

fn run(filter: Option<String>) {
    let filter = filter.as_deref();
    // Per-path benches share one recursive-keygen environment; the setup benches build their own caches.
    // A no-filter run therefore does the shared keygen AND the setup benches' own keygen(s).
    if any_path_bench_selected(filter) {
        run_path_benches(filter);
    }
    if any_setup_bench_selected(filter) {
        run_setup_benches(filter);
    }
}

/// Per-path prove/verify/fold, sharing one environment (one recursive keygen), printed as a table.
fn run_path_benches(filter: Option<&str>) {
    // One shared environment (a full recursive keygen) for the whole run; `cache` stays in scope (and
    // thus on disk) for the entire block. The keygen is timed once as the one-off `setup` cost.
    let cache = TempDir::new().expect("bench cache tempdir");
    let setup_start = Instant::now();
    let env = IvcBenchEnv::new(cache.path()).expect("IVC bench environment should build");
    let setup = setup_start.elapsed();

    let rows: Vec<PathTimings> = PATHS
        .iter()
        .filter(|(path, name)| path_selected(filter, *path, name))
        .map(|(path, name)| {
            let step = env.prepare_step(*path).expect("fixture preparation should succeed");
            measure_path(
                filter,
                matches!(path, TransitionPath::Genesis),
                name,
                &env,
                &step,
            )
        })
        .collect();

    print_report(setup, &rows);
}

/// Times one operation once (a single observation), `black_box`-ing the result.
fn observe<T>(operation: impl FnOnce() -> T) -> Duration {
    let start = Instant::now();
    black_box(operation());
    start.elapsed()
}

/// Setup cold/warm measurements (item 8), each on its own throwaway cache: the cold call populates the
/// cache, the warm call reads it back — both through the production providers. Independent of the shared
/// per-path environment.
fn run_setup_benches(filter: Option<&str>) {
    let srs = selected(filter, "ivc/setup/srs").then(|| {
        let dir = TempDir::new().expect("bench cache tempdir");
        let cold = observe(|| {
            IvcBenchEnv::measure_srs_cold_start(dir.path()).expect("srs cold-start should succeed")
        });
        let warm = observe(|| {
            IvcBenchEnv::measure_srs_warm_start(dir.path()).expect("srs warm-start should succeed")
        });
        (cold, warm)
    });
    let keys = selected(filter, "ivc/setup/keys").then(|| {
        eprintln!(
            "note: 'ivc/setup/keys' runs a full recursive keygen for the cold measurement \
             (minutes, GB-scale RAM)."
        );
        let dir = TempDir::new().expect("bench cache tempdir");
        let srs = IvcBenchEnv::measure_srs_cold_start(dir.path())
            .expect("srs seed for the keys measurement should succeed");
        let cold = observe(|| {
            IvcBenchEnv::measure_keys(dir.path(), &srs).expect("keys cold derive should succeed")
        });
        let warm = observe(|| {
            IvcBenchEnv::measure_keys(dir.path(), &srs).expect("keys warm load should succeed")
        });
        (cold, warm)
    });
    print_setup_report(srs, keys);
}

/// Prints the setup cold-vs-warm table (item 8): cold = generate/derive from scratch, warm = load from the
/// on-disk cache. Single observation each.
fn print_setup_report(srs: Option<(Duration, Duration)>, keys: Option<(Duration, Duration)>) {
    if srs.is_none() && keys.is_none() {
        return;
    }
    println!("\nsetup cache: cold vs warm (single observation each)");
    println!("{:<18} {:>13} {:>13}", "stage", "cold", "warm");
    if let Some((cold, warm)) = srs {
        println!(
            "{:<18} {:>13} {:>13}",
            "srs",
            cell(Some(cold)),
            cell(Some(warm))
        );
    }
    if let Some((cold, warm)) = keys {
        println!(
            "{:<18} {:>13} {:>13}",
            "keys (cert+ivc)",
            cell(Some(cold)),
            cell(Some(warm))
        );
    }
    println!(
        "cold = generate/derive from scratch; warm = load from the on-disk cache (both via the production \
         providers)."
    );
}

fn main() {
    match bench_cli::parse(std::env::args().skip(1)) {
        Err(message) => die(&message),
        Ok(BenchCli::Help) => print_usage(),
        Ok(BenchCli::Version) => println!("{}", env!("CARGO_PKG_VERSION")),
        Ok(BenchCli::List) => print_all_ids(),
        Ok(BenchCli::Ignored) => {}
        Ok(BenchCli::Run(filter)) => run(filter),
    }
}
