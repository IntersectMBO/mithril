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
//! Every benchmark is *manually timed* — a single observation each, gathered into one consolidated
//! table — because a recursive proof at `RECURSIVE_CIRCUIT_DEGREE` costs tens of seconds and building the
//! shared environment runs a full recursive keygen (minutes, GB-scale RAM). So the harness validates its
//! CLI itself, up front, before constructing anything:
//!
//! - `--list` prints every benchmark id and returns — it never builds the environment (no keygen).
//! - `--test` and `--profile-time` are rejected: they would force a full recursive keygen for the shared
//!   environment. Use the façade's `#[ignore]` smoke test (`facade_prepares_proves_and_verifies_all_paths`)
//!   for a once-through sanity run instead.
//! - Only a small documented subset of options is accepted (for `cargo bench` compatibility); any other
//!   option is rejected. A single literal positional filter is allowed (no regex, no `--exact`).

use std::hint::black_box;
use std::time::{Duration, Instant};

use mithril_stm::circuits::halo2_ivc::bench_helpers::{IvcBenchEnv, PreparedStep, TransitionPath};
use tempfile::TempDir;

/// The three transition paths and their id segments.
const PATHS: &[(TransitionPath, &str)] = &[
    (TransitionPath::Genesis, "genesis"),
    (TransitionPath::SameEpoch, "same_epoch"),
    (TransitionPath::NextEpoch, "next_epoch"),
];

/// Options accepted but ignored (for `cargo bench` / Criterion-CLI compatibility), taking no value.
/// (`--help`/`--version` are handled explicitly in [`parse_cli_or_exit`].)
const FLAG_OPTS: &[&str] = &["--verbose", "--quiet", "--nocapture", "--bench"];
/// Options accepted for compatibility that consume the following argument (so their value is not
/// mistaken for the filter). A deliberate subset — anything else is rejected (fail-safe).
const VALUE_OPTS: &[&str] = &[
    "--sample-size",
    "--warm-up-time",
    "--measurement-time",
    "--nresamples",
    "--noise-threshold",
    "--confidence-level",
    "--significance-level",
    "--output-format",
    "--format",
    "--color",
    "--colour",
    "--plotting-backend",
    "--baseline",
    "--baseline-lenient",
    "--save-baseline",
    "--load-baseline",
];
/// Regex metacharacters rejected in the positional filter (the filter is matched literally).
const METACHARS: &[char] = &['.', '*', '+', '?', '[', ']', '(', ')', '{', '}', '|', '^', '$', '\\'];

/// Outcome of validating the CLI, before any environment is built.
enum Cli {
    /// Run selected benchmarks (optional literal filter).
    Run(Option<String>),
    /// `--list`: print ids and return.
    List,
    /// `--ignored`: no benches are ignored, so there is nothing to run.
    NothingToRun,
}

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

/// All benchmark ids exposed by this harness.
fn all_ids() -> Vec<String> {
    PATHS.iter().flat_map(|(path, name)| ids_for(*path, name)).collect()
}

/// A benchmark id runs iff no filter was given, or the literal filter is a substring of the full id.
fn selected(filter: Option<&str>, full_id: &str) -> bool {
    filter.map(|f| full_id.contains(f)).unwrap_or(true)
}

/// True if any benchmark that needs the shared environment is selected.
fn any_env_bench_selected(filter: Option<&str>) -> bool {
    all_ids().iter().any(|id| selected(filter, id))
}

/// True if any benchmark for this path is selected (so its fixture is worth preparing).
fn path_selected(filter: Option<&str>, path: TransitionPath, name: &str) -> bool {
    ids_for(path, name).iter().any(|id| selected(filter, id))
}

/// Validate the CLI up front, before building anything. Fail-closed: unsupported tokens are rejected.
fn parse_cli_or_exit() -> Cli {
    let mut args = std::env::args().skip(1);
    let mut filter: Option<String> = None;
    let mut list = false;
    let mut ignored = false;
    let mut control_modes = 0;

    while let Some(token) = args.next() {
        match token.as_str() {
            "--exact" => die("--exact is not supported; pass a literal id or prefix"),
            "--test" | "--profile-time" => die(&format!(
                "{token} is not supported: it would force a full recursive keygen for the shared \
                 environment. Use the façade #[ignore] smoke test for a once-through run."
            )),
            "--list" => {
                list = true;
                control_modes += 1;
            }
            "--ignored" => {
                ignored = true;
                control_modes += 1;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("{}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            value_opt if VALUE_OPTS.contains(&value_opt) => {
                if args.next().is_none() {
                    die(&format!("missing value for {value_opt}"));
                }
            }
            flag if FLAG_OPTS.contains(&flag) => {}
            other if other.starts_with('-') => die(&format!(
                "unsupported option {other}; run with --list to see the benchmark ids"
            )),
            positional => {
                if filter.is_some() {
                    die("only one literal filter is supported");
                }
                if positional.contains(METACHARS) {
                    die(
                        "regex filters are not supported; pass a literal id or prefix, e.g. \
                         ivc/same_epoch/prove",
                    );
                }
                filter = Some(positional.to_string());
            }
        }
    }

    if control_modes > 1 {
        die("conflicting control modes (e.g. --list with --ignored)");
    }
    if list {
        return Cli::List;
    }
    if ignored {
        return Cli::NothingToRun;
    }
    Cli::Run(filter)
}

fn print_usage() {
    println!(
        "Recursive IVC circuit benchmarks (façade-driven).\n\n\
         Usage: cargo bench ... --bench ivc_halo2_snark -- [<literal-id-or-prefix>]\n\n\
         Pass a single literal id or prefix to select benchmarks; omit it to run all. Use --list to see \
         the ids. --test and --profile-time are unsupported (they force a recursive keygen)."
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

/// Prints the consolidated report: the one-off setup (cold keygen) then an aligned per-path table.
/// Every number is a single observation — a coarse baseline for the SNARK book, not a statistic.
fn print_report(setup: Duration, rows: &[PathTimings]) {
    println!(
        "\nIVC recursive circuit (degree 19) — single observation per cell; one keygen shared across paths"
    );
    println!("setup (cold keygen): {:.3} s\n", setup.as_secs_f64());
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
}

fn run(filter: Option<String>) {
    let filter = filter.as_deref();
    if !any_env_bench_selected(filter) {
        return;
    }

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

fn main() {
    match parse_cli_or_exit() {
        Cli::List => print_all_ids(),
        Cli::NothingToRun => {}
        Cli::Run(filter) => run(filter),
    }
}
