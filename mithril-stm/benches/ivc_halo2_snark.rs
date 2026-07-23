//! Criterion benchmarks for the recursive IVC circuit, driven end-to-end by the production-backed
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
//! The heavy benches are *manually timed* — a single observation each —
//! rather than registered Criterion `bench_function`s, because a recursive proof at
//! `RECURSIVE_CIRCUIT_DEGREE` costs tens of seconds and building the shared environment runs a full
//! recursive keygen (minutes, GB-scale RAM). Criterion's own filter/flags therefore cannot gate this work,
//! so the harness validates the CLI itself, up front, before constructing anything:
//!
//! - `--list` prints every benchmark id and returns — it never builds the environment (no keygen).
//! - `--test` and `--profile-time` are rejected: they would force a full recursive keygen for the shared
//!   environment. Use the façade's `#[ignore]` smoke test (`facade_prepares_proves_and_verifies_all_paths`)
//!   for a once-through sanity run instead.
//! - Only a documented subset of Criterion options is accepted; any other option is rejected. A single
//!   literal positional filter is allowed (no regex, no `--exact`).

use std::hint::black_box;
use std::time::Instant;

use criterion::Criterion;
use mithril_stm::circuits::halo2_ivc::bench_helpers::{IvcBenchEnv, PreparedStep, TransitionPath};
use tempfile::TempDir;

/// The three transition paths and their id segments.
const PATHS: &[(TransitionPath, &str)] = &[
    (TransitionPath::Genesis, "genesis"),
    (TransitionPath::SameEpoch, "same_epoch"),
    (TransitionPath::NextEpoch, "next_epoch"),
];

/// Criterion 0.8 options this harness accepts but takes no value.
/// (`--help`/`--version` are handled explicitly in [`parse_cli_or_exit`].)
const FLAG_OPTS: &[&str] = &["--verbose", "--quiet", "--nocapture", "--bench"];
/// Criterion 0.8 options this harness accepts that consume the following argument. This is a deliberate
/// supported subset, not the complete Criterion option set — anything else is rejected (fail-safe).
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
    /// `--ignored`: Criterion skips all benches, so there is nothing to run.
    NothingToRun,
}

fn die(message: &str) -> ! {
    eprintln!("ivc_halo2_snark: {message}");
    std::process::exit(2);
}

/// Prove benchmark ids for one path (`ivc/{path}/prove/{poseidon,blake2b}`).
fn prove_ids(path_name: &str) -> [String; 2] {
    [
        format!("ivc/{path_name}/prove/poseidon"),
        format!("ivc/{path_name}/prove/blake2b"),
    ]
}

/// All benchmark ids exposed by this harness.
fn all_ids() -> Vec<String> {
    PATHS.iter().flat_map(|(_, name)| prove_ids(name)).collect()
}

/// A benchmark id runs iff no filter was given, or the literal filter is a substring of the full id.
fn selected(filter: Option<&str>, full_id: &str) -> bool {
    filter.map(|f| full_id.contains(f)).unwrap_or(true)
}

/// True if any manually-timed benchmark that needs the shared environment is selected.
fn any_env_bench_selected(filter: Option<&str>) -> bool {
    all_ids().iter().any(|id| selected(filter, id))
}

/// True if any benchmark for `path_name` is selected (so its fixture is worth preparing).
fn path_selected(filter: Option<&str>, path_name: &str) -> bool {
    prove_ids(path_name).iter().any(|id| selected(filter, id))
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

/// Recursive prover, single observation per transcript (excludes the inner certificate prover and the
/// untimed preparation step — both live behind the façade). Delegates to `IvcBenchEnv::prove_*`.
fn run_prove_benches(filter: Option<&str>, env: &IvcBenchEnv, prepared: &[(&str, PreparedStep)]) {
    for (name, step) in prepared {
        let poseidon_id = format!("ivc/{name}/prove/poseidon");
        if selected(filter, &poseidon_id) {
            let start = Instant::now();
            let bytes = black_box(env.prove_poseidon(step).expect("poseidon prove should succeed"));
            println!(
                "{poseidon_id}: one observation {:?} (proof {} bytes)",
                start.elapsed(),
                bytes.len()
            );
        }
        let blake2b_id = format!("ivc/{name}/prove/blake2b");
        if selected(filter, &blake2b_id) {
            let start = Instant::now();
            let bytes = black_box(env.prove_blake2b(step).expect("blake2b prove should succeed"));
            println!(
                "{blake2b_id}: one observation {:?} (proof {} bytes)",
                start.elapsed(),
                bytes.len()
            );
        }
    }
}

fn run(filter: Option<String>) {
    let filter = filter.as_deref();

    // Construct Criterion immediately after parsing so it validates option values/conflicts (numeric
    // `--sample-size`, enum `--output-format`, baseline dependencies, …) before any keygen. It also
    // drives the Criterion-registered benches and produces the final summary.
    let criterion = Criterion::default().configure_from_args();

    if any_env_bench_selected(filter) {
        // One shared environment (a full recursive keygen) for the whole run; `cache` stays in scope
        // (and thus on disk) for the entire block.
        let cache = TempDir::new().expect("bench cache tempdir");
        let env = IvcBenchEnv::new(cache.path()).expect("IVC bench environment should build");

        let prepared: Vec<(&str, PreparedStep)> = PATHS
            .iter()
            .filter(|(_, name)| path_selected(filter, name))
            .map(|(path, name)| {
                let step = env.prepare_step(*path).expect("fixture preparation should succeed");
                println!("ivc/{name}: committed proof {} bytes", step.proof_size());
                (*name, step)
            })
            .collect();

        run_prove_benches(filter, &env, &prepared);
    }

    criterion.final_summary();
}

fn main() {
    match parse_cli_or_exit() {
        Cli::List => print_all_ids(),
        Cli::NothingToRun => {}
        Cli::Run(filter) => run(filter),
    }
}
