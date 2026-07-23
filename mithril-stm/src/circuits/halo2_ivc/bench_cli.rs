//! Fail-closed CLI parsing for the `ivc_halo2_snark` benchmark.
//!
//! Split out (behind `benchmark-internals`) and kept **pure** — no printing, no `process::exit` — so the
//! fail-closed contract can be unit-tested: no option may consume a following token and turn a control
//! flag or filter into an accidental `Run(None)`, which would trigger a multi-minute keygen + prove run.
//! The bench binary turns the returned [`BenchCli`] into printing / exit.

/// Valueless flags tolerated (e.g. `cargo bench` passes `--bench`). Every other `-`/`--` token is
/// rejected — nothing consumes a following value, so no token can be swallowed.
const FLAG_OPTS: &[&str] = &["--verbose", "--quiet", "--nocapture", "--bench"];
/// Regex metacharacters rejected in the positional filter (it is matched literally).
const METACHARS: &[char] = &['.', '*', '+', '?', '[', ']', '(', ')', '{', '}', '|', '^', '$', '\\'];

/// Validated CLI outcome, produced before the bench binary builds anything.
#[derive(Debug, PartialEq, Eq)]
pub enum BenchCli {
    /// Run the selected benchmarks (optional single literal id/prefix filter).
    Run(Option<String>),
    /// `--list`: print ids and return (no environment build).
    List,
    /// `--ignored`: nothing to run (no benches are ignored).
    Ignored,
    /// `--help` / `-h`: print usage and return.
    Help,
    /// `--version` / `-V`: print the crate version and return.
    Version,
}

/// Parse benchmark CLI arguments (already skipping `argv[0]`). Fail-closed: any unsupported option, a regex
/// metacharacter in the filter, more than one positional, or conflicting control flags returns `Err`. No
/// option consumes a following token, so a control flag or filter can never be swallowed into `Run(None)`.
pub fn parse(args: impl Iterator<Item = String>) -> Result<BenchCli, String> {
    let mut filter: Option<String> = None;
    let mut list = false;
    let mut ignored = false;
    let mut help = false;
    let mut version = false;
    let mut control_modes = 0;

    for token in args {
        match token.as_str() {
            "--exact" => {
                return Err("--exact is not supported; pass a literal id or prefix".to_string());
            }
            "--test" | "--profile-time" => {
                return Err(format!(
                    "{token} is not supported: it would force a full recursive keygen for the shared \
                     environment. Use the façade #[ignore] smoke test for a once-through run."
                ));
            }
            "--list" => {
                list = true;
                control_modes += 1;
            }
            "--ignored" => {
                ignored = true;
                control_modes += 1;
            }
            "--help" | "-h" => help = true,
            "--version" | "-V" => version = true,
            flag if FLAG_OPTS.contains(&flag) => {}
            other if other.starts_with('-') => {
                return Err(format!(
                    "unsupported option {other}; run with --list to see the benchmark ids"
                ));
            }
            positional => {
                if filter.is_some() {
                    return Err("only one literal filter is supported".to_string());
                }
                if positional.contains(METACHARS) {
                    return Err(
                        "regex filters are not supported; pass a literal id or prefix, e.g. \
                                ivc/same_epoch/prove"
                            .to_string(),
                    );
                }
                filter = Some(positional.to_string());
            }
        }
    }

    // `--help`/`--version` take precedence and never build anything.
    if help {
        return Ok(BenchCli::Help);
    }
    if version {
        return Ok(BenchCli::Version);
    }
    if control_modes > 1 {
        return Err("conflicting control modes (e.g. --list with --ignored)".to_string());
    }
    if list {
        return Ok(BenchCli::List);
    }
    if ignored {
        return Ok(BenchCli::Ignored);
    }
    Ok(BenchCli::Run(filter))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Result<BenchCli, String> {
        parse(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn no_args_runs_everything() {
        assert_eq!(parse_args(&[]), Ok(BenchCli::Run(None)));
    }

    #[test]
    fn a_single_literal_filter_is_kept() {
        assert_eq!(
            parse_args(&["ivc/same_epoch/prove"]),
            Ok(BenchCli::Run(Some("ivc/same_epoch/prove".to_string())))
        );
    }

    #[test]
    fn control_flags_map_to_their_variants() {
        assert_eq!(parse_args(&["--list"]), Ok(BenchCli::List));
        assert_eq!(parse_args(&["--ignored"]), Ok(BenchCli::Ignored));
        assert_eq!(parse_args(&["--help"]), Ok(BenchCli::Help));
        assert_eq!(parse_args(&["-h"]), Ok(BenchCli::Help));
        assert_eq!(parse_args(&["--version"]), Ok(BenchCli::Version));
        assert_eq!(parse_args(&["-V"]), Ok(BenchCli::Version));
    }

    #[test]
    fn tolerated_valueless_flags_do_not_disturb_parsing() {
        assert_eq!(parse_args(&["--bench", "--list"]), Ok(BenchCli::List));
        assert_eq!(
            parse_args(&["--nocapture", "ivc/genesis"]),
            Ok(BenchCli::Run(Some("ivc/genesis".to_string())))
        );
    }

    // The regression the fail-closed fix closes: value-taking options must be rejected, never swallow the
    // following token, and never fall through to `Run(None)` (which would trigger the full keygen+prove run).
    #[test]
    fn value_taking_options_are_rejected_not_swallowed() {
        assert!(parse_args(&["--sample-size", "10"]).is_err());
        assert!(parse_args(&["--sample-size", "--list"]).is_err());
        assert!(parse_args(&["--color", "always"]).is_err());
        assert!(parse_args(&["--save-baseline", "ivc"]).is_err());
    }

    #[test]
    fn unsupported_and_malformed_inputs_are_rejected() {
        assert!(parse_args(&["--bogus"]).is_err());
        assert!(parse_args(&["--exact"]).is_err());
        assert!(parse_args(&["--test"]).is_err());
        assert!(parse_args(&["--profile-time", "30"]).is_err());
        assert!(parse_args(&["ivc/.*verify"]).is_err());
        assert!(parse_args(&["ivc/genesis", "ivc/same_epoch"]).is_err());
        assert!(parse_args(&["--list", "--ignored"]).is_err());
    }

    #[test]
    fn help_and_version_take_precedence_over_control_flags() {
        assert_eq!(parse_args(&["--list", "--help"]), Ok(BenchCli::Help));
        assert_eq!(
            parse_args(&["--ignored", "--version"]),
            Ok(BenchCli::Version)
        );
    }
}
