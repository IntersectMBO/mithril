#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ---------- Filter Slow tests - Cargo nextest filterset generator ----------
#
# See associated documentation in the `filter-slow-tests` DevBook
#
# **IMPORTANT** To run against GitHub Actions macOS runners, this script *must* be compatible with bash `3.2`
# ---------------------------------------------------------------------------
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

display_help() {
    echo "Generate a cargo-nextest filterset that excludes slow tests unless a related source path"
    echo "has been changed compared to a base branch."
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -a, --all                  allow all tests regardless of changes from the base branch"
    echo "  -c, --commit-ref <commit>  commit from which changes will be identified (default: origin/main)"
    echo "  -h, --help                 Print this help"
    echo
    exit 0
}

# Build the nextest 'or'-joined filter fragment for slow tests whose source
# paths appear in the list of changed files.
#
# Arguments:
#   $1 - newline-separated list of changed file paths (plain string)
#   $2..N - slow-test entries of the form "path/from/repo/root#full::rust::module::path::"
generate_nextest_allowed_slow_filterset() {
  local -r changed_files="$1"
  shift

  local filterset=""

  for entry in "$@"; do
      local watch_path="${entry%%#*}"
      local module_prefix="${entry##*#}"

      if echo "$changed_files" | grep -q "${watch_path}"; then
          # Uses glob notation from the nextest filterset DSL
          local fragment="test(#${module_prefix}*slow::*)"

          if [[ -z "$filterset" ]]; then
            filterset="$fragment"
          else
            filterset="$filterset or $fragment"
          fi
      fi
  done

  echo "$filterset"
}

append_output() {
  local string_to_append="$1"
  local -r rust_package="$2"
  local -r generated_filterset="$3"

  if [[ -n "$generated_filterset" ]]; then
    string_to_append="$string_to_append or (package($rust_package) and ($generated_filterset))"
  fi

  echo "$string_to_append"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare COMMIT_REF="" ALLOW_ALL=false
while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      -h | --help ) display_help ;;
      -a | --all ) ALLOW_ALL=true ;;
      -c | --commit-ref ) shift; COMMIT_REF=${1:-} ;;
    esac
    shift
done
readonly COMMIT_REF=${COMMIT_REF:-"origin/main"} ALLOW_ALL

# ---------------------------------------------------------------------------
# Slow tests entries
#
# Format: "path/from/repo/root#rust::module::path::" (A path can be referenced multiple times)
# ---------------------------------------------------------------------------

readonly -a SLOW_MITHRIL_STM_TESTS=(
  "mithril-stm/src/#protocol::aggregate_signature::"
  "mithril-stm/src/circuits/halo2/#circuits::halo2::"
  "mithril-stm/src/circuits/halo2_ivc/#circuits::halo2_ivc::"
  "mithril-stm/src/membership_commitment/merkle_tree#membership_commitment::merkle_tree::"
  "mithril-stm/src/proof_system/halo2_ivc_snark/proof.rs#proof_system::halo2_ivc_snark::proof::"
  "mithril-stm/src/proof_system/halo2_ivc_snark/prover_input.rs#proof_system::halo2_ivc_snark::proof::"
  "mithril-stm/src/proof_system/halo2_ivc_snark/prover_input_helpers.rs#proof_system::halo2_ivc_snark::prover_input_helpers::"
  "mithril-stm/src/proof_system/halo2_ivc_snark/prover_input_helpers.rs#proof_system::halo2_ivc_snark::proof::"
  "mithril-stm/src/proof_system/halo2_ivc_snark/prover_setup.rs#proof_system::halo2_ivc_snark::prover_setup::"
  "mithril-stm/src/proof_system/halo2_ivc_snark/rolling_state.rs#proof_system::halo2_ivc_snark::proof::"
  "mithril-stm/src/proof_system/halo2_snark#proof_system::halo2_snark::"
  "mithril-stm/src/signature_scheme/bls_multi_signature#signature_scheme::bls_multi_signature::"
)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if $ALLOW_ALL; then
  echo "all()"
else
  OUTPUT="not test(#*slow::*)"

  # Newline-separated list of files changed since the base commit
  readonly CHANGED_FILES="$(git diff --name-only "$COMMIT_REF")"

  FILTERSET_STM="$(generate_nextest_allowed_slow_filterset "$CHANGED_FILES" "${SLOW_MITHRIL_STM_TESTS[@]}")"
  OUTPUT="$(append_output "$OUTPUT" "mithril-stm" "$FILTERSET_STM")"

  echo "$OUTPUT"
fi
