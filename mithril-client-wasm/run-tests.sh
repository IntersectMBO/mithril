#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

# Script directory variable (absolute path)
SCRIPT_DIRECTORY=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
readonly SCRIPT_DIRECTORY

display_help() {
  echo "Run the mithril-client-wasm tests suite"
  echo
  echo "Usage: $0 [OPTIONS]"
  echo
  echo "Options:"
  echo "  --chromedriver <PATH>      Path to the chromedriver to use (default: from \$PATH or downloaded by wasm-pack)"
  echo "  --geckodriver <PATH>       Path to the geckodriver to use (default: from \$PATH or downloaded by wasm-pack)"
  echo "  -h, --help                 Print this help"
  echo
  exit 0
}

error_exit() {
  printf '%s\n' "$1" >&2
  exit 1
}

check_requirements() {
  for tool in "$@"; do
    command -v "$tool" >/dev/null ||
        error_exit "It seems '$tool' is not installed or not in the path."
  done
}

start_aggregator_fake() {
  cargo build --bins -p mithril-aggregator-fake
  cargo run -p mithril-aggregator-fake -- -p 8000 &
  echo ">> Mithril-aggregator-fake started"
}

# Usage: stop_aggregator_fake [--quiet]
stop_aggregator_fake() {
  local -r quiet=$([[ "${1:-}" == "--quiet" ]] && echo true || echo false)

  # The `[m]` bracket prevents `pkill` from matching (and killing) the shell running it
  pkill -f "[m]ithril-aggregator-fake" || true
  [[ "$quiet" == true ]] || echo ">> Mithril-aggregator-fake stopped"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare CHROME_ARGS=(--chrome) FIREFOX_ARGS=(--firefox)

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      --chromedriver ) CHROME_ARGS=(--chrome --chromedriver "${2:?Missing path for --chromedriver}"); shift ;;
      --geckodriver ) FIREFOX_ARGS=(--firefox --geckodriver "${2:?Missing path for --geckodriver}"); shift ;;
      -h | --help ) display_help ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

check_requirements "wasm-pack" "cargo"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

cd "$SCRIPT_DIRECTORY"

stop_aggregator_fake --quiet
trap stop_aggregator_fake EXIT
start_aggregator_fake

wasm-pack test --headless "${FIREFOX_ARGS[@]}" "${CHROME_ARGS[@]}" --release
wasm-pack test --node --release --features test-node
