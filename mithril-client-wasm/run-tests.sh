#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

# Script directory variable (absolute path)
SCRIPT_DIRECTORY=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
readonly SCRIPT_DIRECTORY

# Fixed path so a fake aggregator left over by an interrupted run can be stopped by the next one
readonly AGGREGATOR_FAKE_PID_FILE="${TMPDIR:-/tmp}/mithril-client-wasm-aggregator-fake.pid"
# Must match the address used by the tests (see `FAKE_AGGREGATOR_IP` & `FAKE_AGGREGATOR_PORT` in `src/client_wasm.rs`)
readonly AGGREGATOR_FAKE_IP="127.0.0.1" AGGREGATOR_FAKE_PORT="8000"

display_help() {
  echo "Run the mithril-client-wasm test suite"
  echo
  echo "Usage: $0 [OPTIONS]"
  echo
  echo "Options:"
  echo "  --chromedriver <PATH>      Path to the chromedriver to use (default: from \$PATH or downloaded by wasm-pack)"
  echo "  --geckodriver <PATH>       Path to the geckodriver to use (default: from \$PATH or downloaded by wasm-pack)"
  echo "  -h, --help                 Print this help"
  echo
  echo "Browser tests are skipped for browsers that are not installed and have no driver given."
  echo "If no Chrome is installed, Snap Chromium is used as a fallback with its own driver (chromium.chromedriver)."
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

has_chrome() {
  local browser path
  # macOS apps are not in the $PATH
  if [[ -d "/Applications/Google Chrome.app" || -d "/Applications/Chromium.app" ]]; then
    return 0
  fi

  for browser in google-chrome google-chrome-stable chromium chromium-browser; do
    path=$(command -v "$browser") || continue
    # Snap Chromium is handled separately: its confinement prevents the chromedriver downloaded by wasm-pack
    # from starting it, it must be driven by the chromedriver shipped with the snap
    [[ "$path" == /snap/* ]] || return 0
  done

  return 1
}

has_firefox() {
  # macOS apps are not in the $PATH
  [[ -d "/Applications/Firefox.app" ]] || command -v firefox >/dev/null
}

start_aggregator_fake() {
  cargo build -p mithril-aggregator-fake --bin mithril-aggregator-fake

  local aggregator_fake_bin
  aggregator_fake_bin="$(cargo metadata --no-deps --format-version 1 | jq -r ".target_directory")/debug/mithril-aggregator-fake"

  "${aggregator_fake_bin}" --ip-address "$AGGREGATOR_FAKE_IP" --tcp-port "$AGGREGATOR_FAKE_PORT" &
  echo "$!" > "$AGGREGATOR_FAKE_PID_FILE"

  # Startup errors (i.e. port already in use) make the fake aggregator exit almost immediately
  sleep 1
  kill -0 $! 2>/dev/null || error_exit "Mithril-aggregator-fake failed to start, see its logs above."
  echo ">> Mithril-aggregator-fake started (PID: $!)"
}

# Usage: stop_aggregator_fake [--quiet]
stop_aggregator_fake() {
  local -r quiet=$([[ "${1:-}" == "--quiet" ]] && echo true || echo false)
  local pid

  if [[ ! -f "$AGGREGATOR_FAKE_PID_FILE" ]]; then
    return 0
  fi

  pid="$(cat "$AGGREGATOR_FAKE_PID_FILE")"
  kill "${pid}" 2>/dev/null || true
  rm -f "$AGGREGATOR_FAKE_PID_FILE"

  if [[ "$quiet" != true ]]; then
    echo ">> Mithril-aggregator-fake (PID: ${pid}) stopped"
  fi
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare CHROMEDRIVER="" GECKODRIVER=""

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      --chromedriver ) CHROMEDRIVER="${2:?Missing path for --chromedriver}"; shift ;;
      --geckodriver ) GECKODRIVER="${2:?Missing path for --geckodriver}"; shift ;;
      -h | --help ) display_help ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

check_requirements "wasm-pack" "cargo" "jq"

# ---------------------------------------------------------------------------
# Browsers detection
# ---------------------------------------------------------------------------

declare BROWSER_ARGS=()

if [[ -n "$CHROMEDRIVER" ]]; then
  check_requirements "$CHROMEDRIVER"
  BROWSER_ARGS+=(--chrome --chromedriver "$CHROMEDRIVER")
elif has_chrome; then
  BROWSER_ARGS+=(--chrome)
elif SNAP_CHROMEDRIVER=$(command -v chromium.chromedriver); then
  echo ">> Chrome not found, using Snap Chromium"
  BROWSER_ARGS+=(--chrome --chromedriver "$SNAP_CHROMEDRIVER")
else
  echo ">> Chrome not found, skipping Chrome tests"
fi

if [[ -n "$GECKODRIVER" ]]; then
  check_requirements "$GECKODRIVER"
  BROWSER_ARGS+=(--firefox --geckodriver "$GECKODRIVER")
elif has_firefox; then
  BROWSER_ARGS+=(--firefox)
else
  echo ">> Firefox not found, skipping Firefox tests"
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

cd "$SCRIPT_DIRECTORY"

stop_aggregator_fake --quiet
trap stop_aggregator_fake EXIT
start_aggregator_fake

if [[ ${#BROWSER_ARGS[@]} -gt 0 ]]; then
  wasm-pack test --headless "${BROWSER_ARGS[@]}" --release
else
  echo ">> No browser available, skipping browser tests"
fi
wasm-pack test --node --release --features test-node
