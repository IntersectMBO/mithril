#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

display_help() {
    echo "Stop the Kubo swarm using the generated stop script"
    echo
    echo "Usage: $0 stop [OPTIONS]"
    echo
    echo "Options:"
    echo "  -h, --help                 Print this help"
    echo "  -s, --swarm-dir <dir>      Directory that contains the swarm nodes (required)"
    echo
    echo "Environment variables:"
    echo "  SWARM_DIR                  Directory that contains the swarm nodes"
    echo
    exit 0
}

# Function to display an error message and exit
error_exit() {
  echo "$1" 1>&2
  exit 1
}

require_value() {
  local -r option="$1"
  local -r value="${2:-}"

  if [[ -z "$value" ]]; then
    error_exit "Missing value for option: $option"
  fi
}

require_swarm_dir() {
  local -r swarm_dir="$1"

  if [[ -z "$swarm_dir" ]]; then
    error_exit "Missing required option: -s, --swarm-dir"
  fi
}

# ---------------------------------------------------------------------------
# Command parsing
# ---------------------------------------------------------------------------

declare swarm_dir="${SWARM_DIR:-}"

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do
  case "$1" in
    -h | --help) display_help ;;
    -s | --swarm-dir)
      shift
      require_value "--swarm-dir" "${1:-}"
      swarm_dir=$1
      ;;
    *) error_exit "Unknown option for 'stop': $1" ;;
  esac
  shift
done

if [[ "${1:-}" == "--" ]]; then
  shift
fi

if [[ "$#" -gt 0 ]]; then
  error_exit "Unexpected argument for 'stop': $1"
fi

require_swarm_dir "$swarm_dir"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

declare -r stop_script="${swarm_dir%/}/stop.sh"

if [[ ! -x "$stop_script" ]]; then
  error_exit "Generated stop script is not executable or does not exist: '$stop_script'. Run 'ipfs-devnet.sh init' first."
fi

bash "$stop_script"
