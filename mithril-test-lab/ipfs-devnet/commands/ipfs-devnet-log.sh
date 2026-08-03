#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

display_help() {
    echo "Tail the logs from all Kubo nodes"
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
    echo "Arguments after '--' are forwarded to the generated log script."
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
declare -a forwarded_args=()

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do
  case "$1" in
    -h | --help) display_help ;;
    -s | --swarm-dir)
      shift
      require_value "--swarm-dir" "${1:-}"
      swarm_dir=$1
      ;;
    *) error_exit "Unknown option for 'start': $1" ;;
  esac
  shift
done

if [[ "${1:-}" == "--" ]]; then
  shift
  forwarded_args=("$@")
elif [[ "$#" -gt 0 ]]; then
  error_exit "Unexpected argument for 'start': $1"
fi

require_swarm_dir "$swarm_dir"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

declare -r log="${swarm_dir%/}/log.sh"

if [[ ! -x "$log" ]]; then
  error_exit "Generated log script is not executable or does not exist: '$log'. Run 'ipfs-devnet.sh init' first."
fi

bash "$log" "${forwarded_args[@]}"
