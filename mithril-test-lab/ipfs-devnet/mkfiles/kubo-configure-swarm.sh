#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

display_help() {
    echo "Configure a swarm of kubo ipfs node"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -d, --nodes-dir <dir>      Directory that will contains the nodes configuration (required)"
    echo "  -n, --number <int>         Number of nodes to configure (min: 2)"
    echo "  -h, --help                 Print this help"
    echo
    exit 0
}

# Function to display an error message and exit
error_exit() {
  echo "$1" 1>&2
  exit 1
}

# Generate a 64 chars long random hex string
generate_swarm_key() {
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare NODES_DIR="" NUMBER_OF_NODES=""

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      -d | --nodes-dir) shift; NODES_DIR=${1:-} ;;
      -n | --number) shift; NUMBER_OF_NODES=${1:-} ;;
      -h | --help ) display_help ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

readonly NODES_DIR NUMBER_OF_NODES=${NUMBER_OF_NODES:-2}

if [[ -z "$NODES_DIR" ]]; then
  error_exit "Missing required option: -d, --nodes-dir"
fi

if ! [[ "$NUMBER_OF_NODES" =~ ^[0-9]+$ ]]; then
  error_exit "Invalid value for -n, --number: '$NUMBER_OF_NODES'. Expected an integer."
fi

if (( NUMBER_OF_NODES < 2 )); then
  error_exit "Invalid value for -n, --number: '$NUMBER_OF_NODES'. Expected at least 2."
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo ">> Configuring ${NUMBER_OF_NODES} Kubo nodes in '${NODES_DIR}'"

SWARM_KEY="$(generate_swarm_key)"
readonly SWARM_KEY
echo ">> Swarm key generated (not displayed)."
