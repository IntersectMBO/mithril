#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

# Script directory variable (absolute path)
SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

display_help() {
    echo "Download, configure, and create scripts to manage a swarm of IPFS Kubo nodes"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -d, --download-dir <dir>   Directory where the binary archive will be downloaded [default='/tmp/kubo']"
    echo "  -h, --help                 Print this help"
    echo "  -n, --number <int>         Number of nodes to configure [default: 2]"
    echo "  -o, --overwrite            Allow overwriting existing swarm [default:false]"
    echo "  -s, --swarm-dir <dir>      Directory that will contain the swarm nodes (required)"
    echo "  -v, --version <version>    Specific version to run (omit to use the latest version)"
    echo
    exit 0
}

# Function to display an error message and exit
error_exit() {
  echo "$1" 1>&2
  exit 1
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
declare DOWNLOAD_DIR="" KUBO_VERSION="" NUMBER_OF_NODES="" SWARM_DIR="" OVERWRITE=false

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      -d | --download-dir) shift; DOWNLOAD_DIR=${1:-} ;;
      -h | --help ) display_help ;;
      -n | --number) shift; NUMBER_OF_NODES=${1:-} ;;
      -o | --overwrite ) OVERWRITE=true ;;
      -s | --swarm-dir) shift; SWARM_DIR=${1:-} ;;
      -v | --version) shift; KUBO_VERSION=${1:-} ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

readonly DOWNLOAD_DIR=${DOWNLOAD_DIR:-"/tmp/kubo/"} NUMBER_OF_NODES=${NUMBER_OF_NODES:-2}
readonly KUBO_VERSION SWARM_DIR OVERWRITE

if [[ -z "$SWARM_DIR" ]]; then
  error_exit "Missing required option: -s, --swarm-dir"
fi

if [[ ! -e "$SWARM_DIR" ]]; then
  mkdir -p -- "${SWARM_DIR%/}"
fi

if [[ ! -e "$DOWNLOAD_DIR" ]]; then
  mkdir -p -- "${DOWNLOAD_DIR%/}"
fi

if ! [[ "$NUMBER_OF_NODES" =~ ^[0-9]+$ ]]; then
  error_exit "Invalid value for -n, --number: '$NUMBER_OF_NODES'. Expected an integer."
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Download
download_args=(
  --download-dir "$DOWNLOAD_DIR"
  --output "${SWARM_DIR%/}/bin"
)

if [[ -n "$KUBO_VERSION" ]]; then
  download_args+=(--version "$KUBO_VERSION")
fi

bash "${SCRIPT_DIRECTORY}/mkfiles/kubo-download.sh" "${download_args[@]}"

# Configure
configure_args=(
  --ipfs-bin-path "${SWARM_DIR%/}/bin/ipfs"
  --number "$NUMBER_OF_NODES"
  --swarm-dir "$SWARM_DIR"
)

if "$OVERWRITE"; then
  configure_args+=(--overwrite)
fi

bash "${SCRIPT_DIRECTORY}/mkfiles/kubo-configure-swarm.sh" "${configure_args[@]}"

declare -a NODES_DIR
for ((node_id = 1; node_id <= NUMBER_OF_NODES; node_id++)); do
  NODES_DIR+=("${SWARM_DIR%/}/kubo-node-$node_id")
done
echo ">> nodes dir:" "${NODES_DIR[@]}"

# Create lifecycle scripts
bash "${SCRIPT_DIRECTORY}/mkfiles/mkscripts-lifecycle.sh" --ipfs-bin-path "${SWARM_DIR%/}/bin/ipfs" \
    --output "$SWARM_DIR" "${NODES_DIR[@]}"
