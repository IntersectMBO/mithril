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
    echo "Environment variables:"
    echo "  DOWNLOAD_DIR               Directory where the binary archive will be downloaded"
    echo "  KUBO_VERSION               Specific Kubo version to run"
    echo "  NUMBER_OF_NODES            Number of nodes to configure"
    echo "  SWARM_DIR                  Directory that will contain the swarm nodes"
    echo "  OVERWRITE                  Allow overwriting existing swarm when set to any value except '0' or 'false'"
    echo
    echo "Options and environment variables can be mixed; when both are provided for the same setting,"
    echo "the command-line option takes priority."
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

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

# Setting anything, '0' or 'false' excepted, to `OVERWRITE` env var is equivalent to `true`
declare OVERWRITE_FROM_ENV=false
if [[ -n "${OVERWRITE+x}" && "$OVERWRITE" != "0" && "$OVERWRITE" != "false" ]]; then
  OVERWRITE_FROM_ENV=true
fi

declare DOWNLOAD_DIR="${DOWNLOAD_DIR:-}" SWARM_DIR="${SWARM_DIR:-}"
declare KUBO_VERSION="${KUBO_VERSION:-}" NUMBER_OF_NODES="${NUMBER_OF_NODES:-}"
declare OVERWRITE="$OVERWRITE_FROM_ENV"

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      -d | --download-dir)
        shift
        require_value "--download-dir" "${1:-}"
        DOWNLOAD_DIR=$1
        ;;
      -n | --number)
        shift
        require_value "--number" "${1:-}"
        NUMBER_OF_NODES=$1
        ;;
      -s | --swarm-dir)
        shift
        require_value "--swarm-dir" "${1:-}"
        SWARM_DIR=$1
        ;;
      -v | --version)
        shift
        require_value "--version" "${1:-}"
        KUBO_VERSION=$1
        ;;
      -o | --overwrite) OVERWRITE=true ;;
      -h | --help ) display_help ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

readonly DOWNLOAD_DIR=${DOWNLOAD_DIR:-"/tmp/kubo/"} NUMBER_OF_NODES=${NUMBER_OF_NODES:-2}
readonly KUBO_VERSION SWARM_DIR OVERWRITE

if [[ "${1:-}" == "--" ]]; then
  shift
fi

if [[ "$#" -gt 0 ]]; then
  error_exit "Unexpected argument: $1"
fi

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

# Create query scripts
bash "${SCRIPT_DIRECTORY}/mkfiles/mkscripts-query.sh" --ipfs-bin-path "${SWARM_DIR%/}/bin/ipfs" \
    --output "$SWARM_DIR" "${NODES_DIR[@]}"
