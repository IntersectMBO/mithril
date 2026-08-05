#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

# Script directory variable (absolute path)
SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
readonly SCRIPT_DIRECTORY

# shellcheck source=./lib/common.sh
source "${SCRIPT_DIRECTORY}/lib/common.sh"

display_help() {
    echo "Download and load the Kubo Web UI on the private IPFS network"
    echo
    echo "IMPORTANT: The IPFS devnet must be running, and the download can be quite slow."
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -d, --download-dir <dir>   Directory where the CAR archive will be downloaded [default='/tmp/kubo/']"
    echo "  -h, --help                 Print this help"
    echo "  -s, --swarm-dir <dir>      Directory that contains the swarm nodes (required)"
    echo
    echo "Environment variables:"
    echo "  DOWNLOAD_DIR               Directory where the CAR archive will be downloaded"
    echo "  SWARM_DIR                  Directory that contains the swarm nodes"
    echo
    exit 0
}

find_web_ui_cid() {
  local -r node_port="$1"
  local location cid

  # leverage the 302 Found redirection which contains the CID in its location
  # example: `Location: /ipfs/bafybeiciqeyipumpmhxzlxnbqdbbv6u5uij4hy4wax64dmj7kvrhusiq6y`
  location=$(
    curl --fail --silent --show-error --head "http://127.0.0.1:${node_port}/webui/" |
      awk 'BEGIN { IGNORECASE = 1 } /^Location:/ { sub(/\r$/, ""); print $2; exit }'
  ) || error_exit "Failed to query Kubo Web UI redirect."

  cid=${location#/ipfs/}

  if [[ -z "$cid" || "$cid" == "$location" ]]; then
    error_exit "Failed to extract Web UI CID from redirect location: '$location'"
  fi

  printf '%s\n' "$cid"
}

download_web_ui_car() {
  local -r cid="$1"
  local -r download_dir="${2%/}"

  local -r target_url="https://ipfs.io/ipfs/${cid}?format=car&dag-scope=all"
  local -r archive_path="${download_dir}/webui-${cid}.car"

  if [[ -f "$archive_path" ]]; then
    echo ">> Web UI CAR file already exists: ${archive_path}" >&2
  else
    echo ">> Downloading Kubo Web UI with CID ${cid} from 'ipfs.io'..." >&2
    curl --fail --silent --show-error --location -H "Accept: application/vnd.ipld.car" \
      --output "$archive_path" "$target_url" ||
        error_exit "Failed to download Kubo Web UI CAR file from '${target_url}'."
  fi

  echo "$archive_path"
}

load_web_ui_car() {
  local -r car_file_path="$1"
  local -r ipfs_bin_path="$2"
  local -r node_dir="${3%/}"

  IPFS_PATH="$node_dir" "$ipfs_bin_path" dag import "$car_file_path"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare DOWNLOAD_DIR="${DOWNLOAD_DIR:-}" SWARM_DIR="${SWARM_DIR:-}"

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      -d | --download-dir)
        shift
        require_value "--download-dir" "${1:-}"
        DOWNLOAD_DIR=$1
        ;;
      -h | --help ) display_help ;;
      -s | --swarm-dir)
        shift
        require_value "--swarm-dir" "${1:-}"
        SWARM_DIR=$1
        ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

if [[ "${1:-}" == "--" ]]; then
  shift
fi

if [[ "$#" -gt 0 ]]; then
  error_exit "Unexpected argument: $1"
fi

check_requirements "curl" "awk"

readonly DOWNLOAD_DIR=${DOWNLOAD_DIR:-"/tmp/kubo/"}
readonly SWARM_DIR

require_option "$SWARM_DIR" "-s, --swarm-dir"

require_directory "$SWARM_DIR" "-s, --swarm-dir"

# Use the first node of the network, it will be propagated from it to other nodes afterwards
declare -r NODE_PORT=5001
declare -r NODE_DIR="${SWARM_DIR}/kubo-node-1"
declare -r IPFS_BIN="${SWARM_DIR%/}/bin/ipfs"

require_directory "$NODE_DIR" "Kubo node directory"

require_executable "$IPFS_BIN" "IPFS binary"

create_dir_if_not_exist "$DOWNLOAD_DIR"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo ">> Finding Kubo Web UI CID ..."
CID=$(find_web_ui_cid "$NODE_PORT")
readonly CID
echo ">> CID found: '$CID'"

CAR_FILE=$(download_web_ui_car "$CID" "$DOWNLOAD_DIR")
readonly CAR_FILE

echo ">> Loading Web UI ..."
load_web_ui_car "$CAR_FILE" "$IPFS_BIN" "$NODE_DIR"
echo ">> Web UI loaded in the first swarm node ('$NODE_DIR')"
