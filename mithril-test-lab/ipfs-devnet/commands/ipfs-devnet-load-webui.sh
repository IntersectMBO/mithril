#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

# Script directory variable (absolute path)
SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
readonly SCRIPT_DIRECTORY

# shellcheck source=./lib/common.sh
source "${SCRIPT_DIRECTORY}/lib/common.sh"

readonly GITHUB_API_RELEASES="https://api.github.com/repos/ipfs/ipfs-webui/releases"
readonly CONNECT_TIMEOUT_SECONDS=10

display_help() {
    echo "Download and load the Kubo Web UI on the private IPFS network"
    echo
    echo "The Web UI CAR archive is downloaded from the ipfs-webui GitHub release matching the Web UI CID"
    echo "expected by the running Kubo node."
    echo
    echo "IMPORTANT: The IPFS devnet must be running."
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
  # example: `http://127.0.0.1:5001/ipfs/bafybeiciqeyipumpmhxzlxnbqdbbv6u5uij4hy4wax64dmj7kvrhusiq6y`
  location=$(
    curl --fail --silent --show-error --head --output /dev/null --write-out '%{redirect_url}' \
      "http://127.0.0.1:${node_port}/webui/"
  ) || error_exit "Failed to query Kubo Web UI redirect."

  cid=${location##*/ipfs/}

  if [[ -z "$cid" || "$cid" == "$location" ]]; then
    error_exit "Failed to extract Web UI CID from redirect location: '$location'"
  fi

  printf '%s\n' "$cid"
}

fetch() {
  curl --fail --silent --show-error --location --connect-timeout "$CONNECT_TIMEOUT_SECONDS" "$@"
}

find_web_ui_car_url_from_github() {
  local -r cid="$1"
  local releases car_url

  releases=$(fetch -H "Accept: application/vnd.github+json" "${GITHUB_API_RELEASES}?per_page=100") ||
    error_exit "Failed to list ipfs-webui releases from '${GITHUB_API_RELEASES}'."

  # Each ipfs-webui release body states the CID of its build (e.g. "CID `bafybei...`")
  car_url=$(
    jq --raw-output --arg cid "$cid" '
      first(
        .[]
        | select((.body // "") | contains($cid))
        | .assets[]
        | select(.name | endswith(".car"))
        | .browser_download_url
      ) // empty' <<< "$releases"
  ) || error_exit "Failed to parse ipfs-webui releases from '${GITHUB_API_RELEASES}'."

  if [[ -z "$car_url" ]]; then
    error_exit "No ipfs-webui GitHub release found for CID '${cid}' (searched ${GITHUB_API_RELEASES})."
  fi

  printf '%s\n' "$car_url"
}

download_web_ui_car_from_github() {
  local -r cid="$1"
  local -r download_dir="${2%/}"

  local -r archive_path="${download_dir}/webui-${cid}.car"

  if [[ -f "$archive_path" ]]; then
    echo ">> Web UI CAR file already exists: ${archive_path}" >&2
  else
    local target_url
    target_url=$(find_web_ui_car_url_from_github "$cid")

    echo ">> Downloading Kubo Web UI with CID ${cid} from '${target_url}'..." >&2
    if ! fetch --output "$archive_path" "$target_url"; then
      rm -f "$archive_path"
      error_exit "Failed to download Kubo Web UI CAR file from '${target_url}'."
    fi
  fi

  echo "$archive_path"
}

load_web_ui_car() {
  local -r car_file_path="$1"
  local -r ipfs_bin_path="$2"
  local -r node_dir="${3%/}"
  local -r expected_cid="$4"
  local import_output

  import_output=$(IPFS_PATH="$node_dir" "$ipfs_bin_path" dag import --pin-roots --enc=json "$car_file_path") ||
    error_exit "Failed to import Web UI CAR file '${car_file_path}'."
  echo "$import_output"

  # Example of expected output: `{"Root":{"Cid":{"/":"bafybeiciqeyipumpmhxzlxnbqdbbv6u5uij4hy4wax64dmj7kvrhusiq6y"},"PinErrorMsg":""}}`
  if ! jq --null-input --exit-status --arg cid "$expected_cid" \
    '[inputs | .Root? | select(.Cid["/"] == $cid and .PinErrorMsg == "")] | any' <<< "$import_output" >/dev/null; then
    rm -f "$car_file_path"
    error_exit "Imported CAR file root does not match the expected Web UI CID '${expected_cid}', CAR file discarded."
  fi
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

check_requirements "curl" "jq"

readonly DOWNLOAD_DIR=${DOWNLOAD_DIR:-"/tmp/kubo/"}
readonly SWARM_DIR

require_option "$SWARM_DIR" "-s, --swarm-dir"

require_directory "$SWARM_DIR" "-s, --swarm-dir"

# Use the first node of the network, it will be propagated from it to other nodes afterwards
declare -r NODE_PORT=5001
declare -r NODE_DIR="${SWARM_DIR%/}/kubo-node-1"
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

CAR_FILE=$(download_web_ui_car_from_github "$CID" "$DOWNLOAD_DIR")
readonly CAR_FILE

echo ">> Loading Web UI ..."
load_web_ui_car "$CAR_FILE" "$IPFS_BIN" "$NODE_DIR" "$CID"
echo ">> Web UI loaded in the first swarm node ('$NODE_DIR')"
