#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

readonly BIN_NAME="kubo"
readonly IPFS_DISTRIBUTIONS_CDN="https://dist.ipfs.tech"

display_help() {
    echo "Download the latest kubo ipfs node to a target location"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -d, --download-dir <dir>   Directory where bin archive will be download [default='.']"
    echo "  -h, --help                 Print this help"
    echo "  -o, --output <dir>         Output directory [default='.']"
    echo "  -v, --version <version>    Specific version to download (omit to download the latest version)"
    echo
    exit 0
}

# Function to display an error message and exit
error_exit() {
  echo "$1" 1>&2
  exit 1
}

# Function to check that required tools are installed
check_requirements() {
    command -v curl >/dev/null ||
        error_exit "It seems 'curl' is not installed or not in the path.";
    command -v awk >/dev/null ||
        error_exit "It seems 'awk' is not installed or not in the path.";
}

find_last_released_version() {
  # The file have the following structure: one version per line, from earliest to latest, named "vXX.YY.ZZ[-rcN]" (e.g "v0.31.0-rc2" or "v0.33.2")
  local -r VERSIONS_LIST_URL="${IPFS_DISTRIBUTIONS_CDN}/${BIN_NAME}/versions"

  local latest_version
  latest_version=$(
    curl --fail --silent --show-error --location "$VERSIONS_LIST_URL" |
      awk '/^v[0-9]+[.][0-9]+[.][0-9]+$/ { latest = $0 } END { if (latest != "") print latest; else exit 1 }'
  ) || error_exit "Could not find a released version for '${BIN_NAME}' from '${VERSIONS_LIST_URL}'."

  echo "$latest_version"
}

download_bin_archive() {
  local -r version="$1"
  local -r os="$2"
  local -r arch="$3"

  # example url: https://dist.ipfs.tech/kubo/v0.42.0/kubo_v0.42.0_linux-arm64.tar.gz
  local -r target_url="${IPFS_DISTRIBUTIONS_CDN}/${BIN_NAME}/${version}/${BIN_NAME}_${version}_${os}-${arch}.tar.gz"

  # Todo
}


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare DOWNLOAD_DIR="" KUBO_VERSION="" OUTPUT_DIR=""

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      -d | --download-dir) shift; DOWNLOAD_DIR=${1:-} ;;
      -h | --help ) display_help ;;
      -o | --output) shift; OUTPUT_DIR=${1:-} ;;
      -v | --version) shift; KUBO_VERSION=${1:-} ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

readonly DOWNLOAD_DIR=${DOWNLOAD_DIR:-"."} OUTPUT_DIR=${OUTPUT_DIR:-"."}
readonly KUBO_VERSION=${KUBO_VERSION:-$(find_last_released_version)}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo ">> KUBO_VERSION: ${KUBO_VERSION}"
echo ">> DOWNLOAD_DIR: ${DOWNLOAD_DIR}"
echo ">> OUTPUT_DIR: ${OUTPUT_DIR}"
