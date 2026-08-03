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
    command -v shasum >/dev/null ||
        error_exit "It seems 'shasum' is not installed or not in the path.";
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

find_target_os() {
  # supported os are: linux and darwin
  local -r OS="$(uname -s)"
  local OS_CODE
  OS_CODE="$(echo "$OS" | awk '{print tolower($0)}')"

  case "$OS" in
    Linux) : ;;
    Darwin) : ;;
    *) error_exit "Unsupported ipfs-devnet operating system $OS" ;;
  esac

  echo "$OS_CODE"
}

find_target_arch() {
  # supported archs are: amd64 and arm64
  local -r ARCH="$(uname -m)"

  local ARCH_NAME
  case "$ARCH" in
    x86_64) ARCH_NAME="amd64" ;;
    arm64|aarch64) ARCH_NAME="arm64" ;;
    *) error_exit "Unsupported ipfs-devnet architecture: $ARCH" ;;
  esac

  echo "$ARCH_NAME"
}

format_archive_name() {
  local -r version="$1"
  local -r os="$2"
  local -r arch="$3"

  echo "${BIN_NAME}_${version}_${os}-${arch}.tar.gz"
}

download_bin_archive() {
  local -r version="$1"
  local -r os="$2"
  local -r arch="$3"
  local -r download_dir="${4%/}"

  # example url: https://dist.ipfs.tech/kubo/v0.42.0/kubo_v0.42.0_linux-arm64.tar.gz
  local -r target_url="${IPFS_DISTRIBUTIONS_CDN}/${BIN_NAME}/${version}/$(format_archive_name "$version" "$os" "$arch")"
  local -r checksum_target_url="${target_url}.sha512"
  local -r archive_path="${download_dir}/$(format_archive_name "$version" "$os" "$arch")"

  local expected_checksum
  expected_checksum=$(
    curl --fail --silent --show-error --location "$checksum_target_url" |
      awk '{ print $1; exit }'
  ) || error_exit "Failed to download '${BIN_NAME}' checksum from '${checksum_target_url}'."

  if [[ -f "$archive_path" ]]; then
    echo ">> Archive already exists, verifying checksum: ${archive_path}" >&2
  else
    echo ">> Downloading ${BIN_NAME} ${version} from ${target_url}..." >&2
    curl --fail --silent --show-error --location \
      --output "$archive_path" "$target_url" ||
        error_exit "Failed to download '${BIN_NAME}' archive from '${target_url}'."
  fi

  verify_checksum "$expected_checksum" "$archive_path"

  echo "$archive_path"
}

verify_checksum() {
  local -r expected_checksum="$1"
  local -r file_to_check="$2"

  local actual_checksum
  actual_checksum=$(shasum -a 512 "$file_to_check" | awk '{ print $1 }')

  if [[ "$actual_checksum" != "$expected_checksum" ]]; then
    rm -f "$file_to_check"
    error_exit "Checksum verification failed for '${file_to_check}'."
  fi

  echo "Checksum verified for: ${file_to_check}" >&2
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

if [[ ! -e "$OUTPUT_DIR" ]]; then
  mkdir -p -- "${OUTPUT_DIR%/}"
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

OS="$(find_target_os)"
ARCH="$(find_target_arch)"
readonly OS ARCH

echo ">> KUBO_VERSION: ${KUBO_VERSION}"
echo ">> DOWNLOAD_DIR: ${DOWNLOAD_DIR}"
echo ">> OUTPUT_DIR: ${OUTPUT_DIR}"
echo ">> OS: ${OS}"
echo ">> ARCH: ${ARCH}"

DOWNLOADED_ARCHIVE=$(download_bin_archive "$KUBO_VERSION" "$OS" "$ARCH" "$DOWNLOAD_DIR")
readonly DOWNLOADED_ARCHIVE

echo ">> Downloaded archive to: $DOWNLOADED_ARCHIVE"
tar xzf "$DOWNLOADED_ARCHIVE" -C "${OUTPUT_DIR%/}/" --strip-components=1
echo ">> Extracted archive to ${OUTPUT_DIR}"
