#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

# Script directory variable (absolute path)
SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
readonly SCRIPT_DIRECTORY

# shellcheck source=../lib/common.sh
source "${SCRIPT_DIRECTORY}/../lib/common.sh"

readonly BIN_NAME="kubo"
readonly IPFS_DISTRIBUTIONS_CDN="https://dist.ipfs.tech"
readonly GITHUB_RELEASES="https://github.com/ipfs/kubo/releases"
readonly CONNECT_TIMEOUT_SECONDS=10

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

fetch() {
  curl --fail --silent --show-error --location --connect-timeout "$CONNECT_TIMEOUT_SECONDS" "$@"
}

find_last_released_version_from_cdn() {
  # The file have the following structure: one version per line, from earliest to latest, named "vXX.YY.ZZ[-rcN]" (e.g "v0.31.0-rc2" or "v0.33.2")
  fetch "${IPFS_DISTRIBUTIONS_CDN}/${BIN_NAME}/versions" |
    awk '/^v[0-9]+[.][0-9]+[.][0-9]+$/ { latest = $0 } END { if (latest != "") print latest; else exit 1 }'
}

find_last_released_version_from_github() {
  # The latest release url redirects to the url of its tag (e.g. "https://github.com/ipfs/kubo/releases/tag/v0.43.1")
  fetch --head --output /dev/null --write-out '%{url_effective}' "${GITHUB_RELEASES}/latest" |
    awk -F/ '$NF ~ /^v[0-9]+[.][0-9]+[.][0-9]+$/ { print $NF; found = 1 } END { if (!found) exit 1 }'
}

find_last_released_version() {
  local latest_version
  latest_version=$(find_last_released_version_from_cdn) ||
    latest_version=$(find_last_released_version_from_github) ||
    error_exit "Could not find a released version for '${BIN_NAME}' from '${IPFS_DISTRIBUTIONS_CDN}' or '${GITHUB_RELEASES}'."

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

download_bin_archive_from() {
  local -r target_url="$1"
  local -r archive_path="$2"

  local expected_checksum
  expected_checksum=$(fetch "${target_url}.sha512" | awk '{ print $1; exit }') || return 1

  if [[ -f "$archive_path" ]]; then
    echo ">> Archive already exists, verifying checksum: ${archive_path}" >&2
    verify_checksum "$expected_checksum" "$archive_path" && return 0
    echo ">> Discarding the archive with an invalid checksum: ${archive_path}" >&2
    rm -f "$archive_path"
  fi

  echo ">> Downloading ${BIN_NAME} from ${target_url}..." >&2
  if fetch --output "$archive_path" "$target_url" && verify_checksum "$expected_checksum" "$archive_path"; then
    return 0
  fi

  rm -f "$archive_path"
  return 1
}

download_bin_archive() {
  local -r version="$1"
  local -r os="$2"
  local -r arch="$3"
  local -r download_dir="${4%/}"

  local archive_name
  archive_name=$(format_archive_name "$version" "$os" "$arch")
  local -r archive_path="${download_dir}/${archive_name}"

  # example url: https://dist.ipfs.tech/kubo/v0.42.0/kubo_v0.42.0_linux-arm64.tar.gz
  local -r cdn_url="${IPFS_DISTRIBUTIONS_CDN}/${BIN_NAME}/${version}/${archive_name}"
  # example url: https://github.com/ipfs/kubo/releases/download/v0.42.0/kubo_v0.42.0_linux-arm64.tar.gz
  local -r github_url="${GITHUB_RELEASES}/download/${version}/${archive_name}"

  download_bin_archive_from "$cdn_url" "$archive_path" ||
    download_bin_archive_from "$github_url" "$archive_path" ||
    error_exit "Failed to download '${BIN_NAME}' archive from '${cdn_url}' or '${github_url}'."

  echo "$archive_path"
}

verify_checksum() {
  local -r expected_checksum="$1"
  local -r file_to_check="$2"

  local actual_checksum
  actual_checksum=$(shasum -a 512 "$file_to_check" | awk '{ print $1 }')

  if [[ "$actual_checksum" != "$expected_checksum" ]]; then
    echo "Checksum verification failed for: ${file_to_check}" >&2
    return 1
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

check_requirements "awk" "curl" "shasum" "tar"

readonly DOWNLOAD_DIR=${DOWNLOAD_DIR:-"."} OUTPUT_DIR=${OUTPUT_DIR:-"."}

if [[ -z "$KUBO_VERSION" ]]; then
  KUBO_VERSION=$(find_last_released_version)
fi
readonly KUBO_VERSION

create_dir_if_not_exist "$OUTPUT_DIR"

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
