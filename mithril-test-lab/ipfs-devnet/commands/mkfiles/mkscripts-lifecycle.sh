#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

# Script directory variable (absolute path)
SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
readonly SCRIPT_DIRECTORY

# shellcheck source=../lib/common.sh
source "${SCRIPT_DIRECTORY}/../lib/common.sh"

display_help() {
    echo "Create the scripts to handle the lifecycle of the Kubo nodes (start, stop)"
    echo
    echo "Usage: $0 [OPTIONS] <node_dir>..."
    echo
    echo "Options:"
    echo "  -b, --ipfs-bin-path <path> Path to the kubo ipfs binary (required)"
    echo "  -h, --help                 Print this help"
    echo "  -o, --output <dir>         Output directory [default='.']"
    echo
    exit 0
}

write_start_script() {
  local -r output_dir="${1%/}"
  local -r ipfs_bin="$2"
  shift 2
  local -a nodes_paths=("$@")

  local script_path="${output_dir}/start.sh"

  {
    cat <<'EOF'
#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

display_help() {
    echo "Start the Kubo nodes"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -h, --help                Print this help"
    echo "  --log-level <level>       Kubo log level [default='info']"
    echo
    echo "Allowed log levels: debug, info, warn, error"
    echo
    exit 0
}

error_exit() {
  echo "$1" 1>&2
  exit 1
}

EOF

    printf 'readonly IPFS_BIN=%s\n' "$(shell_quote "$ipfs_bin")"
    write_nodes_paths_declaration "${nodes_paths[@]}"

    cat <<'EOF'

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare LOG_LEVEL=""

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      -h | --help ) display_help ;;
      --log-level) shift; LOG_LEVEL=${1:-} ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

readonly LOG_LEVEL=${LOG_LEVEL:-"info"}

case "$LOG_LEVEL" in
  debug | info | warn | error) : ;;
  *) error_exit "Invalid value for --log-level: '$LOG_LEVEL'. Expected one of: debug, info, warn, error." ;;
esac

if [[ ! -x "$IPFS_BIN" ]]; then
  error_exit "IPFS binary is not executable or does not exist: '$IPFS_BIN'"
fi

for node_path in "${NODES_PATHS[@]}"; do
  if [[ ! -d "$node_path" ]]; then
    error_exit "Node directory does not exist: '$node_path'"
  fi

  pid_file="${node_path%/}/ipfs.pid"
  log_file="${node_path%/}/ipfs.log"

  if [[ -f "$pid_file" ]]; then
    pid="$(cat "$pid_file")"
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      echo ">> Kubo node already running: '$node_path' pid=$pid"
      continue
    fi

    rm -f -- "$pid_file"
  fi

  echo ">> Starting Kubo node: '$node_path'"
  IPFS_PATH="$node_path" LIBP2P_FORCE_PNET=1 GOLOG_LOG_LEVEL="$LOG_LEVEL" nohup "$IPFS_BIN" daemon >"$log_file" 2>&1 &
  pid="$!"

  printf '%s\n' "$pid" >"$pid_file"
  echo ">> Started Kubo node: '$node_path' pid=$pid"
done
EOF
  } > "$script_path"

  chmod +x "$script_path"
}

write_stop_script() {
  local -r output_dir="${1%/}"
  shift
  local -a nodes_paths=("$@")

  local script_path="${output_dir}/stop.sh"

  {
    cat <<'EOF'
#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

EOF

    write_nodes_paths_declaration "${nodes_paths[@]}"

    cat <<'EOF'

for node_path in "${NODES_PATHS[@]}"; do
  pid_file="${node_path%/}/ipfs.pid"

  if [[ ! -f "$pid_file" ]]; then
    echo ">> Kubo node is not running: '$node_path'"
    continue
  fi

  pid="$(cat "$pid_file")"

  if ! [[ "$pid" =~ ^[0-9]+$ ]]; then
    echo ">> Invalid pid file for Kubo node: '$node_path'"
    rm -f -- "$pid_file"
    continue
  fi

  if ! kill -0 "$pid" 2>/dev/null; then
    echo ">> Kubo node is not running: '$node_path' pid=$pid"
    rm -f -- "$pid_file"
    continue
  fi

  echo ">> Stopping Kubo node: '$node_path'"
  if kill "$pid" 2>/dev/null; then
    rm -f -- "$pid_file"
  else
    echo ">> Failed to stop Kubo node: '$node_path' pid=$pid"
  fi
done
EOF
  } > "$script_path"

  chmod +x "$script_path"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare IPFS_BIN="" OUTPUT_DIR=""
declare -a NODES_PATHS=()

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      -b | --ipfs-bin-path) shift; IPFS_BIN=${1:-} ;;
      -h | --help ) display_help ;;
      -o | --output) shift; OUTPUT_DIR=${1:-} ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

if [[ "${1:-}" == "--" ]]; then
  shift
fi

while [[ "$#" -gt 0 ]]; do
  NODES_PATHS+=("$1")
  shift
done

readonly OUTPUT_DIR=${OUTPUT_DIR:-"."}

require_option "$IPFS_BIN" "-b, --ipfs-bin-path"

require_executable "$IPFS_BIN" "IPFS binary"

require_directory "$OUTPUT_DIR" "Output"

if [[ "${#NODES_PATHS[@]}" -eq 0 ]]; then
  error_exit "Missing node directories"
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

write_start_script "$OUTPUT_DIR" "$IPFS_BIN" "${NODES_PATHS[@]}"
write_stop_script "$OUTPUT_DIR" "${NODES_PATHS[@]}"

echo ">> Created: ${OUTPUT_DIR%/}/start.sh"
echo ">> Created: ${OUTPUT_DIR%/}/stop.sh"
