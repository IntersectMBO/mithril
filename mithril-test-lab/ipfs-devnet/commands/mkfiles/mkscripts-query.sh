#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

display_help() {
    echo "Create the scripts that query information from the Kubo swarm nodes"
    echo
    echo "Usage: $0 [OPTIONS] <node_dir>..."
    echo
    echo "Options:"
    echo "  -h, --help                 Print this help"
    echo "  -o, --output <dir>         Output directory [default='.']"
    echo
    exit 0
}

# Function to display an error message and exit
error_exit() {
  echo "$1" 1>&2
  exit 1
}

shell_quote() {
  printf '%q' "$1"
}

write_nodes_paths_declaration() {
  printf 'readonly NODES_PATHS=('

  local node_path
  for node_path in "$@"; do
    printf ' %s' "$(shell_quote "$node_path")"
  done

  printf ' )\n'
}

write_log_script() {
  local -r output_dir="${1%/}"
  shift
  local -a nodes_paths=("$@")

  local -r script_path="${output_dir}/log.sh"

  {
    cat <<'EOF'
#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

display_help() {
    echo "Tail the logs from all Kubo nodes"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -h, --help                Print this help"
    echo "  -l, --lines <int>         Number of lines to tail from each nodes log file [default: '10']"
    echo "  -s, --separator <string>  Separator to print between each log file [default: 70 '-']"
    echo
    echo "Environment variables:"
    echo "  TAIL_LINES                Number of lines to tail from each nodes log file"
    echo "  SEPARATOR                 Separator to print between each log file"
    echo
    echo "Options and environment variables can be mixed; when both are provided for the same setting,"
    echo "the command-line option takes priority."
    echo
    exit 0
}

error_exit() {
  echo "$1" 1>&2
  exit 1
}

EOF

    write_nodes_paths_declaration "${nodes_paths[@]}"

    cat <<'EOF'

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare TAIL_LINES="${TAIL_LINES:-}" SEPARATOR="${SEPARATOR:-}"

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
      -h | --help ) display_help ;;
      -l | --lines) shift; TAIL_LINES=${1:-} ;;
      -s | --separator) shift; SEPARATOR=${1:-} ;;
      *) error_exit "Unknown option: $1" ;;
    esac
    shift
done

readonly TAIL_LINES=${TAIL_LINES:-10}
readonly SEPARATOR=${SEPARATOR:-"----------------------------------------------------------------------"}

if ! [[ "$TAIL_LINES" =~ ^[0-9]+$ ]]; then
  error_exit "Invalid value for --lines: '$TAIL_LINES'. Expected a positive integer."
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

for node_path in "${NODES_PATHS[@]}"; do
  log_file="${node_path%/}/ipfs.log"

  echo "${SEPARATOR}"
  echo "tail -n ${TAIL_LINES} ${log_file}"
  echo "${SEPARATOR}"

  if [[ -f "$log_file" ]]; then
    tail -n "${TAIL_LINES}" "${log_file}"
  else
    echo "Skipping Kubo node '$node_path': log file '$log_file' was not found. Is the swarm running?"
  fi
  echo "${SEPARATOR}"
  echo
done
EOF
  } > "$script_path"

  chmod +x "$script_path"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

declare OUTPUT_DIR=""
declare -a NODES_PATHS=()

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do case "$1" in
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

if [[ ! -d "$OUTPUT_DIR" ]]; then
  error_exit "Output is not a directory or does not exist: '$OUTPUT_DIR'"
fi

if [[ "${#NODES_PATHS[@]}" -eq 0 ]]; then
  error_exit "Missing node directories"
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

write_log_script "$OUTPUT_DIR" "${NODES_PATHS[@]}"

echo ">> Created: ${OUTPUT_DIR%/}/log.sh"
