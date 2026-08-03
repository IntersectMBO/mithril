#!/usr/bin/env bash
set +a -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

display_help() {
  echo "Run a generated Kubo swarm script"
  echo
  echo "Usage: $0 --command <log|start|stop> [OPTIONS] [-- <generated-script-options>...]"
  echo
  echo "Options:"
  echo "  -c, --command <command>    Generated script command to run: log, start, stop (required)"
  echo "  -h, --help                 Print this help"
  echo "  -s, --swarm-dir <dir>      Directory that contains the swarm nodes (required)"
  echo
  echo "Environment variables:"
  echo "  SWARM_DIR                  Directory that contains the swarm nodes"
  echo
  echo "Arguments after '--' are forwarded to the generated script."
  echo
  exit 0
}

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

require_swarm_dir() {
  local -r swarm_dir="$1"

  if [[ -z "$swarm_dir" ]]; then
    error_exit "Missing required option: -s, --swarm-dir"
  fi
}

require_command() {
  local -r command="$1"

  if [[ -z "$command" ]]; then
    error_exit "Missing required option: -c, --command"
  fi

  case "$command" in
    log | start | stop) : ;;
    *) error_exit "Invalid value for --command: '$command'. Expected one of: log, start, stop." ;;
  esac
}

# ---------------------------------------------------------------------------
# Parameter parsing
# ---------------------------------------------------------------------------

declare command="" swarm_dir="${SWARM_DIR:-}"
declare -a forwarded_args=()

while [[ "${1:-}" == -* && ! "${1:-}" == "--" ]]; do
  case "$1" in
    -c | --command)
      shift
      require_value "--command" "${1:-}"
      command=$1
      ;;
    -h | --help) display_help ;;
    -s | --swarm-dir)
      shift
      require_value "--swarm-dir" "${1:-}"
      swarm_dir=$1
      ;;
    *) error_exit "Unknown option: $1" ;;
  esac
  shift
done

require_command "$command"

if [[ "${1:-}" == "--" ]]; then
  shift
  forwarded_args=("$@")
elif [[ "$#" -gt 0 ]]; then
  error_exit "Unexpected argument for '$command': $1"
fi

if [[ "$command" == "stop" && "${#forwarded_args[@]}" -gt 0 ]]; then
  error_exit "Unexpected forwarded argument for 'stop': ${forwarded_args[0]}"
fi

require_swarm_dir "$swarm_dir"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

declare -r generated_script="${swarm_dir%/}/${command}.sh"

if [[ ! -x "$generated_script" ]]; then
  error_exit "Generated ${command} script is not executable or does not exist: '$generated_script'. Run 'ipfs-devnet.sh init' first."
fi

exec bash "$generated_script" "${forwarded_args[@]}"
