# Shared functions by the IPFS devnet scripts

error_exit() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_value() {
  local -r option="$1"
  local -r value="${2:-}"

  if [[ -z "$value" ]]; then
    error_exit "Missing value for option: $option"
  fi
}

check_requirements() {
  for tool in "$@"; do
    command -v "$tool" >/dev/null ||
        error_exit "It seems '$tool' is not installed or not in the path.";
  done
}

require_executable() {
  local -r path="$1"
  local -r label="$2"

  if [[ ! -x "$path" ]]; then
    error_exit "$label is not executable or does not exist: '$path'"
  fi
}

require_option() {
  local -r option="$1"
  local -r label="$2"

  if [[ -z "$option" ]]; then
    error_exit "Missing required option: $label"
  fi
}

require_directory() {
  local -r path="$1"
  local -r label="$2"

  if [[ ! -d "$path" ]]; then
    error_exit "$label is not a directory or does not exist: '$path'"
  fi
}

create_dir_if_not_exist() {
  local -r dir="$1"

  if [[ ! -e "$dir" ]]; then
    mkdir -p -- "${dir%/}"
  fi
}

shell_quote() {
  printf '%q' "$1"
}

require_positive_integer() {
  local -r option="$1"
  local -r value="$2"

  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    error_exit "Invalid value for $option: '$value'. Expected a positive integer."
  fi

  if (( value < 1 )); then
    error_exit "Invalid value for $option: '$value'. Expected a positive integer."
  fi
}

write_nodes_paths_declaration() {
  printf 'readonly NODES_PATHS=('

  local node_path
  for node_path in "$@"; do
    printf ' %s' "$(shell_quote "$node_path")"
  done

  printf ' )\n'
}
