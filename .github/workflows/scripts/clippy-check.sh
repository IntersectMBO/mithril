#!/usr/bin/env bash
set -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi


clippy_all_crates() {
    local exit_code=0
    mapfile -t members < <(
    cargo metadata --no-deps --format-version 1 |
        jq -r '.packages[].name'
    )
    
    for package_name in "${members[@]}"; do
        additional_args=()
        if [[ " mithril-client " == *" ${package_name} "* ]]; then
            additional_args+=(--features rustls)
        fi

        if [[ " mithril-stm " == *" ${package_name} "* ]]; then
            additional_args+=(--features "future_snark,rustls,benchmark-internals")
        fi
        
        echo -e " Running clippy for package: ${package_name}"
        if ! cargo clippy --all-targets --package "${package_name}" "${additional_args[@]}" -- -D warnings; then
            echo -e " Clippy check failed for package: ${package_name}"
            exit_code=1
        fi
    done

    return "$exit_code"
}

clippy_all_crates
exit $?
