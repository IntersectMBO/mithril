#!/usr/bin/env bash
set -eu -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi


clippy_all_crates_all_features() {
    started_at=$(date +%s)
    local exit_code=0
    mapfile -t members < <(
    cargo metadata --no-deps --format-version 1 |
        jq -r '.packages[].name'
    )

    for package_name in "${members[@]}"; do
        #retrieve available features for this package
        mapfile -t available_features < <(
            cargo metadata --no-deps --format-version 1 |
                jq -r --arg package_name "$package_name" \
                    '.packages[] | select(.name == $package_name) | .features | keys[]'
        )

        tls_features=(
            rustls
            rustls-no-provider
            rustls-tls
            rustls-tls-manual-roots
            rustls-tls-native-roots
            rustls-tls-webpki-roots
            native-tls
            native-tls-alpn
            native-tls-no-alpn
            native-tls-vendored
            native-tls-vendored-no-alpn
        )

        filtered_features=()
        is_tls_feature_removed=false

        # Remove all TLS features.
        for available_feature in "${available_features[@]}"; do
            is_tls_feature=false

            for tls_feature in "${tls_features[@]}"; do
                if [[ "$available_feature" == "$tls_feature" ]]; then
                    is_tls_feature=true
                    is_tls_feature_removed=true
                    break
                fi
            done

            if [[ "$is_tls_feature" == false ]]; then
                filtered_features+=("$available_feature")
            fi
        done

        # Remove default feature since generating combinations will cover it anyway.
        if [[ " ${filtered_features[*]} " == *" default "* ]]; then
            mapfile -t filtered_features < <(
                printf '%s\n' "${filtered_features[@]}" | grep -v '^default$'
            )
        fi
        
        echo -e "Available features for package ${package_name}: ${available_features[*]}"
        echo -e "Filtered features for package ${package_name}: ${filtered_features[*]}"

        # Generate all features combinations
        feature_combinations=()
        if ((${#filtered_features[@]} > 0)); then
            mapfile -t feature_combinations < <(
                generate_combinations "${filtered_features[@]}"
            )
        fi

        # If any TLS feature was removed, add "rustls" to all combinations.
        if [[ "$is_tls_feature_removed" == true ]]; then
            mapfile -t feature_combinations < <(
                printf '%s\n' "${feature_combinations[@]}" | sed 's/^/rustls,/'
            )
        fi
        
        # Remove combinations that contains future_snark feature without rustls feature, as it will fail to compile.
        if ((${#feature_combinations[@]} > 0)); then
            mapfile -t feature_combinations < <(
                printf '%s\n' "${feature_combinations[@]}" |
                    awk -F',' '!(/(^|,)future_snark(,|$)/ && !/(^|,)rustls(,|$)/)'
            )
        fi

        # TODO force "future_snark" on mithril-stm ? otherwise cargo clippy --all-targets does not work 

        printf 'Feature combination: %s\n' "${feature_combinations[@]}"
        printf 'Total combinations: %d\n' "${#feature_combinations[@]}"

        for feature_combination in "${feature_combinations[@]}"; do
            echo -e "Running clippy for package: ${package_name} with features: ${feature_combination}"
            if ! cargo clippy --all-targets --package "${package_name}" --features "${feature_combination}" -- -D warnings; then
                exit_code=1
            fi
        done
        
    done

    finished_at=$(date +%s)
    elapsed_time=$((finished_at - started_at))
    echo "Clippy check completed in ${elapsed_time} seconds."

    return "$exit_code"
}

generate_combinations() {
    local -a features=("$@")
    local feature_count=${#features[@]}
    local combination_size mask selected_count feature_index combination

    for ((combination_size = 1; combination_size <= feature_count; combination_size++)); do
        for ((mask = 1; mask < (1 << feature_count); mask++)); do
            selected_count=0

            for ((feature_index = 0; feature_index < feature_count; feature_index++)); do
                if ((mask & (1 << feature_index))); then
                    ((selected_count += 1))
                fi
            done

            ((selected_count == combination_size)) || continue

            combination=""
            for ((feature_index = 0; feature_index < feature_count; feature_index++)); do
                if ((mask & (1 << feature_index))); then
                    [[ -n "$combination" ]] && combination+=","
                    combination+="${features[feature_index]}"
                fi
            done

            printf '%s\n' "$combination"
        done
    done
}

clippy_all_crates_all_features
exit $?
