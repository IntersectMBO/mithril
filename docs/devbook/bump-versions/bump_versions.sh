#!/usr/bin/env bash
set +a -u -o pipefail

if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

display_help() {
    local -r default_diff_ref=$1
    local -r resources_to_check=$2

    echo "Check crates, js packages, and openapi changes against '$default_diff_ref' (default) and update their versions"
    echo
    echo "By default, no changes are made (dry-run mode), use '--run' to apply the changes."
    echo "At the end of the script, the commit message to used is displayed, use '--commit' to commit the changes."
    echo "Check crates will look for this pattern '$resources_to_check'."
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --run: to apply the changes (default is dry-run)"
    echo "  --commit: to commit the changes"
    echo "  --ref: to specify the reference branch/commit (default is '$default_diff_ref')"
    echo
    echo "Prerequisites:"
    echo " 'cargo-get' needs to be installed ('cargo install cargo-get')."
    echo
    exit 0;
}

check_requirements() {
    cargo get --version 2> /dev/null 1> /dev/null ||
        error "It seems 'cargo-get' is not installed or not in the path (to install run: 'cargo install cargo-get').";
}

error() {
    echo "ERROR: $1";
    exit 1;
}

readonly ORANGE="\e[1;33m"
readonly GREEN="\e[1;32m"
readonly RESET="\e[0m"

readonly OPEN_API_FILE=openapi.yaml
declare OPEN_API_UPDATE=""
declare OPEN_API_UPDATE_MESSAGE=""

readonly INFRA_VERSION_FILE=mithril-infra/assets/infra.version
declare INFRA_UPDATE=""
declare INFRA_UPDATE_MESSAGE=""

readonly DEVNET_VERSION_FILE=mithril-test-lab/cardano-devnet/VERSION
declare DEVNET_UPDATE=""
declare DEVNET_UPDATE_MESSAGE=""

readonly BENCHMARK_VERSION_FILE=mithril-test-lab/benchmark/aggregator-prover/VERSION
declare BENCHMARK_UPDATE=""
declare BENCHMARK_UPDATE_MESSAGE=""

readonly IPFS_DEVNET_VERSION_FILE=mithril-test-lab/ipfs-devnet/VERSION
declare IPFS_DEVNET_UPDATE=""
declare IPFS_DEVNET_UPDATE_MESSAGE=""

readonly DEFAULT_DIFF_REF="origin/main"
readonly RESOURCES_TO_CHECK="(src/|tests/|benches/|Cargo.toml)"

update_crate_versions() {
    # NOTE
    # `cargo get workspace.members` display the list of path to crates in the workspace.
    # for the `cargo set-version` command, we need the name of the module (last element of the path).
    #
    local -r dry_run=$1
    local -r -n files_modify=$2
    local -r -a members="$(cargo get workspace.members --delimiter " ")"
    local -i nb_files_modify=0
    local package_name

    local cargo_options=""
    if [ true = "$dry_run" ]
    then
        cargo_options=--dry-run
    fi

    for member in $members
    do
        nb_files_modify=$(echo "$files_modify" | grep -E -c "^$member/$RESOURCES_TO_CHECK")
        if [[ $nb_files_modify -gt 0 ]]
        then
            package_name=${member##*/}
            cargo set-version $cargo_options --package "${package_name##*/}" --bump patch
        fi

    done
}

update_package_json_versions() {
    local -r dry_run=$1
    local -r -n files_modify=$2
    local -r -n package_json_files=$3
    local -r -a members=$(echo "$package_json_files" | xargs dirname)
    local -i nb_files_modify=0

    local package_name version_line patch_number next_patch_number new_version must_update_package_locks
    must_update_package_locks=false

    for member in $members
    do
        nb_files_modify=$(echo "$files_modify" | grep -c "^$member/")
        if [[ $nb_files_modify -gt 0 ]]
        then
            if [[ $member == "mithril-client-wasm" ]]
            then
              must_update_package_locks=true
            fi

            version_line="$(grep -E "\"version\": \"[0-9]+\.[0-9]+\.[0-9]+\"" "$member/package.json" | sed "s/[\",]//g")"
            patch_number=$(echo "$version_line" | cut -d . -f 3)
            next_patch_number=$((patch_number + 1))
            new_version=$(echo "$version_line" | cut -d . -f 1-2).$next_patch_number
            echo -e "   ${GREEN}Upgrading${RESET} [js] $member from ${version_line##*version: } to ${new_version##*version: }"

            if [ true = "$dry_run" ]
            then
              echo -e "${ORANGE}warning${RESET}: aborting $member update due to dry run"
            else
              package_name=${member##*/}
              pushd "$member" > /dev/null || exit
              npm --no-git-tag-version version patch 1>/dev/null
              popd > /dev/null || exit
            fi
        fi
    done

    if [ true = "$must_update_package_locks" ]
    then
      echo -e "${ORANGE}mithril-client-wasm version changed${RESET}: updating package-lock.json files to reflect the new version"

      for member in $members
      do
          if [[ false = "$dry_run" && -e "$member/package-lock.json" ]]
          then
              package_name=${member##*/}
              pushd "$member" > /dev/null || exit
              npm install 1>/dev/null
              popd > /dev/null || exit
          fi
      done
    fi
}

update_openapi_version() {
    local -r dry_run=$1
    local -r version_line=$(grep -E "version: [0-9]+\.[0-9]+\.[0-9]+" $OPEN_API_FILE)
    local -r patch_number=$(echo "$version_line" | cut -d . -f 3)
    local -r next_patch_number=$((patch_number + 1))
    local -r new_version=$(echo "$version_line" | cut -d . -f 1-2).$next_patch_number

    echo -e "   ${GREEN}Upgrading${RESET} $OPEN_API_FILE from ${version_line##*version: } to ${new_version##*version: }"
    if [ true = "$dry_run" ]
    then
        echo -e "${ORANGE}warning${RESET}: aborting $OPEN_API_FILE update due to dry run"
    else
        sed -i "s/$version_line/$new_version/g" $OPEN_API_FILE
    fi
    OPEN_API_UPDATE="\n* $OPEN_API_FILE from \`${version_line##*version: }\` to \`${new_version##*version: }\`"
    OPEN_API_UPDATE_MESSAGE=" and \`$OPEN_API_FILE\` version"
}

update_plain_version_file() {
    local -r dry_run=$1
    local -r version_file=$2
    local -r var_name_prefix=$3

    local -r version_line=$(head -n 1 "$version_file")
    local -r patch_number=$(echo "$version_line" | cut -d . -f 3)
    local -r next_patch_number=$((patch_number + 1))
    local -r new_version=$(echo "$version_line" | cut -d . -f 1-2).$next_patch_number

    echo -e "   ${GREEN}Upgrading${RESET} $version_file from ${version_line} to ${new_version}"
    if [ true = "$dry_run" ]
    then
        echo -e "${ORANGE}warning${RESET}: aborting $version_file update due to dry run"
    else
        echo -e "$new_version\n" > "$version_file"
    fi
    
    eval "${var_name_prefix}_UPDATE=\"\n* $version_file from \\\`${version_line}\\\` to \\\`${new_version}\\\`\""
    eval "${var_name_prefix}_UPDATE_MESSAGE=\" and \\\`$version_file\\\` version\""
}

################
check_requirements

declare DRY_RUN=true
declare COMMIT=false
declare COMPARE_AGAINST=$DEFAULT_DIFF_REF
readonly COMMIT_REF="HEAD"
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help) display_help $DEFAULT_DIFF_REF $RESOURCES_TO_CHECK ;;
        --run) DRY_RUN=false ;;
        --commit) COMMIT=true ;;
        --ref) [[ -n "${2-}" ]] || error "--ref requires a reference (branch/commit)."; COMPARE_AGAINST="$2"; shift ;;
    esac
    shift
done

FILES_MODIFY="$(git diff --name-only "$COMPARE_AGAINST" "$COMMIT_REF")"
readonly -a FILES_MODIFY
PACKAGE_JSON_FILES="$(find -- * -name package.json | grep -v -e "/node_modules/" -e "/pkg/" -e "/dist/" -e "/.next/" -e "docs/website/")"
readonly -a PACKAGE_JSON_FILES

update_crate_versions $DRY_RUN FILES_MODIFY
update_package_json_versions $DRY_RUN FILES_MODIFY PACKAGE_JSON_FILES

if [ "$(echo "${FILES_MODIFY[@]}" | grep -xc "$OPEN_API_FILE")" -gt 0 ]
then
    update_openapi_version $DRY_RUN
fi

if [ "$(echo "${FILES_MODIFY[@]}" | grep -c "^mithril-infra/.*\.tf$")" -gt 0 ]
then
    update_plain_version_file $DRY_RUN "$INFRA_VERSION_FILE" "INFRA"
fi

if [ "$(echo "${FILES_MODIFY[@]}" | grep -c "^mithril-test-lab/cardano-devnet/.*\.sh$")" -gt 0 ]
then
    update_plain_version_file $DRY_RUN "$DEVNET_VERSION_FILE" "DEVNET"
fi

if [ "$(echo "${FILES_MODIFY[@]}" | grep -c "^mithril-test-lab/benchmark/aggregator-prover/.*\.sh$")" -gt 0 ]
then
    update_plain_version_file $DRY_RUN "$BENCHMARK_VERSION_FILE" "BENCHMARK"
fi

if [ "$(echo "${FILES_MODIFY[@]}" | grep -c "^mithril-test-lab/ipfs-devnet/.*\.sh$")" -gt 0 ]
then
    update_plain_version_file $DRY_RUN "$IPFS_DEVNET_VERSION_FILE" "IPFS_DEVNET"
fi


if [ true = $DRY_RUN ]
then
    echo -e "${ORANGE}warning${RESET}: script is run in dry mode. To apply the changes, run ${GREEN}$0 --run${RESET}"
else
  # NOTE
  # The goal is to transform individual `git diff` formatted output to a list item with the crate or package name and the version change.
  # ie, transform this:
  # ```
  # diff --git a/mithril-explorer/package.json b/mithril-explorer/package.json
  # index 20f2e0030..e0e680d52 100644
  # --- a/mithril-explorer/package.json
  # +++ b/mithril-explorer/package.json
  # @@ -1,6 +1,6 @@
  #  {
  #    "name": "mithril-explorer",
  # -  "version": "0.7.19",
  # +  "version": "0.7.20",
  #    "private": true,
  #    "scripts": {
  #      "dev": "next dev",
  # ```
  # to this:
  # `* [js] mithril-explorer from `0.7.18` to `0.7.19``
  #
  UPDATED_CRATES="$(find . -name Cargo.toml -exec git diff "$COMMIT_REF" {} + | grep -E "^[\+\-]version = \"[0-9\.]+\"|name = " | tr '\n' ' ' | sed -r "s/ name = \"([a-z\-]+)\" -version = \"([0-9\.]+)\" \+version = \"([0-9\.]+)\" ?/* \1 from \`\2\` to \`\3\`\n/g")"
  if [[ -n $UPDATED_CRATES ]]
  then
    UPDATED_CRATES="\n${UPDATED_CRATES}"
  fi
  UPDATED_PACKAGE_JSONS="$(echo "$PACKAGE_JSON_FILES" | xargs git diff "$COMMIT_REF" | grep -E "^[\+\-] *\"version\": \"[0-9\.]+\"|name\": " | tr '\n' ' ' | sed -r "s/ *\"name\": \"([a-z@\-]*\/)?([a-z\-]+)\", -  \"version\": \"([0-9\.]+)\", \+  \"version\": \"([0-9\.]+)\", ?/* [js] \2 from \`\3\` to \`\4\`\n/g")"
  if [[ -n $UPDATED_PACKAGE_JSONS ]]
  then
    UPDATED_PACKAGE_JSONS="\n${UPDATED_PACKAGE_JSONS}"
  fi

  COMMIT_MESSAGE=$(echo -e "chore: upgrade crate versions${OPEN_API_UPDATE_MESSAGE}${INFRA_UPDATE_MESSAGE}${DEVNET_UPDATE_MESSAGE}${BENCHMARK_UPDATE_MESSAGE}${IPFS_DEVNET_UPDATE_MESSAGE}\n${UPDATED_CRATES}${UPDATED_PACKAGE_JSONS}${OPEN_API_UPDATE}${INFRA_UPDATE}${DEVNET_UPDATE}${BENCHMARK_UPDATE}${IPFS_DEVNET_UPDATE}")

  echo -e "$COMMIT_MESSAGE"

  if [ true = $COMMIT ]
  then
    git add --update $OPEN_API_FILE Cargo.lock ./*/Cargo.toml ./mithril-test-lab/*/Cargo.toml examples/*/Cargo.toml
    git add --update ./internal/*/Cargo.toml ./internal/cardano-node/*/Cargo.toml ./internal/signed-entity/*/Cargo.toml ./internal/tests/*/Cargo.toml
    git add --update ./*/package.json ./*/package-lock.json mithril-client-wasm/ci-test/package-lock.json examples/*/package.json examples/*/package-lock.json
    git add --update $INFRA_VERSION_FILE $DEVNET_VERSION_FILE $BENCHMARK_VERSION_FILE $IPFS_DEVNET_VERSION_FILE
    git commit -m "$COMMIT_MESSAGE"
  fi
fi
