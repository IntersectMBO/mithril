#! /bin/bash

set -e

TOTAL_RELEASES=$1
TAG_TO_TEST=$2
ASSETS_DIRECTORY="./mithril-binaries"
TAG_FILE=$ASSETS_DIRECTORY/tags.json
TAGS_TO_COMPARE=()

mkdir -p $ASSETS_DIRECTORY
LATEST_TAGS=$(gh api /repos/IntersectMBO/mithril/releases | jq -r '[.[] | select(.prerelease == false)][].tag_name' | head -n "$TOTAL_RELEASES")

for TAG in $LATEST_TAGS; do
  if [[ "$TAG" == "$TAG_TO_TEST" ]]; then
    continue
  fi
  TAGS_TO_COMPARE+=("$TAG")
done

printf '%s\n' "${TAGS_TO_COMPARE[@]}" | jq -R -s -c 'split("\n") | map(select(. != ""))' > "$TAG_FILE"

TAGS_TO_DOWNLOAD=("$TAG_TO_TEST" "${TAGS_TO_COMPARE[@]}")
echo ">> Downloading Mithril distribution binaries"
echo ">> Release to test: $TAG_TO_TEST"
echo ">> Releases to be tested against: ${TAGS_TO_COMPARE[*]}"
for TAG_NAME in "${TAGS_TO_DOWNLOAD[@]}"
do
    echo ">>>> Retrieving artifacts for release ${TAG_NAME}"
    ARCHIVE_DIRECTORY="./mithril-binaries/$TAG_NAME"
    mkdir -p $ARCHIVE_DIRECTORY
    gh release download --repo IntersectMBO/mithril $TAG_NAME -O mithril-archive --pattern "mithril-$TAG_NAME*-linux-x64.tar.gz"
    tar xzf mithril-archive -C $ARCHIVE_DIRECTORY mithril-aggregator mithril-signer mithril-client mithril-relay mithril-setup
    rm mithril-archive
done
