#!/usr/bin/env bash
#
# Computes the IPNS name of an Ed25519 IPNS signing key.
#
# Reads the signing key in PEM PKCS#8 format base64 encoded on stdin (the format of the
# 'mithril_ipfs_ipns_signing_key' Terraform variable) and writes the IPNS name on stdout.

set -euo pipefail

ED25519_PUBLIC_KEY_DER_PREFIX="302a300506032b6570032100"
# CIDv1, libp2p-key codec, identity multihash of the protobuf encoded Ed25519 public key
IPNS_NAME_PREFIX="0172002408011220"

display_help() {
  cat <<HELP
Computes the IPNS name of an Ed25519 IPNS signing key.

Usage:
  base64 -w 0 ipns-signing-key.pem | bash ipns-name.sh

Output:
  The IPNS name (eg, k51...)

Dependencies: base64, openssl, od, python3
HELP
}

fail() {
  echo "ipns-name: $1" >&2
  exit 1
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  display_help
  exit 0
fi

for dependency in base64 openssl od python3; do
  command -v "$dependency" > /dev/null || fail "missing dependency '$dependency'"
done

public_key_der=$(base64 -d 2> /dev/null | openssl pkey -pubout -outform DER 2> /dev/null | od -An -v -tx1 | tr -d ' \n') \
  || fail "the signing key is not a valid PEM PKCS#8 key base64 encoded"

[[ "$public_key_der" =~ ^${ED25519_PUBLIC_KEY_DER_PREFIX}[0-9a-f]{64}$ ]] || fail "the signing key is not an Ed25519 key"

python3 -c '
import sys

value = int(sys.argv[1], 16)
digits = ""
while value:
    value, remainder = divmod(value, 36)
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"[remainder] + digits
print("k" + digits)
' "${IPNS_NAME_PREFIX}${public_key_der#"$ED25519_PUBLIC_KEY_DER_PREFIX"}"
