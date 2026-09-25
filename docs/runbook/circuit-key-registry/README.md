# Manage the circuit verification key registry

## Introduction

The circuit verification key registry is the list of the circuit verification keys trusted for the
SNARK certificates (`Snark` and `IvcSnark` aggregate signature types) of a Mithril network, signed
with the genesis key of that Mithril network.

The registry of a Mithril network is published at
`mithril-infra/configuration/<mithril-network>/circuit-verification-key-registry.json` and
referenced from the Mithril network entry of the [networks.json](../../../networks.json) file:

```json
"circuit-verification-key-registry": {
  "url": "https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-mainnet/circuit-verification-key-registry.json"
}
```

The nodes reject a SNARK certificate whose circuit verification key digests are not allowed by the
registry:

- The clients resolve the registry of their Mithril network through `networks.json`, by selecting
  the Mithril network entry whose aggregators include their aggregator endpoint, and download it.
- The aggregators download the registry from the URL of their
  `circuit_verification_key_registry_url` configuration parameter, set by their deployment (a
  `file://` URL reads a local file, for local deployments).

The nodes refresh the registry when they verify a certificate requiring it, at most once per hour,
keeping the previously verified registry when the refresh fails or would lower the registry
version.

> [!NOTE]
> The `circuit-key-registry` command and the `circuit_verification_key_registry_url` parameter of
> the aggregator, and the `--circuit-verification-key-registry-path` parameter of the client, only
> exist in binaries built with the `future_snark` feature, which the distributions do not enable
> yet: a deployed Mithril network enforces the registry once its distribution is built with it.

> [!IMPORTANT]
> `networks.json` only routes the clients to a registry, it is not trusted: a wrong entry can only
> yield a registry that fails the genesis signature verification, or an older registry of the same
> Mithril network.

## Registry format

```json
{
  "registry": {
    "version": 2,
    "entries": [
      {
        "digest": "3e5a…9c1f",
        "name": "certificate-circuit v1",
        "status": "allowed",
        "start_epoch": 500,
        "end_epoch": null,
        "comment": null
      },
      {
        "digest": "7bd2…04aa",
        "name": "ivc-circuit v1",
        "status": "revoked",
        "start_epoch": 500,
        "end_epoch": 520,
        "comment": "revoked: soundness issue in the accumulator check"
      }
    ]
  },
  "signature": "…"
}
```

| Field                   | Type                   | Description                                                                                                                      |
| ----------------------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `registry.version`      | integer                | Version of the registry, at least `1` and strictly greater than the version of the previously published registry.                |
| `registry.entries`      | array                  | One statement per circuit verification key.                                                                                      |
| `entries[].digest`      | hex string (64 chars)  | Circuit verification key digest the statement is about, unique in the registry.                                                  |
| `entries[].name`        | string                 | Label of the circuit verification key, for humans (e.g. `certificate-circuit v1`).                                               |
| `entries[].status`      | `allowed` or `revoked` | `allowed`: the key may certify the certificates of the epoch range. `revoked`: the certificates of the key are rejected forever. |
| `entries[].start_epoch` | integer                | First epoch (inclusive) at which the key is allowed.                                                                             |
| `entries[].end_epoch`   | integer or `null`      | Last epoch (inclusive) at which an allowed key is allowed, `null` when open-ended; epoch of the revocation of a revoked key.     |
| `entries[].comment`     | string or `null`       | Audit trail, e.g. the reason of a revocation.                                                                                    |
| `signature`             | hex string             | Ed25519 signature of the genesis key of the Mithril network over the `registry` object.                                          |

The nodes enforce the following rules:

- A circuit verification key digest without an entry, or whose `allowed` entry does not cover the
  epoch of the certificate, is rejected.
- A circuit verification key digest with a `revoked` entry is rejected for every epoch, so a
  revocation is retroactive: a forger chooses the epoch its certificate claims.
- A registry refreshed by a running node with a `version` lower than the one it previously
  verified is ignored: the node keeps the registry it previously verified.
- A registry signed with the genesis key of another Mithril network is rejected.

The circuit verification key digests are Poseidon hashes of the transcript representation of the
verification keys, which binds the circuit gates. The two circuits behave differently:

- The IVC circuit does not depend on the protocol parameters: its circuit verification key digest
  is the same for every Mithril network.
- The certificate circuit depends on the `k` and `m` protocol parameters: its circuit verification
  key digest changes with them, so a change of `k` or `m` requires whitelisting the new digest,
  published before the first epoch certified with the new parameters.

## Pre-requisites

- The genesis secret key of the Mithril network, on the air-gapped machine used for signing
- The protocol parameters of the Mithril network
- A `mithril-aggregator` binary built with the `future_snark` feature:

```bash
cargo build --release -p mithril-aggregator --features future_snark
```

## Setup environment variables

Export the environment variables needed to complete the process:

```bash
export MITHRIL_AGGREGATOR=**PATH_TO_YOUR_MITHRIL_AGGREGATOR_BINARY**
export MITHRIL_NETWORK=**YOUR_MITHRIL_NETWORK**
export PROTOCOL_PARAMETERS='**YOUR_PROTOCOL_PARAMETERS_JSON**'
export REGISTRY_PATH=mithril-infra/configuration/$MITHRIL_NETWORK/circuit-verification-key-registry.json
```

Here is an example for the `release-mainnet` Mithril network:

```bash
export MITHRIL_AGGREGATOR=./target/release/mithril-aggregator
export MITHRIL_NETWORK=release-mainnet
export PROTOCOL_PARAMETERS='{"k":1944,"m":16948,"phi_f":0.2}'
export REGISTRY_PATH=mithril-infra/configuration/$MITHRIL_NETWORK/circuit-verification-key-registry.json
```

On the air-gapped machine holding the genesis secret key, also export:

```bash
export GENESIS_SECRET_KEY_PATH=**PATH_TO_YOUR_GENESIS_SECRET_KEY_FILE**
```

## Export the circuit verification key digests

Export the circuit verification key digests of the Mithril network:

```bash
$MITHRIL_AGGREGATOR circuit-key-registry export \
    --protocol-parameters "$PROTOCOL_PARAMETERS" \
    --target-path circuit-verification-key-digests.json
```

The command prints the two digests and writes them to the target file:

```json
{
  "certificate_circuit": "3e5a…9c1f",
  "ivc_circuit": "7bd2…04aa"
}
```

> The certificate circuit verification key is derived from the trusted setup for the given
> protocol parameters, which is fast for the small `k` of the test networks. Without
> `--protocol-parameters`, the production certificate circuit verification key embedded in
> `mithril-stm` is used.

## Whitelist a circuit verification key

Export the circuit verification key digest to whitelist and the first epoch it certifies:

```bash
export CIRCUIT_VERIFICATION_KEY_DIGEST=**YOUR_CIRCUIT_VERIFICATION_KEY_DIGEST**
export CIRCUIT_VERIFICATION_KEY_NAME=**YOUR_CIRCUIT_VERIFICATION_KEY_NAME**
export START_EPOCH=**YOUR_START_EPOCH**
```

On the air-gapped machine, add the `allowed` entry to the registry and sign it:

```bash
$MITHRIL_AGGREGATOR circuit-key-registry whitelist \
    --registry-path $REGISTRY_PATH \
    --genesis-secret-key-path $GENESIS_SECRET_KEY_PATH \
    --digest $CIRCUIT_VERIFICATION_KEY_DIGEST \
    --name "$CIRCUIT_VERIFICATION_KEY_NAME" \
    --start-epoch $START_EPOCH
```

The command verifies the signature of the current registry, appends the entry, increments the
`version`, signs the registry and writes it in place.

> When the registry file does not exist, the command creates it at version `1`: make sure
> `$REGISTRY_PATH` points to the published registry of the Mithril network, otherwise the
> previously published entries are dropped. The command fails when the key already has an entry.

> Add `--end-epoch **YOUR_END_EPOCH**` to close the range of the key, and `--comment "…"` to
> record the reason of the entry.

## Expire a circuit verification key

Export the circuit verification key digest to expire, which must have an `allowed` entry, and the
last epoch at which it certifies:

```bash
export CIRCUIT_VERIFICATION_KEY_DIGEST=**YOUR_CIRCUIT_VERIFICATION_KEY_DIGEST**
export END_EPOCH=**YOUR_END_EPOCH**
```

On the air-gapped machine, expire the key in the registry and sign it:

```bash
$MITHRIL_AGGREGATOR circuit-key-registry expire \
    --registry-path $REGISTRY_PATH \
    --genesis-secret-key-path $GENESIS_SECRET_KEY_PATH \
    --digest $CIRCUIT_VERIFICATION_KEY_DIGEST \
    --end-epoch $END_EPOCH
```

The command verifies the signature of the current registry, closes the range of the `allowed`
entry of the key at the end epoch, increments the `version`, signs the registry and writes it in
place. The certificates of the key up to the end epoch keep verifying.

> [!IMPORTANT]
> The end epoch must not precede the last epoch certified with the key, the one preceding the
> re-genesis or the protocol parameters change retiring it, otherwise the certificates of the last
> epochs are rejected.

> Add `--comment "…"` to record the reason of the expiration.

## Revoke a circuit verification key

Export the circuit verification key digest to revoke, which must have an `allowed` entry, the epoch
of the revocation and its reason:

```bash
export CIRCUIT_VERIFICATION_KEY_DIGEST=**YOUR_CIRCUIT_VERIFICATION_KEY_DIGEST**
export REVOCATION_EPOCH=**YOUR_REVOCATION_EPOCH**
export REVOCATION_COMMENT=**YOUR_REVOCATION_COMMENT**
```

On the air-gapped machine, revoke the key in the registry and sign it:

```bash
$MITHRIL_AGGREGATOR circuit-key-registry revoke \
    --registry-path $REGISTRY_PATH \
    --genesis-secret-key-path $GENESIS_SECRET_KEY_PATH \
    --digest $CIRCUIT_VERIFICATION_KEY_DIGEST \
    --revocation-epoch $REVOCATION_EPOCH \
    --comment "$REVOCATION_COMMENT"
```

The command verifies the signature of the current registry, turns the `allowed` entry of the key
into a `revoked` one recording the revocation epoch and the comment, increments the `version`,
signs the registry and writes it in place. The certificates of a revoked key are rejected for every
epoch.

> [!WARNING]
> The revocation also rejects the current certificate chain of the Mithril network, which stops
> certifying from the publication of the revocation until the re-genesis with the fixed circuit
> keys. Before publishing, whitelist the digests of the fixed circuit keys (see above) in the same
> published registry and prepare the distribution embedding them, so the re-genesis follows the
> publication immediately.

After the publication of the revocation (see below), run a re-genesis with the fixed circuit keys,
following the [update-circuit-keys](../update-circuit-keys/README.md) and
[genesis-manually](../genesis-manually/README.md) runbooks.

## Publish the registry

Create a pull request with the signed registry at `$REGISTRY_PATH`, reviewed by the tech lead and
the cryptographers.

> [!IMPORTANT]
> The signature covers the exact bytes of the `registry` object, so the signed registry file must
> never be reformatted: it is excluded from `prettier` in `.prettierignore`, and a reformatted
> registry fails the genesis signature verification of every node.

For the first registry of a Mithril network, also reference it from the Mithril network entry of
[networks.json](../../../networks.json):

```json
"circuit-verification-key-registry": {
  "url": "https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/**YOUR_MITHRIL_NETWORK**/circuit-verification-key-registry.json"
}
```

and set the `CIRCUIT_VERIFICATION_KEY_REGISTRY_URL` variable of the GitHub environment of the
Mithril network to the same URL.

Publish the registry before the first epoch whose certificates need it, with at least one hour of
lead time. Once the pull request is merged on `main`:

- The clients download the new registry at their next certificate verification, a long-running
  client keeping a verified registry for at most an hour.
- The aggregators of the Mithril network download the new registry from the URL of the
  `CIRCUIT_VERIFICATION_KEY_REGISTRY_URL` variable, passed to them by their deployment, at their
  next certificate verification once their previous download is more than an hour old.

## Sign a hand-authored registry

A registry authored by hand (the `registry` object above, without `signature`) can be signed as a
whole. On the air-gapped machine:

```bash
export REGISTRY_TO_SIGN_PATH=**PATH_TO_YOUR_UNSIGNED_REGISTRY_FILE**
```

```bash
$MITHRIL_AGGREGATOR circuit-key-registry sign \
    --to-sign-registry-path $REGISTRY_TO_SIGN_PATH \
    --target-signed-registry-path $REGISTRY_PATH \
    --genesis-secret-key-path $GENESIS_SECRET_KEY_PATH
```

## Use a local registry with the client

For tests and local deployments, the client CLI reads the registry from a local file instead of
resolving it through `networks.json` (the genesis signature verification still applies):

```bash
mithril-client --unstable --circuit-verification-key-registry-path $REGISTRY_PATH cardano-db snapshot list
```

Library users get the same through `with_circuit_verification_key_registry_retriever` on the client
builder.
