# IPNS signing key

## Introduction

When IPFS is enabled on a Mithril network, the aggregator publishes the IPFS directory of the immutable archives under an IPNS name. This IPNS name is derived from an Ed25519 signing key that the IPFS node of the aggregator imports at startup.

The signing key is provided to the deployment by the `IPFS_IPNS_SIGNING_KEY` secret of the GitHub environment of the network, in PEM PKCS#8 format. This secret is optional (e.g. for a follower aggregator): the aggregator does not publish to IPNS when it is empty.

The deployment computes the IPNS name from the signing key and publishes it as a [DNSLink](https://dnslink.dev/) TXT record in the DNS zone of the network, so that third parties follow the stable name `/ipns/immutables.<NETWORK>.api.mithril.network` (e.g. `/ipns/immutables.testing-preview.api.mithril.network`) instead of the IPNS name. The record is not created when the secret is empty.

> [!IMPORTANT]
> :fire: The IPNS signing key is a private key: anyone who holds it can publish content under the IPNS name of the network. It must not be stored anywhere other than the GitHub environment secret and the IPFS node of the aggregator.

All the commands below are run locally and require [Docker](https://docs.docker.com/get-docker/).

## Pre-requisites

Export the environment variables:

```bash
export IPFS_IMAGE=ipfs/kubo:v0.43.1
export KEY_DIRECTORY=$(mktemp -d)
```

## Create a signing key

Generate a new Ed25519 signing key and export it in PEM PKCS#8 format:

```bash
docker run --rm -u $(id -u):$(id -g) -e IPFS_PATH=/tmp/ipfs -v $KEY_DIRECTORY:/keys --entrypoint sh $IPFS_IMAGE -c '
ipfs init > /dev/null
ipfs key gen --type=ed25519 ipns-signing-key > /dev/null
ipfs key export ipns-signing-key --format=pem-pkcs8-cleartext -o /keys/ipns-signing-key.pem
'
```

Display the signing key:

```bash
cat $KEY_DIRECTORY/ipns-signing-key.pem
```

## Compute the IPNS name

Compute the IPNS name associated to the signing key:

```bash
docker run --rm -u $(id -u):$(id -g) -e IPFS_PATH=/tmp/ipfs -v $KEY_DIRECTORY:/keys:ro --entrypoint sh $IPFS_IMAGE -c '
ipfs init > /dev/null
ipfs key import --format=pem-pkcs8-cleartext ipns-signing-key /keys/ipns-signing-key.pem
'
```

The command outputs the IPNS name, and the immutable archives directory is then available at `/ipns/<IPNS_NAME>`.

> [!TIP]
> The same command computes the IPNS name of an existing signing key, provided it is first stored in `$KEY_DIRECTORY/ipns-signing-key.pem`.

## Register the signing key

Copy the full content of `$KEY_DIRECTORY/ipns-signing-key.pem` (including the `BEGIN` and `END` lines) into the `IPFS_IPNS_SIGNING_KEY` secret of the GitHub environment of the network.

The key is imported by the IPFS node and the DNSLink record is updated at the next deployment of the network.

Then delete the local copy of the signing key:

```bash
rm -rf $KEY_DIRECTORY
```

## Rotate the signing key

The IPFS node replaces its signing key with the one of the deployment at each start.

> [!WARNING]
> Rotating the signing key changes the IPNS name of the network. The third-party nodes that follow the DNSLink name of the network are switched to the new IPNS name by the deployment, whereas the nodes that follow the previous IPNS name directly must be informed of the new one before the rotation is deployed.

To rotate the signing key, create a new signing key, compute its IPNS name and register it as described above.

## Verify the DNSLink record

Export the name of the network:

```bash
export NETWORK=**NETWORK**
```

Verify that the DNSLink record points to the IPNS name:

```bash
dig +short TXT _dnslink.immutables.$NETWORK.api.mithril.network
```

The command outputs `"dnslink=/ipns/<IPNS_NAME>"`.
