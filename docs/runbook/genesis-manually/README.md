# Manual genesis of production Mithril network

## Era compatibility

Every `mithril-aggregator genesis` subcommand takes an optional `--mithril-era` flag.

The era controls which key material the subcommand expects:

| Era + key material                             | Outcome                                                     |
| ---------------------------------------------- | ----------------------------------------------------------- |
| `pythagoras` + legacy single-Ed25519 key       | OK (current behaviour, untouched)                           |
| `pythagoras` + dual bundle (Ed25519 + Schnorr) | OK (only the Ed25519 half is used)                          |
| `lagrange` + dual bundle                       | OK (dual ceremony: both signatures are produced / verified) |
| `lagrange` + legacy single-Ed25519 key         | Error: convert it with `genesis upgrade-key-to-dual`        |

The signing-key file (`genesis.sk`) and the verification-key file (`genesis.vk`) layouts are auto-detected.

## Circuit verification key registry

For the `Snark` and `IvcSnark` aggregate signature types, the certificates following the genesis
certificate are rejected unless the circuit verification key registry of the Mithril network allows
their circuit verification keys from the genesis epoch: whitelist the digests of the deployed
circuit keys and publish the registry before the genesis, following the
[circuit-key-registry](../circuit-key-registry/README.md) runbook.

## Configure environment variables

Export the environment variables:

```bash
export MITHRIL_VM=**MITHRIL_VM**
export CARDANO_NETWORK=**CARDANO_NETWORK**
```

Here is an example for the `release-mainnet` network:

```bash
export MITHRIL_VM=aggregator.release-mainnet.api.mithril.network
export CARDANO_NETWORK=mainnet
```

## Export the genesis payload to sign

Connect to the aggregator VM:

```bash
ssh curry@$MITHRIL_VM
```

Once connected to the aggregator VM, export the environment variables:

```bash
export NETWORK=**CARDANO_NETWORK**
export NETWORK_MAGIC=**NETWORK_MAGIC**
export DATA_STORES_DIRECTORY=**DATA_STORES_DIRECTORY**
export CARDANO_NODE_SOCKET_PATH=**CARDANO_NODE_SOCKET_PATH**
export CHAIN_OBSERVER_TYPE=**CHAIN_OBSERVER_TYPE**
export MITHRIL_ERA=**MITHRIL_ERA**
```

And create genesis dir:

```bash
mkdir -p /home/curry/data/$NETWORK/mithril-aggregator/mithril/genesis
```

And connect to the aggregator container:

```bash
docker exec -it mithril-aggregator bash
```

Once connected to the aggregator container, export the genesis payload to sign:

```bash
/app/bin/mithril-aggregator -vvv genesis export --target-path /mithril-aggregator/mithril/genesis/genesis-payload-to-sign.txt --mithril-era $MITHRIL_ERA
```

> The `--mithril-era` parameter specifies which Mithril era to use for the genesis certificate (e.g. `pythagoras`, `lagrange`).

Then disconnect from the aggregator container:

```bash
exit
```

Then disconnect from the aggregator VM:

```bash
exit
```

## Sign the genesis payload

Once on your local machine, copy the genesis payload to sign from the aggregator VM:

```bash
scp curry@$MITHRIL_VM:/home/curry/data/$CARDANO_NETWORK/mithril-aggregator/mithril/genesis/genesis-payload-to-sign.txt .
```

Download or build the aggregator on your local machine as explained in this [documentation](https://mithril.network/doc/manual/developer-docs/nodes/mithril-aggregator#download-source)

Then, sign the payload with the genesis secret key:

```bash
./mithril-aggregator -vvv genesis sign --to-sign-payload-path genesis-payload-to-sign.txt --target-signed-payload-path genesis-payload-signed.txt --genesis-secret-key-path genesis.sk --mithril-era $MITHRIL_ERA
```

> Pythagoras writes a raw 64-byte Ed25519 signature. Lagrange writes a versioned dual-signature
> envelope (Ed25519 + Schnorr); the signing-key file must be the dual bundle produced by
> `genesis upgrade-key-to-dual` or `genesis generate-keypair --mithril-era lagrange`.

## Import the signed genesis payload

Then, copy the signed genesis payload back to the aggregator VM:

```bash
scp  ./genesis-payload-signed.txt curry@$MITHRIL_VM:/home/curry/data/$CARDANO_NETWORK/mithril-aggregator/mithril/genesis/genesis-payload-signed.txt
```

Then, connect back to the aggregator VM:

```bash
ssh curry@$MITHRIL_VM
```

Export the environment variable:

```bash
export NETWORK=**CARDANO_NETWORK**
export MITHRIL_NETWORK=**MITHRIL_NETWORK**
export NETWORK_MAGIC=**NETWORK_MAGIC**
export DATA_STORES_DIRECTORY=**DATA_STORES_DIRECTORY**
export CARDANO_NODE_SOCKET_PATH=**CARDANO_NODE_SOCKET_PATH**
export CHAIN_OBSERVER_TYPE=**CHAIN_OBSERVER_TYPE**
```

And connect back to the aggregator container:

```bash
docker exec -it mithril-aggregator bash
```

Once connected to the aggregator container, import the signed genesis payload:

```bash
/app/bin/mithril-aggregator -vvv genesis import --signed-payload-path /mithril-aggregator/mithril/genesis/genesis-payload-signed.txt --genesis-verification-key $(curl -sSL "https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/$MITHRIL_NETWORK/genesis.vkey") --mithril-era $MITHRIL_ERA
```
