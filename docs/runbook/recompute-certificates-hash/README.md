# Recompute the certificates hashes of Mithril aggregator

## Configure environment variables

Export the environment variables:

```bash
export MITHRIL_VM=**MITHRIL_VM**
export CARDANO_NETWORK=**CARDANO_NETWORK**
export MITHRIL_DISTRIBUTION=**MITHRIL_DISTRIBUTION**
```

Here is an example for the `release-mainnet` network:

```bash
export MITHRIL_VM=aggregator.release-mainnet.api.mithril.network
export CARDANO_NETWORK=mainnet
export MITHRIL_DISTRIBUTION=latest
```

## Connect to the VM

Connect to the aggregator VM:

```bash
ssh curry@$MITHRIL_VM
```

## Stop the aggregator

Stop the aggregator container:

```bash
docker stop mithril-aggregator
```

## Make a backup of the aggregator database

Export the environment variables:

```bash
export CARDANO_NETWORK=**CARDANO_NETWORK**
export MITHRIL_DISTRIBUTION=**MITHRIL_DISTRIBUTION**
```

Truncate WAL and SHM files:

```bash
sqlite3 /home/curry/data/$CARDANO_NETWORK/mithril-aggregator/mithril/stores/aggregator.sqlite3 "PRAGMA wal_checkpoint(TRUNCATE);"
```

And copy the SQLite database file `aggregator.sqlite3`:

```bash
cp /home/curry/data/$CARDANO_NETWORK/mithril-aggregator/mithril/stores/aggregator.sqlite3 /home/curry/data/$CARDANO_NETWORK/mithril-aggregator/mithril/stores/aggregator.sqlite3.bak.$(date +%Y-%m-%d)
```

## Create a temp directory

Create a temp directory:

```bash
rm -rf /home/curry/temp
mkdir -p /home/curry/temp/config
cd /home/curry/temp
```

## Download the pre-compiled aggregator binary

Download the mithril pre-compiled binaries package:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/IntersectMBO/mithril/refs/heads/main/mithril-install.sh | sh -s -- -c mithril-aggregator -d $MITHRIL_DISTRIBUTION -p "$(pwd)"
```

Make sure you are running the expected version of the aggregator:

```bash
./mithril-aggregator --version
```

## Run the migration

Once connected to the aggregator container, recompute the certificates hashes:

```bash
DATA_STORES_DIRECTORY=/home/curry/data/$CARDANO_NETWORK/mithril-aggregator/mithril/stores/ ./mithril-aggregator -vvv tools recompute-certificates-hash
```

## Restart the aggregator

Restart the aggregator to make sure that the certificate chain is valid:

```bash
docker start mithril-aggregator
```

Make sure that the certificate chain is valid (wait for the state machine to go into the `READY` state):

```bash
docker logs -f --tail 1000 mithril-aggregator
```

## Cleanup the temp directory

Remove the temp directory:

```bash
rm -rf /home/curry/temp
```

## Exit from the VM

Then disconnect from the aggregator VM:

```bash
exit
```

## Database rollback procedure

If the recomputation fails, you can rollback the database,and try again the process.

First, stop the aggregator:

```bash
docker stop mithril-aggregator
```

Then, restore the backed up database:

```bash
cp /home/curry/data/$CARDANO_NETWORK/mithril-aggregator/mithril/stores/aggregator.sqlite3.bak.$(date +%Y-%m-%d) /home/curry/data/$CARDANO_NETWORK/mithril-aggregator/mithril/stores/aggregator.sqlite3
```

Then, start the aggregator:

```bash
docker start mithril-aggregator
```

Then disconnect from the aggregator VM:

```bash
exit
```
