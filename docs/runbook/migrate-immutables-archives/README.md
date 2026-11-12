# Migrate the immutable files archives of a Mithril aggregator

This runbook describes how to migrate the immutable files archives of a Mithril aggregator to a new format (e.g. after a compression change or a `zstd` library upgrade that produces different archives).

The migration consists of clearing the immutable files archives cache of the aggregator, with the `tools clear-immutables-archives-cache` command, and then restarting the aggregator so that the `ImmutablesArchivesPreloader` job re-creates all the archives at startup.

> [!IMPORTANT]
>
> - The aggregator must be running a distribution that produces the new archives format (i.e. the target distribution must already be deployed on the network).
> - While the archives are being re-created, the `CardanoDatabase` signed entity type is locked and is not certified by the aggregator. This can take a while on networks with many immutable files (e.g. `mainnet`).
> - This runbook only migrates the archives of the local cache of the aggregator. The archives already uploaded to remote storages (`gcp` snapshot uploader, IPFS) are not replaced, as the aggregator never overwrites an existing remote archive: they keep the previous format. They remain valid for the existing and future Cardano database snapshots, since the snapshots only certify the content of the archives.

> [!WARNING]
> If the aggregator uses the `local` snapshot uploader, the immutable files archives are served directly from the cache directory. Deleting them breaks the download of the existing Cardano database snapshots until the `ImmutablesArchivesPreloader` job has re-created the archives.

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

## Create a temp directory

Export the environment variables:

```bash
export CARDANO_NETWORK=**CARDANO_NETWORK**
export MITHRIL_DISTRIBUTION=**MITHRIL_DISTRIBUTION**
```

Create a temp directory:

```bash
rm -rf /home/curry/temp
mkdir -p /home/curry/temp
cd /home/curry/temp
```

## Download the pre-compiled aggregator binary

Download the mithril pre-compiled binaries package:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/IntersectMBO/mithril/refs/heads/main/mithril-install.sh | sh -s -- -c mithril-aggregator -d $MITHRIL_DISTRIBUTION -p "$(pwd)"
```

Make sure you are running the expected version of the aggregator (it should be the same as the version of the aggregator running on the VM):

```bash
./mithril-aggregator --version
```

## Inspect the immutable files archives cache

Run the command without the `--delete` option (dry run) to display a summary of the archives found in the cache directory, without deleting anything:

```bash
SNAPSHOT_DIRECTORY=/home/curry/data/$CARDANO_NETWORK/mithril-aggregator/mithril/snapshots ./mithril-aggregator -vvv tools clear-immutables-archives-cache
```

Check that the displayed cache directory is `/home/curry/data/$CARDANO_NETWORK/mithril-aggregator/mithril/snapshots/cardano-database/immutable` and that the number of archives and the range of immutable file numbers are consistent with the network.

## Stop the aggregator

Stop the aggregator container:

```bash
docker stop mithril-aggregator
```

## Clear the immutable files archives cache

Delete the immutable files archives:

```bash
SNAPSHOT_DIRECTORY=/home/curry/data/$CARDANO_NETWORK/mithril-aggregator/mithril/snapshots ./mithril-aggregator -vvv tools clear-immutables-archives-cache --delete
```

Make sure that the cache directory is now empty by running the dry run again:

```bash
SNAPSHOT_DIRECTORY=/home/curry/data/$CARDANO_NETWORK/mithril-aggregator/mithril/snapshots ./mithril-aggregator -vvv tools clear-immutables-archives-cache
```

It should display `Nothing to delete: no immutable archives in the cache directory`.

## Restart the aggregator

Restart the aggregator, which will re-create all the immutable files archives at startup:

```bash
docker start mithril-aggregator
```

## Wait for the end of the archives re-creation

Monitor the logs of the `ImmutablesArchivesPreloader` job:

```bash
docker logs -f --tail 1000 mithril-aggregator | grep -E "ImmutablesArchivesPreloader|Failed to preload the immutables archives"
```

The job logs a `Started` message when it begins and a `Finished` message when the preload attempt ends. Wait for `Finished`, then verify that no `Failed to preload the immutables archives` warning was logged before proceeding.

> [!NOTE]
> If the `Failed to preload the immutables archives` warning was logged, the archives were not all re-created. The missing archives will be created during the next Cardano database snapshot creation, or you can restart the aggregator to run the job again (the archives already re-created are kept).

> [!NOTE]
> The duration of the job depends on the number of immutable files of the network, e.g. it took ~35 minutes for ~29,500 immutable files on `testing-preview`.

To follow the progress of the job, display the last immutable trio being archived (requires the `debug` log level) and compare it with the last immutable file number of the Cardano node (approximately the highest immutable file number displayed by the dry run of the [Inspect the immutable files archives cache](#inspect-the-immutable-files-archives-cache) step):

```bash
docker logs --tail 1000 mithril-aggregator | grep "Snapshotting immutable trio" | tail -n 1
```

Then, make sure that the certification of the Cardano database resumes by monitoring the new Cardano database snapshots in the [Mithril explorer](https://mithril.network/explorer/?aggregator=**URL_ENCODED_AGGREGATOR_ENDPOINT**).

Here is an example for the `release-mainnet` network: [Mithril explorer](https://mithril.network/explorer/?aggregator=https%3A%2F%2Faggregator.release-mainnet.api.mithril.network%2Faggregator).

> [!NOTE]
> A new Cardano database snapshot is only produced when a new immutable file is completed by the Cardano node (e.g. every ~6 hours on `mainnet`), so this check can be done later.

Optionally, check the number of re-created archives:

```bash
SNAPSHOT_DIRECTORY=/home/curry/data/$CARDANO_NETWORK/mithril-aggregator/mithril/snapshots ./mithril-aggregator -vvv tools clear-immutables-archives-cache
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
