# Migrate the immutable files archives of a Mithril aggregator

This runbook describes how to migrate the immutable files archives of a Mithril aggregator to a new format (e.g. after a compression change or a `zstd` library upgrade that produces different archives).

The migration consists of clearing the immutable files archives cache of the aggregator, with the `tools clear-immutables-archives-cache` command, and then restarting the aggregator so that the `ImmutablesArchivesPreloader` job re-creates all the archives at startup.

> [!IMPORTANT]
>
> - The aggregator must be running a distribution that produces the new archives format (i.e. the target distribution must already be deployed on the network).
> - While the archives are being re-created, the `CardanoDatabase` signed entity type is locked and is not certified by the aggregator. This can take a while on networks with many immutable files (e.g. `mainnet`).
> - The archives already uploaded to the `gcp` snapshot uploader are not replaced, as the aggregator never overwrites an existing remote archive: they keep the previous format. They remain valid for the existing and future Cardano database snapshots, since the snapshots only certify the content of the archives.
> - The archives already uploaded to IPFS are replaced: when an archive is re-created, the aggregator unpins it and removes it from its MFS directory, and the new archive is uploaded with the next Cardano database snapshot. The previous archives are not deleted: they are still served by the IPFS node until they are garbage collected.

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

## Check the discard of the IPFS archives

> [!NOTE]
> This step is only needed if the aggregator uploads the immutable files archives to IPFS.

Check that no remote archive failed to be discarded from IPFS during the re-creation:

```bash
docker logs mithril-aggregator | grep "Failed to discard remote immutable archive"
```

If nothing is displayed, skip to the [Cleanup the temp directory](#cleanup-the-temp-directory) step. Otherwise, the listed archives (see their `archive_path`) are still the previous archives on IPFS and must be discarded manually:

- if only a few archives are listed, follow the [Discard a few IPFS archives](#discard-a-few-ipfs-archives) step
- if many archives are listed, follow the [Purge all the IPFS archives](#purge-all-the-ipfs-archives) step

In both cases, the discarded archives are uploaded again by the aggregator with the next Cardano database snapshot.

Export the RPC API authentication token of the IPFS node:

```bash
export IPFS_AUTH_TOKEN=**IPFS_AUTH_TOKEN**
```

Define a helper to run the IPFS CLI against the IPFS node:

```bash
ipfs_cli() { docker exec ipfs-node-aggregator ipfs --api-auth "$IPFS_AUTH_TOKEN" "$@"; }
```

### Discard a few IPFS archives

Stop the aggregator container, so that it does not upload archives while they are discarded:

```bash
docker stop mithril-aggregator
```

For each listed archive, export its file name:

```bash
export ARCHIVE_NAME=**ARCHIVE_NAME**
```

Here is an example for the immutable file number `12345`:

```bash
export ARCHIVE_NAME=12345.tar.zst
```

Unpin the archive and remove it from the MFS directory of the aggregator:

```bash
ipfs_cli pin rm $(ipfs_cli files stat --hash /mithril/$ARCHIVE_NAME)
ipfs_cli files rm /mithril/$ARCHIVE_NAME
```

> [!NOTE]
> The `pin rm` command fails with `not pinned or pinned indirectly` if the archive is already unpinned: the archive can still be removed from the MFS directory.

Once all the listed archives are discarded, restart the aggregator:

```bash
docker start mithril-aggregator
```

### Purge all the IPFS archives

Stop the aggregator container, so that it does not upload archives during the purge:

```bash
docker stop mithril-aggregator
```

Unpin all the archives of the MFS directory of the aggregator, then remove the directory:

```bash
docker exec -e IPFS_AUTH_TOKEN ipfs-node-aggregator sh -c '
ipfs_cli() { ipfs --api-auth "$IPFS_AUTH_TOKEN" "$@"; }
for name in $(ipfs_cli files ls /mithril); do
  ipfs_cli pin rm $(ipfs_cli files stat --hash /mithril/$name) > /dev/null || echo "Failed to unpin $name"
done
ipfs_cli files rm -r /mithril
'
```

Make sure that the MFS directory is removed:

```bash
ipfs_cli files ls /mithril
```

It should display `Error: file does not exist`.

Restart the aggregator:

```bash
docker start mithril-aggregator
```

> [!WARNING]
> Until the next Cardano database snapshot uploads all the archives again, the archives of the existing Cardano database snapshots can only be downloaded from IPFS while they are not garbage collected.

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

## Reclaim the disk space of the IPFS node

> [!NOTE]
> This step is optional and only applies if the aggregator uploads the immutable files archives to IPFS. It must be run **at least 48 hours after the re-creation of the archives**, once a new Cardano database snapshot has been published.

The previous archives discarded from IPFS are not deleted: they stay on the disk of the IPFS node (and are still served) until a garbage collection is run. The automatic garbage collection is not enabled on the IPFS node of the aggregator, so it must be run manually to reclaim this disk space.

> [!WARNING]
> The garbage collection removes every version of the MFS directory of the aggregator except the current one: the IPFS locations of all the Cardano database snapshots except the latest one stop resolving from the IPFS node of the aggregator. The clients can still download these snapshots from the cloud storage locations (if any) and from the IPFS replicas that have pinned them.

Connect to the aggregator VM:

```bash
ssh curry@$MITHRIL_VM
```

Export the RPC API authentication token of the IPFS node:

```bash
export IPFS_AUTH_TOKEN=**IPFS_AUTH_TOKEN**
```

Define a helper to run the IPFS CLI against the IPFS node:

```bash
ipfs_cli() { docker exec ipfs-node-aggregator ipfs --api-auth "$IPFS_AUTH_TOKEN" "$@"; }
```

Make sure that all the re-created archives have been uploaded again, by comparing the number of archives in the MFS directory of the aggregator with the number of archives in its cache directory:

```bash
ipfs_cli files ls /mithril | wc -l
ls /home/curry/data/$CARDANO_NETWORK/mithril-aggregator/mithril/snapshots/cardano-database/immutable | wc -l
```

> [!NOTE]
> The cache directory can contain one more archive than the MFS directory, if an archive has been created since the last Cardano database snapshot.

Display the disk usage of the IPFS node:

```bash
ipfs_cli repo stat --human
```

Run the garbage collection, and display the number of removed blocks:

```bash
ipfs_cli repo gc --quiet | wc -l
```

Display the disk usage of the IPFS node again to check the reclaimed disk space:

```bash
ipfs_cli repo stat --human
```

Then disconnect from the aggregator VM:

```bash
exit
```
