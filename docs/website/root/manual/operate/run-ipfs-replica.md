---
sidebar_position: 5
---

# Run an IPFS replica

:::danger

The distribution of the immutable archives on IPFS is currently **unstable**. It is not suitable for production use yet.

:::

:::info

You don't need to run a Cardano node or a Mithril node to replicate the immutable archives.

:::

A Mithril aggregator can publish the immutable archives of its Cardano database snapshots on [IPFS](https://ipfs.tech). Anyone can help distribute them by running a [Kubo](https://github.com/ipfs/kubo) node that replicates the archives and serves them to the Mithril clients, which lowers the distribution costs and improves the availability of the snapshots.

The replication works as follows:

- The aggregator adds each new immutable archive to a directory and publishes the latest version of this directory under an **IPNS name**
- The replica resolves the IPNS name periodically and pins the new version of the directory, fetching only the missing archives
- The replica keeps the previous versions of the directory pinned, as older snapshots still reference them
- The replica announces the archives to the IPFS network and serves them to the Mithril clients.

## Prerequisites

:::info

Note that this guide works only on a Linux machine.

:::

- **Kubo** `v0.43.1` or newer (installed by the setup script)
- Run the setup with a user that has full `sudo` rights, and access to Docker (eg, member of the `docker` group) for the Docker deployment
- Meet the [Hardware](#hardware) and [Connectivity](#connectivity) requirements
- Open the IPFS swarm port `4001` (TCP and UDP) for inbound and outbound traffic, for example with `ufw`:

```bash
sudo ufw allow 4001/tcp
sudo ufw allow 4001/udp
```

- Retrieve the **IPNS name of the immutable archives** of the Mithril network you target in the [Network configurations](../getting-started/network-configurations.md) page.

## Hardware

Running an IPFS replica requires the following resources:

- **CPU**: at least 2 vCPUs
- **RAM**: at least 4 GB
- **Storage**: an SSD, to serve many concurrent downloads with low latency, sized for 3 to 5 years of growth of the archives:
  - For `mainnet`: at least 200 GB
  - For test networks (`preprod`, `preview`): at least 30 GB.

:::info

The immutable archives currently use about 60 GB on `mainnet` and grow by about 10 GB per year, so about 110 GB in 5 years. They use less than 5 GB on the test networks. The recommended sizes also leave room for the Kubo metadata and the operating system. The replica never removes pinned archives, so monitor the free disk space and extend the disk before it runs out. The previous versions of the directory share the blocks of the archives, so keeping them pinned only adds a few kilobytes per version.

You can display the current size of the directory as described in the [Verify that the replica is complete](#verify-that-the-replica-is-complete) section.

:::

## Connectivity

To provide fast and reliable downloads, the replica needs:

- A **public** IPv4 or IPv6 address, reachable on port `4001` (TCP and UDP), directly or through a port forwarding of port `4001` on a NAT router
- A symmetric bandwidth of at least 100 Mbit/s (1 Gbit/s recommended for `mainnet`)
- An unmetered or large monthly data allowance, as each full download of the `mainnet` archives transfers about 60 GB
- A permanent uptime, as the node must stay online to announce the archives to the IPFS network.

## Set up the replica

:::caution

- Here is the needed information to set up the Kubo node:
  - `**YOUR_IPNS_NAME**`: replace with the IPNS name of the immutable archives (the value can be found in the [Network configurations](../getting-started/network-configurations.md) page)
  - `**YOUR_PUBLIC_IP_ADDRESS**`: replace with the **public** IP address of your machine (only needed if the machine is behind a NAT that forwards port `4001` to it).

:::

:::info

The setup takes **less than a minute**. The initial synchronization of the immutable archives then runs in the background, and the replica serves the archives as they are downloaded:

| Network                              | Size of the archives | Initial synchronization at 100 Mbit/s |
| ------------------------------------ | -------------------- | ------------------------------------- |
| `mainnet`                            | ~60 GB               | 1.5 hours or more                     |
| Test networks (`preprod`, `preview`) | < 5 GB               | 10 minutes or more                    |

The actual duration depends on your bandwidth and on the number of nodes that serve the archives. The next synchronizations only download the new archives.

:::

Download the setup script:

```bash
curl --fail -sSLO https://mithril.network/doc/scripts/setup_ipfs_replica.sh
```

Then, run it with the binary deployment:

```bash
IPNS_NAME=**YOUR_IPNS_NAME** bash setup_ipfs_replica.sh
```

Or with the Docker deployment:

```bash
DEPLOYMENT=docker IPNS_NAME=**YOUR_IPNS_NAME** bash setup_ipfs_replica.sh
```

:::tip

The script also supports these optional variables:

- `PUBLIC_IP_ADDRESS`: the **public** IPv4 or IPv6 address announced by the node, if the machine is behind a NAT
- `KUBO_VERSION`: the Kubo version to install (`v0.43.1` by default).

Run `bash setup_ipfs_replica.sh --help` to display all the variables.

:::

If the setup succeeds, you should see this message:

```bash
>> Congrats, your IPFS replica is set up! The initial synchronization runs in the background.
```

The replica is set up. Follow the initial synchronization with:

```bash
journalctl -u mithril-ipfs-replication -f
```

Then, go to the [Verify the replication](#verify-the-replication) section.

## Verify the replication

Download the verification script:

```bash
curl --fail -sSLO https://mithril.network/doc/scripts/verify_ipfs_replica.sh
```

Then, run it with the binary deployment:

```bash
IPNS_NAME=**YOUR_IPNS_NAME** bash verify_ipfs_replica.sh
```

Or with the Docker deployment:

```bash
DEPLOYMENT=docker IPNS_NAME=**YOUR_IPNS_NAME** bash verify_ipfs_replica.sh
```

If your replica is complete and up to date, you should see a message like this, followed by a link to check that your node is reachable with the [IPFS Check](https://check.ipfs.network) tool:

```bash
>> Congrats, your replica is complete and up to date: Local: 4.9 GB of 4.9 GB (100.00%)
```

Otherwise, you should see a message like this:

```bash
>> Oops, the replica is not complete yet: Local: 1.2 GB of 4.9 GB (24.49%)
```

During the initial synchronization, the message shows its progress. Run the script again later.

---

## Expert setup

The following sections describe the manual steps run by the setup and verification scripts. You don't need them if you used the scripts, but they help to customize or troubleshoot a replica.

### Binary deployment

#### Download the pre-built binary

To download the Kubo binary and its checksum, run:

```bash
curl --fail -sLO https://github.com/ipfs/kubo/releases/download/v0.43.1/kubo_v0.43.1_linux-amd64.tar.gz
curl --fail -sLO https://github.com/ipfs/kubo/releases/download/v0.43.1/kubo_v0.43.1_linux-amd64.tar.gz.sha512
```

Verify the checksum of the archive:

```bash
sha512sum -c kubo_v0.43.1_linux-amd64.tar.gz.sha512
```

You should see:

```bash
kubo_v0.43.1_linux-amd64.tar.gz: OK
```

Then, extract the binary:

```bash
tar -xzf kubo_v0.43.1_linux-amd64.tar.gz --strip-components=1 kubo/ipfs
```

And test that the binary works:

```bash
./ipfs --version
```

You should see:

```bash
ipfs version 0.43.1
```

:::tip

On an ARM machine, replace `linux-amd64` with `linux-arm64` in the commands above.

Newer versions of Kubo are listed on the [Kubo releases](https://github.com/ipfs/kubo/releases) page.

:::

#### Installing the service

##### Move the executable

To install the executable in `/opt/mithril-ipfs`, owned by `root`, run:

```bash
sudo mkdir -p /opt/mithril-ipfs
sudo install -o root -g root -m 755 ipfs /opt/mithril-ipfs/ipfs
```

##### Create the service user

Create a `mithril-ipfs` user that owns the Kubo repository located in `/var/lib/mithril-ipfs`:

```bash
sudo useradd --system --create-home --home-dir /var/lib/mithril-ipfs --shell /usr/sbin/nologin mithril-ipfs
```

Then, create an `ipfs_node` shell function to run Kubo commands with this user:

```bash
ipfs_node () {
  sudo -u mithril-ipfs env IPFS_PATH=/var/lib/mithril-ipfs /opt/mithril-ipfs/ipfs "$@"
}
```

##### Initialize the Kubo repository

Initialize the repository with the `server` profile, which prevents the node from scanning the local network:

```bash
ipfs_node init --profile server
```

If the machine is behind a NAT, announce its public address (use `/ip6/` instead of `/ip4/` for an IPv6 address):

```bash
ipfs_node config --json Addresses.AppendAnnounce '["/ip4/**YOUR_PUBLIC_IP_ADDRESS**/tcp/4001", "/ip4/**YOUR_PUBLIC_IP_ADDRESS**/udp/4001/quic-v1"]'
```

Raise the Bitswap server limits, which otherwise keep at most 1 MB in flight per peer and slow down the download of the archives by the clients:

```bash
ipfs_node config --json Internal.Bitswap.TaskWorkerCount 32
ipfs_node config --json Internal.Bitswap.EngineTaskWorkerCount 32
ipfs_node config --json Internal.Bitswap.EngineBlockstoreWorkerCount 256
ipfs_node config --json Internal.Bitswap.MaxOutstandingBytesPerPeer 8388608
```

##### Set up the service

- Create a `/etc/systemd/system/mithril-ipfs.service` description file for the service:

```bash
sudo bash -c 'cat > /etc/systemd/system/mithril-ipfs.service << EOF
[Unit]
Description=IPFS Kubo node service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=60
User=mithril-ipfs
Environment=IPFS_PATH=/var/lib/mithril-ipfs
LimitNOFILE=65536
ExecStart=/opt/mithril-ipfs/ipfs daemon --migrate

[Install]
WantedBy=multi-user.target
EOF'
```

Reload the service configuration (optional):

```bash
sudo systemctl daemon-reload
```

Then, start the service:

```bash
sudo systemctl start mithril-ipfs
```

Register the service to start on boot:

```bash
sudo systemctl enable mithril-ipfs
```

Monitor the status of the service:

```bash
systemctl status mithril-ipfs.service
```

Finally, monitor the logs of the service:

```bash
journalctl -u mithril-ipfs -f
```

#### Set up the automatic replication

##### Create the replication script

Create a `/opt/mithril-ipfs/replicate-immutable-archives.sh` script that pins the latest version of the directory and keeps the previous versions pinned:

```bash
sudo bash -c 'cat > /opt/mithril-ipfs/replicate-immutable-archives.sh << "EOF"
#!/bin/sh

# Pins the latest version of the immutable archives directory published under an IPNS name,
# keeping the previous versions pinned as older snapshots still reference them.

set -eu

ipns_name="$1"
state_file="${IPFS_PATH}/replicated-directory.path"
pin_timeout_seconds=14400

latest_path=$(ipfs name resolve --nocache "${ipns_name}")
previous_path=$(cat "${state_file}" 2>/dev/null || true)

if [ "${latest_path}" = "${previous_path}" ]; then
  echo "Replica is up to date: ${latest_path}"
  exit 0
fi

if [ -n "${previous_path}" ] && ipfs pin ls --type=recursive "${previous_path}" > /dev/null 2>&1; then
  timeout "${pin_timeout_seconds}" ipfs pin update --unpin=false "${previous_path}" "${latest_path}"
else
  timeout "${pin_timeout_seconds}" ipfs pin add --progress=false "${latest_path}"
fi

echo "${latest_path}" > "${state_file}.tmp"
mv "${state_file}.tmp" "${state_file}"
echo "Replica updated to: ${latest_path}"
EOF'
sudo chmod +x /opt/mithril-ipfs/replicate-immutable-archives.sh
```

##### Set up the replication service

- Create a `/etc/systemd/system/mithril-ipfs-replication.service` description file for the service:

```bash
sudo bash -c 'cat > /etc/systemd/system/mithril-ipfs-replication.service << EOF
[Unit]
Description=Immutable archives replication service
Requires=mithril-ipfs.service
After=mithril-ipfs.service

[Service]
Type=oneshot
User=mithril-ipfs
Environment=IPFS_PATH=/var/lib/mithril-ipfs
Environment=PATH=/opt/mithril-ipfs:/usr/bin:/bin
TimeoutStartSec=5h
ExecStart=/opt/mithril-ipfs/replicate-immutable-archives.sh **YOUR_IPNS_NAME**
EOF'
```

- Create a `/etc/systemd/system/mithril-ipfs-replication.timer` description file that runs the replication 30 minutes after the end of the previous run:

```bash
sudo bash -c 'cat > /etc/systemd/system/mithril-ipfs-replication.timer << EOF
[Unit]
Description=Immutable archives replication timer

[Timer]
OnBootSec=5min
OnUnitInactiveSec=30min

[Install]
WantedBy=timers.target
EOF'
```

Reload the service configuration (optional):

```bash
sudo systemctl daemon-reload
```

Then, start the first replication in the background:

```bash
sudo systemctl start --no-block mithril-ipfs-replication.service
```

:::info

The first replication downloads all the immutable archives, see the [Set up the replica](#set-up-the-replica) section for its expected duration. Each run stops after 4 hours and the next one resumes the download. The next replications only download the new archives.

:::

Register the timer to start on boot and start it:

```bash
sudo systemctl enable --now mithril-ipfs-replication.timer
```

Monitor the schedule of the timer:

```bash
systemctl list-timers mithril-ipfs-replication.timer
```

Finally, monitor the logs of the replication:

```bash
journalctl -u mithril-ipfs-replication -f
```

### Docker deployment

The list of available Kubo images on the registry is listed [here](https://hub.docker.com/r/ipfs/kubo/tags).

#### Prepare the configuration script

Create a `/opt/mithril-ipfs/container-init.d/configure-node.sh` script run by the container before it starts the Kubo node:

```bash
sudo mkdir -p /opt/mithril-ipfs/container-init.d
sudo bash -c 'cat > /opt/mithril-ipfs/container-init.d/configure-node.sh << EOF
#!/bin/sh
set -e

ipfs config Addresses.API /ip4/127.0.0.1/tcp/5001
ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8080
EOF'
```

If the machine is behind a NAT, announce its public address (use `/ip6/` instead of `/ip4/` for an IPv6 address):

```bash
sudo bash -c 'cat >> /opt/mithril-ipfs/container-init.d/configure-node.sh << EOF
ipfs config --json Addresses.AppendAnnounce "[\"/ip4/**YOUR_PUBLIC_IP_ADDRESS**/tcp/4001\", \"/ip4/**YOUR_PUBLIC_IP_ADDRESS**/udp/4001/quic-v1\"]"
EOF'
```

Raise the Bitswap server limits, which otherwise keep at most 1 MB in flight per peer and slow down the download of the archives by the clients:

```bash
sudo bash -c 'cat >> /opt/mithril-ipfs/container-init.d/configure-node.sh << EOF
ipfs config --json Internal.Bitswap.TaskWorkerCount 32
ipfs config --json Internal.Bitswap.EngineTaskWorkerCount 32
ipfs config --json Internal.Bitswap.EngineBlockstoreWorkerCount 256
ipfs config --json Internal.Bitswap.MaxOutstandingBytesPerPeer 8388608
EOF'
```

Then, create the replication script as described in the [Create the replication script](#create-the-replication-script) section.

#### Run the Docker container

Run the Kubo container with the `server` profile:

```bash
docker run -d --name mithril-ipfs --restart always \
  -e IPFS_PROFILE=server \
  -v mithril-ipfs-data:/data/ipfs \
  -v /opt/mithril-ipfs/container-init.d:/container-init.d:ro \
  -v /opt/mithril-ipfs/replicate-immutable-archives.sh:/usr/local/bin/replicate-immutable-archives.sh:ro \
  -p 4001:4001 -p 4001:4001/udp \
  ipfs/kubo:v0.43.1
```

Then, create an `ipfs_node` shell function to run Kubo commands in the container:

```bash
ipfs_node () {
  docker exec mithril-ipfs ipfs "$@"
}
```

Test that the node works:

```bash
ipfs_node --version
```

Finally, monitor the logs of the container:

```bash
docker logs -f mithril-ipfs
```

#### Set up the automatic replication

- Create a `/etc/systemd/system/mithril-ipfs-replication.service` description file for the service:

```bash
sudo bash -c 'cat > /etc/systemd/system/mithril-ipfs-replication.service << EOF
[Unit]
Description=Immutable archives replication service
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
TimeoutStartSec=5h
ExecStart=$(command -v docker) exec mithril-ipfs replicate-immutable-archives.sh **YOUR_IPNS_NAME**
EOF'
```

Then, create the timer and start the replication as described in the [Set up the replication service](#set-up-the-replication-service) section, starting from the creation of the `/etc/systemd/system/mithril-ipfs-replication.timer` file.

### Manual verification

:::tip

The following commands use the `ipfs_node` shell function defined in the [Create the service user](#create-the-service-user) section, or in the [Run the Docker container](#run-the-docker-container) section for a Docker deployment.

:::

#### Verify the connection to the IPFS network

Display the number of peers connected to your node:

```bash
ipfs_node swarm peers | wc -l
```

The number should be greater than `0` a few minutes after the start of the node.

#### Verify that the replica is complete

Resolve the IPNS name to the latest version of the directory:

```bash
export DIRECTORY_PATH=$(ipfs_node name resolve --nocache **YOUR_IPNS_NAME**)
echo $DIRECTORY_PATH
```

Display the size of the directory and the share stored locally:

```bash
ipfs_node files stat --with-local $DIRECTORY_PATH
```

You should see something like this once the replication is complete (`CumulativeSize` is the size of the directory in bytes):

```bash
bafybeih4c2gyqkfyspxmk4uq3ljpaxytrk6hbb2ldzcwp6cd5wyinhxcmy
Size: 0
CumulativeSize: 61834213907
ChildBlocks: 256
Type: directory
Mode: not set (not set)
Mtime: not set
Local: 62 GB of 62 GB (100.00%)
```

#### Verify that the replica is up to date

Check that the latest version of the directory is pinned:

```bash
ipfs_node pin ls --type=recursive $DIRECTORY_PATH
```

You should see the CID of the directory followed by `recursive`. Otherwise, the next replication run will pin it.

#### Verify that the replica is reachable

Display the peer ID of your node:

```bash
ipfs_node config Identity.PeerID
```

Then, open the [IPFS Check](https://check.ipfs.network) tool and run a check with:

- **CID**: the CID of the directory (the value of `$DIRECTORY_PATH` without the `/ipfs/` prefix)
- **Multiaddr**: `/p2p/**YOUR_PEER_ID**` (replace `**YOUR_PEER_ID**` with the peer ID of your node).

The check should report that your node is reachable, that it has the CID, and that it announces it to the IPFS network.
