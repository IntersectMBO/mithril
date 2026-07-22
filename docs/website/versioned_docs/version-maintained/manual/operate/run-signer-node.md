---
sidebar_position: 3
---

import CompiledBinaries from '../../compiled-binaries.mdx'

# Run a Mithril signer node

:::tip

For more information about the **Mithril protocol**, see the [About Mithril](../../mithril/intro.md) section.

:::

## Mithril signer deployment model

:::info

In this guide, you will learn how to set up a **Mithril signer** within the stake pool operator (SPO) infrastructure, both on Cardano `mainnet` and `testnet` environments:

- On `mainnet`, you **must** run the **production** deployment where the **Mithril signer** runs on the **Cardano block producer** machine and the **Mithril relay** runs on the **Cardano relay** machine. **Note** that you can also run the **production** deployment on `testnet`.
- You can also run **naive** deployment, where the **Mithril signer** runs on the **Cardano relay** machine. This is possible in the testnet environment only, and does not require setting up a **Mithril relay**.

:::

:::info

In the current setup, you don't need to install a Mithril aggregator.

:::

:::caution

The **production** deployment model is currently in beta.

:::

Below is the schema of the **production** deployment on mainnet:
[![Production Mithril Signer Deployment Model](images/signer-deployment-production.jpg)](images/signer-deployment-production.jpg)

and the schema of the **naive** deployment specifically for `testnets`:
[![Naive Mithril Signer Deployment Model](images/signer-deployment-naive.jpg)](images/signer-deployment-naive.jpg)

:::danger

On `mainnet`, you must **never** copy the `KES secret key` from the **Cardano block producer** machine!

:::

## Mithril keys certification

The **Mithril signer** uses your Cardano `operational certificate` and `KES secret key` files, which enable:

- Automatic computation of the `PoolId`
- Verification of your `PoolId` ownership and the associated stake used by the Mithril protocol
- Verification of your Mithril `signer secret key` ownership, which allows you to participate in the multi-signature process for certificate production on the Mithril network.

## Mithril signer footprint

The **Mithril signer** has been designed to have the lowest possible footprint in terms of CPU, memory, disk I/O, and storage.
Thus, there are no additional requirements for the recommended hardware to run a Cardano stake pool, as detailed in this [guide](https://developers.cardano.org/docs/operate-a-stake-pool/hardware-requirements).

:::info

Here are some figures about the Mithril signer node running on Cardano `mainnet`:

- It is **idle** most of the time with a very low **CPU** usage of less than `5%`
- It uses less than `175 MB` of **resident memory**
- It sends a **new signature** to the aggregator roughly every `10 minutes` and a **new registration** every `5 days` (`<1 MB` per day)
- When launched for the **first time**, a **pre-loading** phase occurs, during which the Cardano blocks and transactions are imported with a spike of `50-70%` CPU on one core for `~11 hours`
- When signing for the **first time**, the Cardano database digest cache needs to be built with a spike of `50-70%` CPU on one core for `~1 hour`
- Also, the full Cardano database files will be **read from disk once** during this cache building process
- Only **stake distributions**, **Mithril keys**, and some **cache** (for the **Cardano database** and **Cardano blocks and transactions**) are stored on the disk (`<300 MB`).

:::

### Cardano blocks and transactions certification footprint

Here is a detailed view of the Cardano blocks and transactions signature's impact (the most resource-intensive part of Mithril) on the SPO infrastructure on the `mainnet`:

#### CPU

[![Cardano blocks and transactions signer CPU](images/cardano-block-transaction-signer-cpu.png)](images/cardano-block-transaction-signer-cpu.png)

#### Memory

[![Cardano blocks and transactions signer memory](images/cardano-block-transaction-signer-res-memory.png)](images/cardano-block-transaction-signer-res-memory.png)

#### Disk

[![Cardano blocks and transactions signer disk](images/cardano-block-transaction-signer-disk-usage.png)](images/cardano-block-transaction-signer-disk-usage.png)

## Prerequisites

:::info

Note that this guide works only on a Linux machine.

:::

- To operate a **Cardano node** as a **stake pool**, you need:

  - The pool's `operational certificate`
  - The pool's `KES secret key`

- To access the file system of the **Cardano block-producing** node for **production** deployment (or of the **Cardano relay** node for **naive** deployment), you will need the following permissions:

  - Read rights on the `Database` folder (specified by the `--database-path` setting of the **Cardano node**)
  - Read and write rights on the `Inter Process Communication` file (typically defined by the `CARDANO_NODE_SOCKET_PATH` environment variable used to launch the **Cardano node**)

- Install a recent version of [`cardano-cli`](https://github.com/IntersectMBO/cardano-node/releases/tag/8.9.1) (version 8.9.1+)

- Install a correctly configured Rust toolchain (latest stable version); you can follow the instructions provided [here](https://www.rust-lang.org/learn/get-started)

- Install build tools `build-essential` and `m4`; for example, on Ubuntu/Debian/Mint, run `sudo apt install build-essential m4`

- Install OpenSSL development libraries; for example, on Ubuntu/Debian/Mint, run `apt install libssl-dev`

- Install a recent version of `jq` (version 1.6+) by running `apt install jq`

- Only for the **production** deployment, install a recent version of [`squid-cache`](http://www.squid-cache.org/) (version 6.12+).

## Set up the Mithril signer node

:::caution

- For **production** deployment, the **Mithril signer** setup is performed on the **Cardano block producer** machine

- For **naive** deployment, the **Mithril signer** setup is performed on the **Cardano relay** machine.

:::

:::info

Compare the version of your Cardano node with the minimum supported versions listed in the [`networks.json`](https://github.com/IntersectMBO/mithril/blob/main/networks.json) file to verify its compatibility with the Mithril signer.

First, check the version of your Cardano node by running the following command:

```bash
cardano-node --version
```

Then, refer to the minimum supported versions listed in the [`networks.json`](https://github.com/IntersectMBO/mithril/blob/main/networks.json) file.

You can also fetch the minimum supported version for your network using the command below:

```bash
wget -q -O - https://raw.githubusercontent.com/IntersectMBO/mithril/main/networks.json | jq -r '."**YOUR_CARDANO_NETWORK**"."cardano-minimum-version"."mithril-signer"'
```

Here is an example for `preprod`:

```bash
wget -q -O - https://raw.githubusercontent.com/IntersectMBO/mithril/main/networks.json | jq -r '."preprod"."cardano-minimum-version"."mithril-signer"'
```

:::

### Building your own executable

#### Download the source file

To download the source from GitHub (HTTPS), run:

```bash
git clone https://github.com/IntersectMBO/mithril.git
```

Or (SSH):

```bash
git clone git@github.com:IntersectMBO/mithril.git
```

#### Build the Mithril signer binary

First, switch to build a branch/tag:

```bash
# **YOUR_BUILD_BRANCH_OR_TAG** depends on the Mithril network you target,
# please refer to the **Build from** column of the **Mithril networks** section
git checkout **YOUR_BUILD_BRANCH_OR_TAG**
```

Then, change the directory:

```bash
cd mithril/mithril-signer
```

Run tests (optional):

```bash
make test
```

Finally, build the executable:

```bash
make build
```

### Download the pre-built binary

<CompiledBinaries node="mithril-signer"/>

### Verifying the binary

#### Verify the version of the binary

You can check that the Mithril signer binary is running the correct version by running:

```bash
./mithril-signer -V
```

You should see something like:

```bash
mithril-signer 0.2.0
```

:warning: Please verify that the displayed version matches the version described in the release/pre-release notes (refer to the **Build from** column in the **Mithril networks** section).

#### Verify the build

Check that the Mithril signer binary is working correctly by running the help function:

```bash
./mithril-signer -h
```

You should see:

```bash
An implementation of a Mithril signer

Usage: mithril-signer [OPTIONS]

Options:
  -r, --run-mode <RUN_MODE>
          Run Mode [env: RUN_MODE=] [default: dev]
  -v, --verbose...
          Verbosity level, add more v to increase
  -c, --configuration-dir <CONFIGURATION_DIR>
          Directory where the configuration file is located [default: ./config]
      --disable-digests-cache
          Disable immutables digests cache
      --reset-digests-cache
          If set the existing immutables digests cache will be reset
  -h, --help
          Print help information (use `--help` for more detail)
  -V, --version
          Print version information
```

:::tip

If you wish to delve deeper, you can access logs at various levels from the Mithril signer:

- Add `-v` for some logs (WARN)
- Add `-vv` for more logs (INFO)
- Add `-vvv` for even more logs (DEBUG)
- Add `-vvvv` for all logs (TRACE).

:::

### Installing the service

#### Move the executable

To move the executable to /opt/mithril, run:

```bash
sudo mkdir -p /opt/mithril
sudo mv mithril-signer /opt/mithril
```

#### Set up the service

:::caution

- `User=cardano`:
  Replace this value with the correct user. Here, we assume that the user running the **Cardano node** is `cardano`. The **Mithril signer** must imperatively run with the same user.

- In the `/opt/mithril/mithril-signer.env` env file:
  - `KES_SECRET_KEY_PATH=/cardano/keys/kes.skey`: replace `/cardano/keys/kes.skey` with the path to your Cardano `KES secret key` file
  - `OPERATIONAL_CERTIFICATE_PATH=/cardano/cert/opcert.cert`: replace `/cardano/cert/opcert.cert` with the path to your Cardano `operational certificate` file
  - `DB_DIRECTORY=/cardano/db`: replace `/cardano/db` with the path to the database folder of the **Cardano node** (the one in `--database-path`)
  - `CARDANO_NODE_SOCKET_PATH=/cardano/ipc/node.socket`: replace with the path to the IPC file (`CARDANO_NODE_SOCKET_PATH` env var)
  - `CARDANO_CLI_PATH=/app/bin/cardano-cli`: replace with the path to the `cardano-cli` executable
  - `DATA_STORES_DIRECTORY=/opt/mithril/stores`: replace with the path to a folder where the **Mithril signer** will store its data (eg, `/opt/mithril/stores`)
  - `STORE_RETENTION_LIMIT`: if set, this will limit the number of records in some internal stores (5 is a good fit)
  - `ERA_READER_ADAPTER_TYPE=cardano-chain`: replace `cardano-chain` with the era reader adapter type used in your Mithril network
  - `ERA_READER_ADAPTER_PARAMS={"address": "...", "verification_key": "..."}`: replace `{"address": "...", "verification_key": "..."}` with the era reader parameters that you need to compute by running the command `jq -nc --arg address $(wget -q -O - **YOUR_ERA_READER_ADDRESS**) --arg verification_key $(wget -q -O - **YOUR_ERA_READER_VERIFICATION_KEY**) '{"address": $address, "verification_key": $verification_key}'`
  - `RELAY_ENDPOINT=http://192.168.1.50:3132` **(optional)**: this is the endpoint of the **Mithril relay**, which is required for **production** deployment only. For **naive** deployment, do not set this variable in your environment file.

:::

:::tip

Here is an **example** set of values for **release-preprod** that will be used in this guide in the **tip** boxes to illustrate some commands:

- **YOUR_KES_SECRET_KEY_PATH**: `/cardano/keys/kes.skey`
- **YOUR_OPERATIONAL_CERTIFICATE_PATH**: `/cardano/keys/node.cert`
- **YOUR_CARDANO_NETWORK**: `preprod`
- **YOUR_AGGREGATOR_ENDPOINT**: `https://aggregator.release-preprod.api.mithril.network/aggregator`
- **YOUR_ERA_READER_ADAPTER_TYPE**: `cardano-chain`
- **YOUR_ERA_READER_ADAPTER_PARAMS**: `{"address": "addr_test1qpkyv2ws0deszm67t840sdnruqgr492n80g3y96xw3p2ksk6suj5musy6w8lsg3yjd09cnpgctc2qh386rtxphxt248qr0npnx", "verification_key": "5b35352c3232382c3134342c38372c3133382c3133362c34382c382c31342c3138372c38352c3134382c39372c3233322c3235352c3232392c33382c3234342c3234372c3230342c3139382c31332c33312c3232322c32352c3136342c35322c3130322c39312c3132302c3230382c3134375d"}`
- **YOUR_RELAY_ENDPOINT**: `192.168.1.50`
- **YOUR_RELAY_LISTENING_PORT**: `3132`
- **YOUR_BLOCK_PRODUCER_INTERNAL_IP**: `192.168.1.75`
- **YOUR_SIGNER_LOGS_PATH**: `/var/log/syslog`
- **YOUR_PARTY_ID**: `pool1hp72sauk0g0yqm4dzllz0pz6j93gewhllkzphn4hykkfmne43y`

:::

First, create an environment file that the service will use:

- For **production** deployment:

```bash
sudo bash -c 'cat > /opt/mithril/mithril-signer.env << EOF
KES_SECRET_KEY_PATH=**YOUR_KES_SECRET_KEY_PATH**
OPERATIONAL_CERTIFICATE_PATH=**YOUR_OPERATIONAL_CERTIFICATE_PATH**
NETWORK=**YOUR_CARDANO_NETWORK**
AGGREGATOR_ENDPOINT=**YOUR_AGGREGATOR_ENDPOINT**
RUN_INTERVAL=60000
DB_DIRECTORY=/cardano/db
CARDANO_NODE_SOCKET_PATH=/cardano/ipc/node.socket
CARDANO_CLI_PATH=/app/bin/cardano-cli
DATA_STORES_DIRECTORY=/opt/mithril/stores
STORE_RETENTION_LIMIT=5
ERA_READER_ADAPTER_TYPE=**YOUR_ERA_READER_ADAPTER_TYPE**
ERA_READER_ADAPTER_PARAMS=**YOUR_ERA_READER_ADAPTER_PARAMS**
RELAY_ENDPOINT=**YOUR_RELAY_ENDPOINT**
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set for `release-preprod`:

```bash
sudo bash -c 'cat > /opt/mithril/mithril-signer.env << EOF
KES_SECRET_KEY_PATH=/cardano/keys/kes.skey
OPERATIONAL_CERTIFICATE_PATH=/cardano/keys/node.cert
NETWORK=preprod
AGGREGATOR_ENDPOINT=https://aggregator.release-preprod.api.mithril.network/aggregator
RUN_INTERVAL=60000
DB_DIRECTORY=/cardano/db
CARDANO_NODE_SOCKET_PATH=/cardano/ipc/node.socket
CARDANO_CLI_PATH=/app/bin/cardano-cli
DATA_STORES_DIRECTORY=/opt/mithril/stores
STORE_RETENTION_LIMIT=5
ERA_READER_ADAPTER_TYPE=cardano-chain
ERA_READER_ADAPTER_PARAMS={"address": "addr_test1qpkyv2ws0deszm67t840sdnruqgr492n80g3y96xw3p2ksk6suj5musy6w8lsg3yjd09cnpgctc2qh386rtxphxt248qr0npnx", "verification_key": "5b35352c3232382c3134342c38372c3133382c3133362c34382c382c31342c3138372c38352c3134382c39372c3233322c3235352c3232392c33382c3234342c3234372c3230342c3139382c31332c33312c3232322c32352c3136342c35322c3130322c39312c3132302c3230382c3134375d"}
RELAY_ENDPOINT=http://192.168.1.50:3132
EOF'
```

:::

- For **naive** deployment:

```bash
sudo bash -c 'cat > /opt/mithril/mithril-signer.env << EOF
KES_SECRET_KEY_PATH=**YOUR_KES_SECRET_KEY_PATH**
OPERATIONAL_CERTIFICATE_PATH=**YOUR_OPERATIONAL_CERTIFICATE_PATH**
NETWORK=**YOUR_CARDANO_NETWORK**
AGGREGATOR_ENDPOINT=**YOUR_AGGREGATOR_ENDPOINT**
RUN_INTERVAL=60000
DB_DIRECTORY=/cardano/db
CARDANO_NODE_SOCKET_PATH=/cardano/ipc/node.socket
CARDANO_CLI_PATH=/app/bin/cardano-cli
DATA_STORES_DIRECTORY=/opt/mithril/stores
STORE_RETENTION_LIMIT=5
ERA_READER_ADAPTER_TYPE=**YOUR_ERA_READER_ADAPTER_TYPE**
ERA_READER_ADAPTER_PARAMS=**YOUR_ERA_READER_ADAPTER_PARAMS**
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set for `release-preprod`:

```bash
sudo bash -c 'cat > /opt/mithril/mithril-signer.env << EOF
KES_SECRET_KEY_PATH=/cardano/keys/kes.skey
OPERATIONAL_CERTIFICATE_PATH=/cardano/keys/node.cert
NETWORK=preprod
AGGREGATOR_ENDPOINT=https://aggregator.release-preprod.api.mithril.network/aggregator
RUN_INTERVAL=60000
DB_DIRECTORY=/cardano/db
CARDANO_NODE_SOCKET_PATH=/cardano/ipc/node.socket
CARDANO_CLI_PATH=/app/bin/cardano-cli
DATA_STORES_DIRECTORY=/opt/mithril/stores
STORE_RETENTION_LIMIT=5
ERA_READER_ADAPTER_TYPE=cardano-chain
ERA_READER_ADAPTER_PARAMS={"address": "addr_test1qpkyv2ws0deszm67t840sdnruqgr492n80g3y96xw3p2ksk6suj5musy6w8lsg3yjd09cnpgctc2qh386rtxphxt248qr0npnx", "verification_key": "5b35352c3232382c3134342c38372c3133382c3133362c34382c382c31342c3138372c38352c3134382c39372c3233322c3235352c3232392c33382c3234342c3234372c3230342c3139382c31332c33312c3232322c32352c3136342c35322c3130322c39312c3132302c3230382c3134375d"}
EOF'
```

:::

Then, create a `/etc/systemd/system/mithril-signer.service` description file for the service:

```bash
sudo bash -c 'cat > /etc/systemd/system/mithril-signer.service << EOF
[Unit]
Description=Mithril signer service
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=60
User=cardano
EnvironmentFile=/opt/mithril/mithril-signer.env
ExecStart=/opt/mithril/mithril-signer -vvv

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
sudo systemctl start mithril-signer
```

Register the service to start on boot:

```bash
sudo systemctl enable mithril-signer
```

Monitor the status of the service:

```bash
systemctl status mithril-signer.service
```

Finally, monitor the logs of the service:

```bash
tail -f /var/log/syslog | grep mithril-signer
```

### Activate a Prometheus endpoint

The Mithril signer node can expose basic metrics on a Prometheus endpoint, which is not activated by default.

| Metrics                                                         | Description                                                                         |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **mithril_signer_signer_registration_success_since_startup**    | Number of successful signer registrations since startup on a Mithril signer node    |
| **mithril_signer_signer_registration_total_since_startup**      | Number of signer registrations since startup on a Mithril signer node               |
| **mithril_signer_signer_registration_success_last_epoch**       | Latest epoch at which signer successfully registered on a Mithril signer node       |
| **mithril_signer_signature_registration_success_since_startup** | Number of successful signature registrations since startup on a Mithril signer node |
| **mithril_signer_signature_registration_total_since_startup**   | Number of signature registrations since startup on a Mithril signer node            |
| **mithril_signer_signature_registration_success_last_epoch**    | Latest epoch at which signature successfully registered on a Mithril signer node    |
| **mithril_signer_runtime_cycle_success_since_startup**          | Number of successful runtime cycles since startup on a Mithril signer node          |
| **mithril_signer_runtime_cycle_total_since_startup**            | Number of runtime cycles since startup on a Mithril signer node                     |

To expose metrics on the endpoint, append the following environment variable to your environment file. In that case, the metrics server will listen on the `9090` port:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-signer.env << EOF
ENABLE_METRICS_SERVER=true
EOF`
```

You can also specify a custom listen IP address and port for the metrics server:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-signer.env << EOF
ENABLE_METRICS_SERVER=true
METRICS_SERVER_IP=**YOUR_METRICS_SERVER_IP**
METRICS_SERVER_PORT=**YOUR_METRICS_SERVER_PORT**
EOF`
```

:::tip

Here is an example that reproduces the default configuration for the Prometheus server:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-signer.env << EOF
ENABLE_METRICS_SERVER=true
METRICS_SERVER_IP=0.0.0.0
METRICS_SERVER_PORT=9090
EOF`
```

:::

:::info

When activated, the metrics endpoint will be accessible at the `http://**YOUR_METRICS_SERVER_IP**:**YOUR_METRICS_SERVER_PORT**/metrics` location, which translates to [`http://0.0.0.0:9090/metrics`](http://0.0.0.0:9090/metrics) with the default configuration.

:::

:::info

See this [Grafana template](https://grafana.com/grafana/dashboards/20776-mithril-signer/), which helps to easily set up a dashboard for this Prometheus endpoint (ID 20776).

:::

### Rotating the KES keys

:::danger

When the KES keys expire, the Mithril signer cannot register with the Mithril protocol.

:::

After rotating the KES keys on your Cardano block producer, we recommend following this upgrade procedure for your Mithril signer node:

1. Update the `KES_SECRET_KEY_PATH` entry of your environment file to reflect the location of the **new KES secret key file**
2. Update the `OPERATIONAL_CERTIFICATE_PATH` entry of your environment file to reflect the location of the **new operational certificate file**
3. Restart your Mithril signer service with the following command:

```bash
sudo systemctl restart mithril-signer
```

4. Check the logs of your signer node and make sure that it has successfully registered after restarting (the following log should be displayed: `STATE MACHINE: new cycle: Registered`).

## Set up the Mithril relay node

:::caution

- For **production** deployment, the setup of the **Mithril relay** is performed on the **Cardano relay** machine

- For **naive** deployment, this step is not necessary.

:::

### Building Squid from source

:::info

- If you have already installed `Squid` via the `apt` package manager, we recommend that you delete it before manually building it from source by running the following commands:

  - `sudo systemctl stop squid`
  - `sudo apt remove squid`
  - `sudo apt autoremove`

- The FAQ for compiling `Squid` is available [here](https://wiki.squid-cache.org/SquidFaq/CompilingSquid)

- You will need a C++ compiler that can be installed with the `sudo apt install build-essential` command.

:::

On the [Squid page with released versions](https://www.squid-cache.org/Versions/), identify the latest stable released version (currently `6.12`) and download it:

```bash
wget https://www.squid-cache.org/Versions/v6/squid-6.12.tar.gz
```

Uncompress the downloaded archive and change the directory:

```bash
tar xzf squid-6.12.tar.gz
cd squid-6.12
```

Then, configure the compilation:

```bash
./configure \
    --prefix=/opt/squid \
    --localstatedir=/opt/squid/var \
    --libexecdir=/opt/squid/lib/squid \
    --datadir=/opt/squid/share/squid \
    --sysconfdir=/etc/squid \
    --with-default-user=squid \
    --with-logdir=/opt/squid/var/log/squid \
    --with-pidfile=/opt/squid/var/run/squid.pid
```

Compile the sources:

```bash
make
```

Install `squid` binary:

```bash
sudo make install
```

Optionally, verify that the version is correct:

```bash
/opt/squid/sbin/squid -v
```

You should see a result like this:

```bash
Squid Cache: Version 6.12
Service Name: squid
configure options:  '--prefix=/opt/squid' '--localstatedir=/opt/squid/var' '--libexecdir=/opt/squid/lib/squid' '--datadir=/opt/squid/share/squid' '--sysconfdir=/etc/squid' '--with-default-user=squid' '--with-logdir=/opt/squid/var/log/squid' '--with-pidfile=/opt/squid/var/run/squid.pid'
```

### Configuring the Squid proxy

:::info

The **Mithril relay** node serves as a forward proxy, relaying traffic between the **Mithril signer** and the **Mithril aggregator**. When appropriately configured, it facilitates the security of the **block-producing** node. You can use `squid` to operate this forward proxy, and this section presents a recommended configuration.

:::

Make a copy of the original configuration:

```bash
sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.bak
```

Prepare the forward proxy configuration file:

```bash
sudo bash -c 'cat > /etc/squid/squid.conf << EOF
# Listening port (port 3132 is recommended)
http_port **YOUR_RELAY_LISTENING_PORT**

# ACL for the internal IP of your block producer node
acl block_producer_internal_ip src **YOUR_BLOCK_PRODUCER_INTERNAL_IP**

# ACL for aggregator endpoint
acl aggregator_domain dstdomain .mithril.network

# ACL for SSL port only
acl SSL_port port 443

# Allowed traffic
http_access allow block_producer_internal_ip aggregator_domain SSL_port

# Do not disclose block producer internal IP
forwarded_for delete

# Turn off via header
via off

# Deny request for original source of a request
follow_x_forwarded_for deny all

# Anonymize request headers
request_header_access signer-node-version allow all
request_header_access mithril-api-version allow all
request_header_access Authorization allow all
request_header_access Proxy-Authorization allow all
request_header_access Cache-Control allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Connection allow all
request_header_access All deny all

# Disable cache
cache deny all

# Deny everything else
http_access deny all

EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set for `release-preprod`:

```bash
sudo bash -c 'cat > /etc/squid/squid.conf << EOF
# Listening port (port 3132 is recommended)
http_port 3132

# ACL for the internal IP of your block producer node
acl block_producer_internal_ip src 192.168.1.75

# ACL for aggregator endpoint
acl aggregator_domain dstdomain .mithril.network

# ACL for SSL port only
acl SSL_port port 443

# Allowed traffic
http_access allow block_producer_internal_ip aggregator_domain SSL_port

# Do not disclose block producer internal IP
forwarded_for delete

# Turn off via header
via off

# Deny request for original source of a request
follow_x_forwarded_for deny all

# Anonymize request headers
request_header_access signer-node-version allow all
request_header_access mithril-api-version allow all
request_header_access Authorization allow all
request_header_access Proxy-Authorization allow all
request_header_access Cache-Control allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Connection allow all
request_header_access All deny all

# Disable cache
cache deny all

# Deny everything else
http_access deny all

EOF'
```

:::

:::tip

If you are using the same Cardano relay for multiple Cardano block producers, you will need to add a new line per block producer to authorize its internal IP:

```bash
# ACL for the internal IP of your block producer node
acl block_producer_internal_ip src **YOUR_BLOCK_PRODUCER_INTERNAL_IP_1**
acl block_producer_internal_ip src **YOUR_BLOCK_PRODUCER_INTERNAL_IP_2**
acl block_producer_internal_ip src **YOUR_BLOCK_PRODUCER_INTERNAL_IP_3**
```

:::

With this configuration, the proxy will:

- Accept incoming traffic originating from the internal IP of the block-producing machine
- Accept incoming traffic directed to the listening port of the proxy
- Accept incoming HTTPS traffic proxied to `mithril.network` domain hosts
- Anonymize the traffic completely and avoid disclosing any information about the block-producing machine
- Deny all other traffic.

:::info

:::

### Installing the service

Create (or re-use) an unprivileged system user on the machine:

```bash
sudo adduser --system --no-create-home --group squid
```

Change ownership of `/opt/squid/var` directory:

```bash
sudo chown squid -R /opt/squid/var/
sudo chgrp squid -R /opt/squid/var/
```

Create a `/etc/systemd/system/squid.service` description file for the service:

```bash
sudo bash -c 'cat > /etc/systemd/system/squid.service << EOF
[Unit]
Description=Squid service
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=60
User=squid
Group=squid
ExecStart=/opt/squid/sbin/squid -f /etc/squid/squid.conf -d5
PIDFile=/opt/squid/var/run/squid.pid

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
sudo systemctl start squid
```

Register the service to start on boot:

```bash
sudo systemctl enable squid
```

Monitor the status of the service:

```bash
systemctl status squid
```

Finally, monitor the logs of the service:

```bash
tail -f /var/log/syslog | grep squid
```

And monitor squid access logs:

```bash
sudo tail -f /opt/squid/var/log/squid/access.log
```

:::tip

If your **Squid service** does not start properly and you have the error message `FATAL: /dev/null (13) Permission denied` in the logs of the service, it means that some permissions need to be fixed following the creation of the new `squid` user by running the following commands:

- `sudo chmod 666 /dev/null`
- `sudo systemctl restart squid`

:::

### Firewall configuration

:::info

We assume that the **Cardano relay** machine is protected by a firewall. Therefore, it is necessary to allow the proxied traffic originating from the **Cardano block producer** through this firewall.
:::

#### About the Cardano relay machine

You need to allow incoming traffic on the listening port of the **Mithril relay** on the **Cardano relay** machine, originating from the **Cardano block producer** machine.

Assuming you are using [`Uncomplicated Firewall`](https://en.wikipedia.org/wiki/Uncomplicated_Firewall) (`0.36+`), the command to open that traffic is:

```bash
sudo ufw allow from **YOUR_BLOCK_PRODUCER_INTERNAL_IP** to any port **YOUR_RELAY_LISTENING_PORT** proto tcp
```

:::tip

Here is an example of the aforementioned command created with the example set for `release-preprod`:

```bash
sudo ufw allow from 192.168.1.75 to any port 3132 proto tcp
```

:::

Assuming you are using [`Iptables`](https://en.wikipedia.org/wiki/Iptables) (`1.8.7+`), the command to open that traffic is:

```bash
sudo iptables -A INPUT -s **YOUR_BLOCK_PRODUCER_INTERNAL_IP** -p tcp --dport **YOUR_RELAY_LISTENING_PORT** -j ACCEPT
sudo iptables -L -v
sudo service netfilter-persistent save
```

:::tip

Here is an example of the aforementioned command created with the example set for `release-preprod`:

```bash
sudo iptables -A INPUT -s 192.168.1.75 -p tcp --dport 3132 -j ACCEPT
sudo iptables -L -v
sudo service netfilter-persistent save
```

:::

## Set up the DMQ node (unstable)

:::danger

The DMQ node setup is currently **unstable** and not suitable for production use.

During the stabilization and ramp-up phase of the DMQ network:

- Signatures are still sent to the central aggregator (using the DMQ node is harmless)
- This section is subject to frequent changes.

:::

The DMQ node supports the implementation of a **Decentralized Message Queue** (DMQ) for Mithril. The DMQ protocol allows Mithril signers to exchange signatures in a decentralized manner, enhancing the robustness and scalability of the Mithril networks. Once stabilized and deployed on a majority of SPOs on a Mithril network, the DMQ protocol will allow multiple aggregators to operate simultaneously, improving the overall availability of the Mithril protocol. The DMQ protocol is fully described in the [CIP-0137](https://cips.cardano.org/cip/CIP-0137).

The DMQ node follows the same deployment model as the Mithril signer node and the Cardano node:

- For **production** deployment, the **DMQ node** setup is performed on the **Cardano block producer** machine and on the **Cardano relay** machine
- For **naive** deployment, the **DMQ node** setup is performed on the **Cardano relay** machine only (for tests only).

If you choose the **production** deployment, you will need to install and configure the DMQ node on both the **Cardano block producer** machine and the **Cardano relay** machine, following the same steps.

:::info

**Which deployment should I use?**

In this section, **production deployment** refers only to the recommended **two-machine deployment model** (Cardano block producer + Cardano relay), not to the maturity or production-readiness of the **DMQ** itself. The earlier warning that the DMQ setup is **not suitable for production use on mainnet** still applies.

On **testnet**, we recommend the **production** deployment model, but you can use the **naive** deployment for testing purposes only.

:::

:::info

**Which DMQ node socket path should I use in the Mithril signer configuration?**

The Mithril signer must connect to the DMQ node socket that is on the **same machine** where the signer is running:

- For **production** deployment: use the **block-producer** DMQ node socket path (since the Mithril signer runs on the block producer machine)
- For **naive** deployment: use the **relay** DMQ node socket path (since the Mithril signer runs on the relay machine).

:::

:::caution

- Here is the needed information to set up a DMQ node:
  - `**YOUR_DMQ_NODE_SOCKET_PATH**`: replace with the path to the IPC file of the DMQ node
  - `**YOUR_CARDANO_NODE_SOCKET_PATH**`: replace with the path to the IPC file of the Cardano node
  - `**YOUR_CARDANO_NETWORK_MAGIC**`: replace with the network magic number of your Cardano network
  - `**YOUR_DMQ_NETWORK_MAGIC**`: replace with the network magic number of your DMQ network (the value can be found in the [Mithril networks](../getting-started/network-configurations.md) table)
  - `**YOUR_DMQ_NODE_RELAY_INTERNAL_ADDRESS**`: replace with the **internal** IP address of your DMQ node on the relay machine
  - `**YOUR_DMQ_NODE_RELAY_PUBLIC_ADDRESS**`: replace with the **public** IP address of your DMQ node on the relay machine
  - `**YOUR_DMQ_NODE_RELAY_PORT**`: replace with the listening port of your DMQ node on the relay machine
  - `**YOUR_DMQ_NODE_BLOCK_PRODUCER_INTERNAL_ADDRESS**`: replace with the **internal** IP address of your DMQ node on the block producer machine (this is sensitive information that must not be shared publicly)
  - `**YOUR_DMQ_NODE_BLOCK_PRODUCER_PORT**`: replace with the listening port of your DMQ node on the block producer machine
  - `**YOUR_DMQ_BOOTSTRAP_PEER_ADDRESS**`: replace with the IP address of your DMQ bootstrap peer (the address can be found in the [Mithril networks](../getting-started/network-configurations.md) table)
  - `**YOUR_DMQ_BOOTSTRAP_PEER_PORT**`: replace with the listening port of your DMQ bootstrap peer (the value can be found in the [Mithril networks](../getting-started/network-configurations.md) table).

:::

:::tip

Here is an **example** set of values for **pre-release-preview** that will be used in this guide in the **tip** boxes to illustrate some commands:

- **YOUR_DMQ_NODE_SOCKET_PATH**: `/dmq/ipc/node.socket`
- **YOUR_CARDANO_NODE_SOCKET_PATH**: `/cardano/ipc/node.socket`
- **YOUR_CARDANO_NETWORK_MAGIC**: `2`
- **YOUR_DMQ_NETWORK_MAGIC**: `2147483650`
- **YOUR_DMQ_NODE_RELAY_INTERNAL_ADDRESS**: `192.168.1.30`
- **YOUR_DMQ_NODE_RELAY_PUBLIC_ADDRESS**: `34.14.65.160`
- **YOUR_DMQ_NODE_RELAY_PORT**: `6161`
- **YOUR_DMQ_NODE_BLOCK_PRODUCER_INTERNAL_ADDRESS**: `192.168.1.60`
- **YOUR_DMQ_NODE_BLOCK_PRODUCER_PORT**: `6161`
- **YOUR_DMQ_BOOTSTRAP_PEER_ADDRESS**: `34.76.22.193`
- **YOUR_DMQ_BOOTSTRAP_PEER_PORT**: `6161`

:::

### Download the pre-built binary

:::tip

As we are still in a testing stage, we only support the `pre-release-preview` network.

You can use these parameters for the **pre-release-preview** network:

- **DMQ_RELEASE_URL**: `https://github.com/IntersectMBO/dmq-node/releases/download/0.4.2.0/dmq-node-linux.tar.gz`

_These URLs may change in the future; please refer to this page for the latest released version of the DMQ node binary._

:::

To download the latest released version of the DMQ node binary, run the following command:

```bash
curl --fail -sL -o dmq-node.tar.gz **DMQ_RELEASE_URL**
```

Then, extract the archive:

```bash
tar -xzf dmq-node.tar.gz --strip-components=2 result/bin
```

And test that the binary works:

```bash
./dmq-node --version
```

You should see something like:

```bash
dmq-node version: 0.2.0.0
```

### Installing the service

#### Move the executable

To move the executable to /opt/dmq, run:

```bash
sudo mkdir -p /opt/dmq
sudo mv dmq-node /opt/dmq
```

#### Create the DMQ node socket directory

Create the directory that will hold the DMQ node IPC socket file:

```bash
sudo mkdir -p $(dirname **YOUR_DMQ_NODE_SOCKET_PATH**)
sudo chown cardano:cardano $(dirname **YOUR_DMQ_NODE_SOCKET_PATH**)
```

:::tip

Here is an example of the aforementioned command created with the example set for `pre-release-preview`:

```bash
sudo mkdir -p $(dirname /dmq/ipc/node.socket)
sudo chown cardano:cardano $(dirname /dmq/ipc/node.socket)
```

:::

#### Prepare the configuration file of the DMQ node

- For a **DMQ node on the relay machine**, create a `/opt/dmq/config-relay.json` configuration file:

```bash
bash -c 'cat > /opt/dmq/config-relay.json << EOF
{
  "NetworkMagic": **YOUR_DMQ_NETWORK_MAGIC**,
  "CardanoNetworkMagic": **YOUR_CARDANO_NETWORK_MAGIC**,
  "CardanoNodeSocket": "**YOUR_CARDANO_NODE_SOCKET_PATH**",
  "PeerSharing": true,
  "PeerSelectionCounters": true,
  "TraceOptions": {
    "": {
      "backends": [
        "Stdout MachineFormat",
        "PrometheusSimple suffix 127.0.0.1 12000"
      ],
      "severity": "Debug"
    }
  }
}
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set for `pre-release-preview`:

```bash
bash -c 'cat > /opt/dmq/config-relay.json << EOF
{
  "NetworkMagic": 2147483650,
  "CardanoNetworkMagic": 2,
  "CardanoNodeSocket": "/cardano/ipc/node.socket",
  "PeerSharing": true,
  "PeerSelectionCounters": true,
  "TraceOptions": {
    "": {
      "backends": [
        "Stdout MachineFormat",
        "PrometheusSimple suffix 127.0.0.1 12000"
      ],
      "severity": "Debug"
    }
  }
}
EOF'
```

:::

- For a **DMQ node on the block-producer machine**, create a `/opt/dmq/config-bp.json` configuration file:

```bash
bash -c 'cat > /opt/dmq/config-bp.json << EOF
{
  "NetworkMagic": **YOUR_DMQ_NETWORK_MAGIC**,
  "CardanoNetworkMagic": **YOUR_CARDANO_NETWORK_MAGIC**,
  "CardanoNodeSocket": "**YOUR_CARDANO_NODE_SOCKET_PATH**",
  "PeerSharing": false,
  "PeerSelectionCounters": true,
  "TraceOptions": {
    "": {
      "backends": [
        "Stdout MachineFormat",
        "PrometheusSimple suffix 127.0.0.1 12000"
      ],
      "severity": "Debug"
    }
  }
}
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set for `pre-release-preview`:

```bash
bash -c 'cat > /opt/dmq/config-bp.json << EOF
{
  "NetworkMagic": 2147483650,
  "CardanoNetworkMagic": 2,
  "CardanoNodeSocket": "/cardano/ipc/node.socket",
  "PeerSharing": false,
  "PeerSelectionCounters": true,
  "TraceOptions": {
    "": {
      "backends": [
        "Stdout MachineFormat",
        "PrometheusSimple suffix 127.0.0.1 12000"
      ],
      "severity": "Debug"
    }
  }
}
EOF'
```

:::

#### Prepare the topology file for the DMQ node

:::tip

The DMQ node's topology file follows a similar format to the Cardano node's topology file. More information is available at [Cardano node topology](https://developers.cardano.org/docs/get-started/infrastructure/node/topology/).

:::

:::info

**Which peers should be configured for each DMQ node?**

- The **relay** DMQ node connects to the **DMQ bootstrap peer** from the [Mithril networks](../getting-started/network-configurations.md) table. This is how your relay discovers and communicates with the rest of the DMQ network.
- The **block producer** DMQ node connects **only** to your own **relay** DMQ node (using the relay's **internal** IP address). The block producer should **never** connect directly to external bootstrap peers.

:::

- For a **DMQ node on the relay machine**, create a `/opt/dmq/topology-relay.json` configuration file:

```bash
bash -c 'cat > /opt/dmq/topology-relay.json << EOF
{
  "bootstrapPeers": [],
  "localRoots": [
    {
      "accessPoints": [
        {
          "address": "**YOUR_DMQ_BOOTSTRAP_PEER_ADDRESS**",
          "port": **YOUR_DMQ_BOOTSTRAP_PEER_PORT**,
          "valency": 1
        }
      ],
      "advertise": true,
      "trustable": false,
      "valency": 2
    }
  ],
  "peerSnapshotFile": null,
  "publicRoots": [
    {
      "accessPoints": [],
      "advertise": false
    }
  ]
}
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set for `pre-release-preview`:

```bash
bash -c 'cat > /opt/dmq/topology-relay.json << EOF
{
  "bootstrapPeers": [],
  "localRoots": [
    {
      "accessPoints": [
        {
          "address": "34.76.22.193",
          "port": 6161,
          "valency": 1
        }
      ],
      "advertise": true,
      "trustable": false,
      "valency": 2
    }
  ],
  "peerSnapshotFile": null,
  "publicRoots": [
    {
      "accessPoints": [],
      "advertise": false
    }
  ]
}
EOF'
```

:::

- For a **DMQ node on the block-producer machine**, create a `/opt/dmq/topology-bp.json` configuration file:

```bash
bash -c 'cat > /opt/dmq/topology-bp.json << EOF
{
  "bootstrapPeers": [],
  "localRoots": [
    {
      "accessPoints": [
        {
          "address": "**YOUR_DMQ_NODE_RELAY_INTERNAL_ADDRESS**",
          "port": **YOUR_DMQ_NODE_RELAY_PORT**,
          "valency": 1
        }
      ],
      "advertise": false,
      "trustable": false,
      "valency": 2
    }
  ],
  "peerSnapshotFile": null,
  "publicRoots": [
    {
      "accessPoints": [],
      "advertise": false
    }
  ]
}
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set for `pre-release-preview`:

```bash
bash -c 'cat > /opt/dmq/topology-bp.json << EOF
{
  "bootstrapPeers": [],
  "localRoots": [
    {
      "accessPoints": [
        {
          "address": "192.168.1.30",
          "port": 6161,
          "valency": 1
        }
      ],
      "advertise": false,
      "trustable": false,
      "valency": 2
    }
  ],
  "peerSnapshotFile": null,
  "publicRoots": [
    {
      "accessPoints": [],
      "advertise": false
    }
  ]
}
EOF'
```

:::

#### Set up the service

:::caution

- `User=cardano`:
  Replace this value with the correct user. We assume that the user running the **Cardano node** is `cardano`. The **DMQ node** must imperatively run with the same user.

:::

- For a **DMQ node on the relay machine**, create a `/etc/systemd/system/dmq-relay.service` description file for the service:

```bash
sudo bash -c 'cat > /etc/systemd/system/dmq-relay.service << EOF
[Unit]
Description=DMQ relay service
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=60
User=cardano
ExecStart=/opt/dmq/dmq-node --configuration-file /opt/dmq/config-relay.json --topology-file /opt/dmq/topology-relay.json --local-socket **YOUR_DMQ_NODE_SOCKET_PATH** --host-addr **YOUR_DMQ_NODE_RELAY_PUBLIC_ADDRESS** --port **YOUR_DMQ_NODE_RELAY_PORT**

[Install]
WantedBy=multi-user.target
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set for `pre-release-preview`:

```bash
sudo bash -c 'cat > /etc/systemd/system/dmq-relay.service << EOF
[Unit]
Description=DMQ relay service
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=60
User=cardano
ExecStart=/opt/dmq/dmq-node --configuration-file /opt/dmq/config-relay.json --topology-file /opt/dmq/topology-relay.json --local-socket /dmq/ipc/node.socket --host-addr 34.14.65.160 --port 6161

[Install]
WantedBy=multi-user.target
EOF'
```

:::

Reload the service configuration (optional):

```bash
sudo systemctl daemon-reload
```

Then, start the service:

```bash
sudo systemctl start dmq-relay
```

Register the service to start on boot:

```bash
sudo systemctl enable dmq-relay
```

Monitor the status of the service:

```bash
systemctl status dmq-relay.service
```

Finally, monitor the logs of the service:

```bash
tail -f /var/log/syslog | grep dmq-relay
```

- For a **DMQ node on the block-producer machine**, create a `/etc/systemd/system/dmq-bp.service` description file for the service:

```bash
sudo bash -c 'cat > /etc/systemd/system/dmq-bp.service << EOF
[Unit]
Description=DMQ block-producer service
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=60
User=cardano
ExecStart=/opt/dmq/dmq-node --configuration-file /opt/dmq/config-bp.json --topology-file /opt/dmq/topology-bp.json --local-socket **YOUR_DMQ_NODE_SOCKET_PATH** --host-addr **YOUR_DMQ_NODE_BLOCK_PRODUCER_INTERNAL_ADDRESS** --port **YOUR_DMQ_NODE_BLOCK_PRODUCER_PORT**

[Install]
WantedBy=multi-user.target
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set for `pre-release-preview`:

```bash
sudo bash -c 'cat > /etc/systemd/system/dmq-bp.service << EOF
[Unit]
Description=DMQ block-producer service
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=60
User=cardano
ExecStart=/opt/dmq/dmq-node --configuration-file /opt/dmq/config-bp.json --topology-file /opt/dmq/topology-bp.json --local-socket /dmq/ipc/node.socket --host-addr 192.168.1.60 --port 6161

[Install]
WantedBy=multi-user.target
EOF'
```

:::

Reload the service configuration (optional):

```bash
sudo systemctl daemon-reload
```

Then, start the service:

```bash
sudo systemctl start dmq-bp
```

Register the service to start on boot:

```bash
sudo systemctl enable dmq-bp
```

Monitor the status of the service:

```bash
systemctl status dmq-bp.service
```

Finally, monitor the logs of the service:

```bash
tail -f /var/log/syslog | grep dmq-bp
```

### Update the configuration of the Mithril signer

The Mithril signer node must be configured to use the DMQ node. The socket path to use depends on your deployment model:

- For **production** deployment: use the **block-producer** DMQ node socket path (the Mithril signer runs on the block producer machine)
- For **naive** deployment: use the **relay** DMQ node socket path (the Mithril signer runs on the relay machine).

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-signer.env << EOF
DMQ_NODE_SOCKET_PATH=**YOUR_DMQ_NODE_SOCKET_PATH**
EOF'
```

:::tip

Here is an example of the aforementioned command created with the example set for `pre-release-preview`:

```bash
sudo bash -c 'cat >> /opt/mithril/mithril-signer.env << EOF
DMQ_NODE_SOCKET_PATH=/dmq/ipc/node.socket
EOF'
```

:::

### Firewall configuration

You should use a configuration that is very similar to your Cardano nodes' configuration:

- For the **DMQ node on the relay machine**, allow incoming traffic on the listening port of your DMQ relay node from the **Cardano block producer** machine
- For the **DMQ node on the block-producer machine**, allow incoming traffic on the listening port of your DMQ block-producer node from the **DMQ relay** machine only.

:::tip

More information about the recommended firewall configuration of the Cardano node is available at [Cardano firewall configuration](https://developers.cardano.org/docs/operate-a-stake-pool/deployment-scenarios/hardening-server/#7--firewall-configuration).

:::

## Verify the Mithril signer deployment

:::tip
There is a delay of `2` epochs between the signer node's registration and its ability to generate individual signatures. This delay is further explained in the [Mithril certificate chain in depth](https://mithril.network/doc/mithril/mithril-protocol/certificates) documentation.

Once this delay has passed, you should be able to observe your `PoolId` listed in some of the certificates accessible on the [`Mithril explorer`](https://mithril.network/explorer).
:::

### Verify your signer is registered

After installing the Mithril signer, you can verify that your node is registered.

First, download the script into the desired directory:

```bash
wget https://mithril.network/doc/scripts/verify_signer_registration.sh
```

Make the script executable:

```bash
chmod +x verify_signer_registration.sh
```

Finally, execute the script:

```bash
PARTY_ID=**YOUR_PARTY_ID** AGGREGATOR_ENDPOINT=**YOUR_AGGREGATOR_ENDPOINT** ./verify_signer_registration.sh
```

:::tip

Here is an example command:

```bash
PARTY_ID=pool1hp72sauk0g0yqm4dzllz0pz6j93gewhllkzphn4hykkfmne43y AGGREGATOR_ENDPOINT=https://aggregator.release-preprod.api.mithril.network/aggregator ./verify_signer_registration.sh
```

:::

If your signer is registered, you should see this message:

```bash
>> Congrats, your signer node is registered!
```

Otherwise, you should see this error message:

```bash
>> Oops, your signer node is not registered. Party ID not found among the signers registered at epoch 430.
```

### Verify your signer contributes with individual signatures

After waiting for two epochs, you will be able to verify that your signer is contributing with individual signatures.

First, download the script into the desired directory:

```bash
wget https://mithril.network/doc/scripts/verify_signer_signature.sh
```

Make the script executable:

```bash
chmod +x verify_signer_signature.sh
```

Finally, execute the script:

```bash
PARTY_ID=**YOUR_PARTY_ID** AGGREGATOR_ENDPOINT=**YOUR_AGGREGATOR_ENDPOINT** ./verify_signer_signature.sh
```

:::tip

Here is an example of the aforementioned command created with the example set for `release-preprod`:

```bash
PARTY_ID=pool1hp72sauk0g0yqm4dzllz0pz6j93gewhllkzphn4hykkfmne43y AGGREGATOR_ENDPOINT=https://aggregator.release-preprod.api.mithril.network/aggregator ./verify_signer_signature.sh
```

:::

If your signer is contributing, you should see this message:

```bash
>> Congrats, you have signed this certificate: https://aggregator.release-preprod.api.mithril.network/aggregator/certificate/el3p289b03a223244285b2ls10839846ae7a69f1e8362824a383f376f93f723f !
```

Otherwise, you should see this error message:

```bash
>> Oops, your party id was not found in the last 20 certificates. Please try again later.
```
