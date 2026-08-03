# IPFS private devnet

This directory provides scripts to initialize, manage, and observe a local private IPFS network made of Kubo nodes.

The main entry point is:

```shell
./ipfs-devnet.sh <COMMAND> [OPTIONS]
```

It wraps the generated swarm scripts and provides a single interface for:

- initializing a private Kubo swarm;
- starting all nodes;
- stopping all nodes;
- tailing node logs.

## Requirements

The devnet scripts require a Unix-like environment and the following tools:

- `bash`
- `curl`
- `awk`
- `shasum`
- `tar`

Supported platforms for the Kubo download helper are:

- Linux `amd64` and `arm64`
- macOS `amd64` and `arm64`

## Quick start

Browse to the IPFS devnet from the Mithril root directory:

```shell
cd mithril-test-lab/ipfs-devnet
```

Initialize a private swarm with five nodes:

```shell
./ipfs-devnet.sh init --swarm-dir ./swarm --number 5
```

Start the swarm:

```shell
./ipfs-devnet.sh start --swarm-dir ./swarm
```

Display the latest logs from each node:

```shell
./ipfs-devnet.sh log --swarm-dir ./swarm
```

Stop the swarm:

```shell
./ipfs-devnet.sh stop --swarm-dir ./swarm
```

> [!TIP]
> You can set an environment variable `SWARM_DIR` to avoid passing the `--swarm-dir` option for all commands.
>
> ```shell
> export SWARM_DIR=./swarm
>
> ./ipfs-devnet.sh init --number 5
> ./ipfs-devnet.sh start
> ./ipfs-devnet.sh log
> ./ipfs-devnet.sh stop
> ```
>
> All other parameters have equivalent environment variables; check the script help messages for more information.

## Commands

Available commands:

| Command | Description                                                 |
| ------- | ----------------------------------------------------------- |
| `init`  | Download Kubo, configure nodes, and generate swarm scripts. |
| `start` | Start all configured nodes.                                 |
| `stop`  | Stop all configured nodes.                                  |
| `log`   | Display recent logs for each node.                          |

### `init`

Downloads Kubo, configures the private network, and generates management scripts in the swarm directory.

```shell
./ipfs-devnet.sh init [OPTIONS]
```

Options:

| Option                     | Environment variable | Description                                                                                       | Default        |
| -------------------------- | -------------------- | ------------------------------------------------------------------------------------------------- | -------------- |
| `-s, --swarm-dir <dir>`    | `SWARM_DIR`          | **[Required]** Directory that will contain the swarm nodes.                                       | -              |
| `-n, --number <int>`       | `NUMBER_OF_NODES`    | Number of Kubo nodes to configure. Must be at least 2.                                            | `2`            |
| `-d, --download-dir <dir>` | `DOWNLOAD_DIR`       | Directory where the Kubo archive is downloaded.                                                   | `/tmp/kubo/`   |
| `-v, --version <version>`  | `KUBO_VERSION`       | Kubo version to download, for example `v0.42.0`. If omitted, the latest released version is used. | Latest release |
| `-o, --overwrite`          | `OVERWRITE`          | Replace an existing swarm configuration.                                                          | `false`        |
| `-h, --help`               | -                    | Print command help.                                                                               | -              |

> [!NOTE]
> Command-line options take priority over environment variables.

Example:

```shell
./ipfs-devnet.sh init --swarm-dir ./swarm --number 5 --version v0.42.0
```

The initialization creates:

```text
swarm/
├── bin/
│   └── ipfs
├── kubo-node-1/
├── kubo-node-2/
├── ...
├── kubo-node-5/
├── start.sh
├── stop.sh
└── log.sh
```

Each node is initialized with its own IPFS repository and a shared private swarm key.
The nodes are configured to peer with each other locally.

For node `N`, the default local ports are:

| Service | Port formula | Example for node 1 |
| ------- | ------------ | ------------------ |
| Swarm   | `4000 + N`   | `4001`             |
| API     | `5000 + N`   | `5001`             |
| Gateway | `8080 + N`   | `8081`             |

#### Re-initialize an existing swarm

If the target swarm directory already contains node configurations, use `--overwrite`:

```shell
./ipfs-devnet.sh init --swarm-dir ./swarm --number 5 --overwrite
```

Or with the environment variable:

```shell
OVERWRITE=1 ./ipfs-devnet.sh init --swarm-dir ./swarm --number 5
```

> [!NOTE]
> `OVERWRITE=0` and `OVERWRITE=false` are treated as disabled.

### `start`

Start all configured Kubo nodes:

```shell
./ipfs-devnet.sh start [OPTIONS] [-- [FORWARDED_OPTIONS]]
```

Options:

| Option                  | Environment variable | Description                                             | Default |
| ----------------------- | -------------------- | ------------------------------------------------------- | ------- |
| `-s, --swarm-dir <dir>` | `SWARM_DIR`          | **[Required]** Directory that contains the swarm nodes. | -       |
| `-h, --help`            | -                    | Print command help.                                     | -       |

Options forwardable to the generated `start.sh` (after `--`):

| Option                | Environment variable | Description                                        | Default |
| --------------------- | -------------------- | -------------------------------------------------- | ------- |
| `--log-level <level>` | -                    | Kubo log level (`debug`, `info`, `warn`, `error`). | `info`  |
| `-h, --help`          | -                    | Print command help.                                | -       |

> [!NOTE]
> Command-line options take priority over environment variables.

Main usage:

```shell
./ipfs-devnet.sh start --swarm-dir ./swarm
```

Changing the log level:

```shell
./ipfs-devnet.sh start --swarm-dir ./swarm -- --log-level debug
```

> [!NOTE]
> When started, each node writes:
>
> - its process id to `kubo-node-N/ipfs.pid`;
> - its daemon logs to `kubo-node-N/ipfs.log`.

> [!IMPORTANT]
> Starting an already running swarm is safe: nodes with a valid running PID are skipped.

### `stop`

Stop all configured Kubo nodes:

```shell
./ipfs-devnet.sh stop [OPTIONS]
```

Options:

| Option                  | Environment variable | Description                                             | Default |
| ----------------------- | -------------------- | ------------------------------------------------------- | ------- |
| `-s, --swarm-dir <dir>` | `SWARM_DIR`          | **[Required]** Directory that contains the swarm nodes. | -       |
| `-h, --help`            | -                    | Print command help.                                     | -       |

> [!NOTE]
> Command-line options take priority over environment variables.

Main usage:

```shell
./ipfs-devnet.sh stop --swarm-dir ./swarm
```

The stop command reads each node’s `ipfs.pid` file and sends a termination signal to the corresponding process.

If a PID file is missing, invalid, or points to a process that no longer exists, the script reports it and
continues with the other nodes.

### `log`

Display the last `n` lines from each node’s log:

```shell
./ipfs-devnet.sh log [OPTIONS] [-- [FORWARDED_OPTIONS]]
```

Options:

| Option                  | Environment variable | Description                                             | Default |
| ----------------------- | -------------------- | ------------------------------------------------------- | ------- |
| `-s, --swarm-dir <dir>` | `SWARM_DIR`          | **[Required]** Directory that contains the swarm nodes. | -       |
| `-h, --help`            | -                    | Print command help.                                     | -       |

Options forwardable to the generated `log.sh` (after `--`):

| Option                     | Environment variable | Description                                      | Default   |
| -------------------------- | -------------------- | ------------------------------------------------ | --------- |
| `-l, --lines <int>`        | `TAIL_LINES`         | Number of lines to tail from each node log file. | `10`      |
| `-s, --separator <string>` | `SEPARATOR`          | Separator printed between log files.             | 70 dashes |
| `-h, --help`               | -                    | Print command help.                              | -         |

Main usage:

```shell
./ipfs-devnet.sh log --swarm-dir ./swarm
```

Output example for a swarm of two nodes (truncated):

```shell
----------------------------------------------------------------------
tail -n 10 swarm/kubo-node-1/ipfs.log
----------------------------------------------------------------------
2026-08-03T13:43:35.620+0200    INFO    p2p-config      fxevent/slog.go:75      OnStop hook executed  {"system": "fx", "callee": "github.com/libp2p/go-libp2p/config.(*Config).addAutoNAT.func3.1()", "caller": "github.com/libp2p/go-libp2p/config.(*Config).addAutoNAT.func3", "runtime": "3.193µs"}
2026-08-03T13:43:35.620+0200    INFO    p2p-config      fxevent/slog.go:75      OnStop hook executed  {"system": "fx", "callee": "github.com/libp2p/go-libp2p/config.(*Config).makeAutoNATV2Host.func1.1()", "caller": "github.com/libp2p/go-libp2p/config.(*Config).makeAutoNATV2Host.func1", "runtime": "3.402µs"}
2026-08-03T13:43:35.632+0200    INFO    core/server     corehttp/corehttp.go:136        server at /ip4/127.0.0.1/tcp/5001 terminating...
----------------------------------------------------------------------

----------------------------------------------------------------------
tail -n 10 swarm/kubo-node-2/ipfs.log
----------------------------------------------------------------------
2026-08-03T13:43:35.626+0200    INFO    p2p-config      fxevent/slog.go:75      OnStop hook executed  {"system": "fx", "callee": "github.com/libp2p/go-libp2p/config.(*Config).makeAutoNATV2Host.func1.1()", "caller": "github.com/libp2p/go-libp2p/config.(*Config).makeAutoNATV2Host.func1", "runtime": "7.149µs"}
2026-08-03T13:43:35.626+0200    INFO    p2p-config      fxevent/slog.go:75      OnStop hook executed  {"system": "fx", "callee": "github.com/libp2p/go-libp2p/config.(*Config).addAutoNAT.func3.1()", "caller": "github.com/libp2p/go-libp2p/config.(*Config).addAutoNAT.func3", "runtime": "3.989µs"}
2026-08-03T13:43:35.639+0200    INFO    core/server     corehttp/corehttp.go:136        server at /ip4/127.0.0.1/tcp/5002 terminating...
----------------------------------------------------------------------
```

Display more lines:

```shell
./ipfs-devnet.sh log --swarm-dir ./swarm -- --lines 50
```

Customize the separator:

```shell
./ipfs-devnet.sh log --swarm-dir ./swarm \
    -- --lines 50 --separator "=================================================="
```

Example with environment variables:

```shell
TAIL_LINES=20 ./ipfs-devnet.sh log --swarm-dir ./swarm
```

## Troubleshooting

### Some Kubo nodes are still running after `stop`

The `stop` command uses the PID files stored in each `kubo-node-N` directory.
If a node remains alive after stopping the swarm, first retry:

```shell
./ipfs-devnet.sh stop --swarm-dir ./swarm
```

If the process is still running, identify the remaining Kubo processes before killing them manually:

```shell
ps aux | grep '[i]pfs'
```

Then stop only the processes that belong to this devnet.

As a last resort, if you are sure no other local IPFS/Kubo node is running, you can terminate all `ipfs` processes:

```shell
killall ipfs
```
