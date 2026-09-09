# Mithril End To End Tests Suite

- Integration test suite handling Mithril signature, certificate generation and snapshot verification process.

---

## Pre-requisites

**Install Rust**

- Install a [correctly configured](https://www.rust-lang.org/learn/get-started) Rust toolchain (latest stable version).

- Install Rust [Clippy](https://github.com/rust-lang/rust-clippy) component.

- Install Build Tools `build-essential` and `m4`. For example, on Ubuntu/Debian/Mint, run `sudo apt install build-essential m4`.

## Download source code

```bash
# Download sources from github
git clone https://github.com/IntersectMBO/mithril

# Build nodes
make -C mithril-aggregator build
make -C mithril-signer build
make -C mithril-client-cli build
make -C mithril-relay build

# Go to sources directory
cd mithril-test-lab/mithril-end-to-end
```

## Build and run the test suite

```bash
# Build
make build

# Help
./mithril-end-to-end --help

# Run
./mithril-end-to-end -vvv --work-directory db/ --bin-directory ../../target/release --devnet-scripts-directory=../cardano-devnet
```

To run `mithril-end-to-end` command, you must first compile the Mithril nodes:

```bash
cargo build --release
```

## Additional network topology options

These options can be combined with the base run command shown above (see `./mithril-end-to-end --help` for the full
list of flags).

### Multiple aggregators

Run several aggregators behind Mithril relays with `--number-of-aggregators` (requires `--use-relays` as soon as more
than one aggregator is used):

```bash
./mithril-end-to-end -vvv --work-directory db/ --bin-directory ../../target/release --devnet-scripts-directory=../cardano-devnet --number-of-aggregators 3 --use-relays
```

### DMQ

Use the DMQ protocol to broadcast signatures with `--use-dmq`:

```bash
./mithril-end-to-end -vvv --work-directory db/ --bin-directory ../../target/release --devnet-scripts-directory=../cardano-devnet --use-dmq
```

By default, this uses the Haskell DMQ node created within the `cardano-devnet`. Use `--dmq-node-flavor fake` instead to
use a fake DMQ network created by the Mithril relay.

### IPFS

Enable upload/download of Cardano DB snapshots through IPFS with `--use-ipfs`:

```bash
./mithril-end-to-end -vvv --work-directory db/ --bin-directory ../../target/release --devnet-scripts-directory=../cardano-devnet --use-ipfs
```

By default, a fresh IPFS devnet is spawned in the working directory and stopped at the end of the run. To attach to an
already-running IPFS devnet instead (started and left running independently of the test run), use `--ipfs-devnet-to-attach <path>`.
The target swarm must have at least one node per aggregator, plus one for the client.

### Note for MacOS users

#### `sed` compatibility

Mithril end to end test uses `sed` command which is not compatible with MacOS.

To deal easily with this issue, you can install `gnu-sed` and use it as `sed`.

Here is an example of the installation of `gnu-sed` with Homebrew:

```bash
brew install gnu-sed
```

The shell output should display the instruction below, that you must follow:

```bash
GNU "sed" has been installed as "gsed".
If you need to use it as "sed", you can add a "gnubin" directory
to your PATH from your bashrc like:

     PATH="$HOMEBREW_PREFIX/opt/gnu-sed/libexec/gnubin:$PATH"
```

Once saved, you need to reload your shell profile. Execute source $HOME/.bashrc or source $HOME/.zshrc (depending on the shell application you use).

#### Troubleshoot Cardano node timeout errors on macOS

Sometimes, the default parameter values used to run the end to end test may not be suitable for macOS environments, causing the following error:

```bash
>>>> Timeout: node-pool1 has not enough immutable files within 100 attempts
```

The default value of the **Cardano slot length** parameter can prevent the Cardano nodes to work properly in the `devnet`. Increasing the value helps improve the stability: you can add `--cardano-slot-length 0.25` to the run command:

```bash
./mithril-end-to-end -vvv --work-directory db/ --bin-directory ../../target/release --devnet-scripts-directory=../cardano-devnet --cardano-slot-length 0.25
```

### Use your own cardano binaries

You can use your own compiled cardano binaries to run the end to end test:

- Build the **cardano-node** and **cardano-cli** binaries following the documentation on the [Cardano Developer Portal](https://developers.cardano.org/docs/get-started/installing-cardano-node#macos).

- From the root of the repository, copy the `cardano-node` and `cardano-cli` binaries in the `devnet/bin` directory:

```bash
cp $HOME/.local/bin/cardano-node mithril-test-lab/cardano-devnet/bin/cardano-node
cp $HOME/.local/bin/cardano-cli mithril-test-lab/cardano-devnet/bin/cardano-cli
```

- Use the `--skip-cardano-bin-download` option to run the end to end test:

```bash
./mithril-end-to-end -vvv --db-directory db/ --bin-directory ../../target/release --skip-cardano-bin-download
```

## Build and run an aggregator stress test

```bash
# Build
make build

# Help
./load-aggregator --help

# Run with 100 signers and 0 clients
./load-aggregator -vvv --cardano-cli-path script/mock-cardano-cli --aggregator-dir ../../target/release --num-signers=100

# Run with 100 signers and 200 clients
./load-aggregator -vvv --cardano-cli-path script/mock-cardano-cli --aggregator-dir ../../target/release --num-signers=100 --num-clients=200
```

## Benchmark aggregator performances

```bash
# Build the load aggregator tool
make build

# Run a benchmark for [10, 20, 30 40, 50] signers x [100, 200, 300] clients
MIN_SIGNERS=10 MAX_SIGNERS=50 STEP_SIGNERS=10 MIN_CLIENTS=100 MAX_CLIENTS=300 STEP_CLIENTS=100 ./benchmark-aggregator.sh
```

## Launch a monitor

```bash
# Run monitor
make monitor
```

You will have acces to the following dashboards:

| Dashboard      | URL                                                   | Credentials     |
| -------------- | ----------------------------------------------------- | --------------- |
| **Grafana**    | [http://0.0.0.0:3000](http://0.0.0.0:3000/dashboards) | mithril/mithril |
| **Prometheus** | [http://0.0.0.0:9090](http://0.0.0.0:9090/)           | -               |
