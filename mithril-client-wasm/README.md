# Mithril-client-wasm [![CI workflow](https://github.com/IntersectMBO/mithril/actions/workflows/ci.yml/badge.svg)](https://github.com/IntersectMBO/mithril/actions/workflows/ci.yml) [![cnpm](https://img.shields.io/npm/v/@mithril-dev/mithril-client-wasm.svg)](https://www.npmjs.com/package/@mithril-dev/mithril-client-wasm) [![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](https://github.com/IntersectMBO/mithril/blob/main/LICENSE) [![Discord](https://img.shields.io/discord/500028886025895936.svg?logo=discord&style=flat-square)](https://discord.gg/5kaErDKDRq)

**This is a work in progress** 🛠

- `mithril-client-wasm` defines all the tooling necessary to manipulate Mithril certified types available from a Mithril aggregator from a WASM compatible browser.

- The different types of available data certified by Mithril are:
  - Cardano transactions: list & get snapshots, get proofs.
  - Cardano stake distribution: list, get and get by epoch.
  - Cardano database: list and get.
  - Mithril stake distribution: list and get.
  - Certificate: list, get, and chain validation.

## Installation

- Install a correctly configured Rust toolchain (latest stable version). You can follow the instructions provided [here](https://www.rust-lang.org/learn/get-started).

- Install the WASM target:

```bash
rustup target add wasm32-unknown-unknown
```

- Install Rust WASM Pack:

```bash
cargo install wasm-pack
```

- Install **clang**:

```bash
sudo apt install clang
```

- Install `nodejs` version `22.15+`

```bash
sudo apt install nodejs
```

- Install `npm` version `10.9+`

```bash
sudo apt install npm
```

> [!WARNING]
> If you have troubles building the `BLST` library, you will need to:
>
> - Install [`Emscripten`](https://emscripten.org/docs/getting_started/downloads.html)
> - For macOS users, consider reading this [guide](https://github.com/emscripten-core/emscripten/issues/5696) to activate the `emcc` command
> - Use these environment variables to use this compiler (or prefix all following commands with them):
>
> ```bash
> export CC=emcc
> export AR=emar
> ```
>
> - Install the WASM `emscripten` target:
>
> ```bash
> rustup target add wasm32-unknown-emscripten
> ```

## Build Mithril client library in WASM

Go to the `mithril-client-wasm` directory:

```bash
cd mithril-client-wasm
```

Then you can build the WASM library:

```bash
make build
```

## Run the Mithril client library in the browser

You will need to run the Mithril client library in a compatible browser:

| Browser                 | Minimum version |  Released  |    Tested in CI    |
| ----------------------- | :-------------: | :--------: | :----------------: |
| **Chrome**              |      `54`       | 2016-10-12 | :heavy_check_mark: |
| **Edge**                |      `79`       | 2020-01-15 |         -          |
| **Firefox**             |      `38`       | 2015-05-12 | :heavy_check_mark: |
| **Opera**               |      `41`       | 2016-10-25 |         -          |
| **Safari**              |     `15.4`      | 2022-03-14 |         -          |
| **Chrome Android**      |      `54`       | 2016-10-19 |         -          |
| **Firefox for Android** |      `38`       | 2015-05-12 |         -          |
| **Opera Android**       |      `41`       | 2016-10-25 |         -          |
| **Safari on iOS**       |     `15.4`      | 2022-03-14 |         -          |
| **Node.js**             |    `18.0.0`     | 2022-04-19 | :heavy_check_mark: |

Go to the `mithril-client-wasm` directory:

```bash
cd mithril-client-wasm
```

Install the library:

```bash
make www-install
```

Then you can serve the Mithril client library in the browser:

```bash
make www-serve
```

Finally, open [http://localhost:8080](http://localhost:8080) with your browser. (port 8080 is the default port)
