---
sidebar_position: 3
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

import CompiledBinaries from '../../../compiled-binaries.mdx'

# Mithril setup node

:::info

🚧 **Work in progress** 🚧
Mithril setup help user to configure a Mithril environement (Signer, DMQ, ...)

:::

## Resources

|       Node        |                                   Source repository                                    | Rust documentation | Docker packages |
| :---------------: | :------------------------------------------------------------------------------------: | :----------------: | :-------------: |
| **Mithril setup** | [:arrow_upper_right:](https://github.com/IntersectMBO/mithril/tree/main/mithril-setup) |         -          |        -        |

## Prerequisites

<Tabs groupId="system" queryString>
<TabItem value="linux-mac" label="Linux / Mac">
TODO

</TabItem>
</Tabs>

## Download the source file

Download the source file from GitHub (HTTPS):

```bash
git clone https://github.com/IntersectMBO/mithril.git
```

Or (SSH):

```bash
git clone git@github.com:IntersectMBO/mithril.git
```

Switch to the desired branch/tag:

```bash
# Replace **YOUR_BUILD_BRANCH_OR_TAG** with the appropriate branch or tag name
# Please refer to the [**Network configurations**](http://mithril.network/manual/getting-started/network-configurations) section of the user manual
git checkout **YOUR_BUILD_BRANCH_OR_TAG**
```

Change the directory:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  cd mithril/mithril-setup
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  cd mithril\mithril-setup
  ```
  </TabItem>
</Tabs>

## Development testing and building

Run tests:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  make test
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  cargo test
  ```
  </TabItem>
</Tabs>

Create the help menu:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  make help
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  cargo run -- -h
  ```
  </TabItem>
</Tabs>

Generate the Rust documentation:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  make doc
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  cargo doc --no-deps --open
  ```
  </TabItem>
</Tabs>

Run in debug mode with the default configuration:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  make debug
  ```
  </TabItem>
  <TabItem value="windows" label="Windows">
  ```powershell
  cargo run
  ```
  </TabItem>
</Tabs>

## Building for release and running the binary

Build and run in release mode with the default configuration:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  make run
  ```
  </TabItem>
</Tabs>

Or, build only in release mode:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  make build
  ```
  </TabItem>
</Tabs>

Display the help menu:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  ./mithril-setup --help
  ```
  </TabItem>
</Tabs>

You should see:

```bash
This program shows, downloads and verifies certified blockchain artifacts.

Usage: mithril-setup [OPTIONS] <COMMAND>

Commands:
  signer                      Mithril signer installation command
  help                        Print this message or the help of the given subcommand(s)

Options:
      --run-mode <RUN_MODE>
          Run Mode

          [env: RUN_MODE=]
          [default: dev]

  -v, --verbose...
          Verbosity level (-v=warning, -vv=info, -vvv=debug, -vvvv=trace)

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

Run in release mode with the default configuration:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  ./mithril-setup
  ```
  </TabItem>
</Tabs>

Run in release mode with a specific mode:

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  ```bash
  ./mithril-setup --run-mode preview
  ```
  </TabItem>
</Tabs>

:::tip

If you wish to delve deeper and access several levels of logs from the Mithril setup, use the following:

- Add `-v` for some logs (WARN)
- Add `-vv` for more logs (INFO)
- Add `-vvv` for even more logs (DEBUG)
- Add `-vvvv` for all logs (TRACE).

:::

## Download the pre-built binary

<Tabs groupId="system" queryString>
  <TabItem value="linux-mac" label="Linux / Mac">
  <CompiledBinaries  node="mithril-setup"/>
  </TabItem>
  <TabItem value="windows" label="Windows">
  :::info
  Each distribution (pre-)release comes with pre-compiled binaries ready to use.
  You can download them from the distribution (pre-)release distribution page on GitHub that depends on the Mithril network you
  are targeting.
  :::
  </TabItem>
</Tabs>
