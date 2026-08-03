---
title: One line installer for Mithril binaries
authors:
  - name: Mithril Team
tags:
  [
    binaries,
    pre-built,
    install,
    update,
    nodes,
    command-line,
    binaries,
    installer,
  ]
---

### One line installer for Mithril binaries

To simplify the installation and updating of Mithril binaries, we have created a one line installer that downloads and installs the Mithril binaries for you. This installer is available for Linux and macOS and supports the Mithril signer, Mithril aggregator, and Mithril client CLI.

The one line command is also displayed in the various `Download the pre-built binary` sections across the documentation.

#### Examples of the one line installer

- Download the **latest Mithril signer** in the current directory:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/input-output-hk/mithril/refs/heads/main/mithril-install.sh | sh -s -- -c mithril-signer -d latest -p "$(pwd)"
```

- Download the **latest Mithril client CLI** in the current directory:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/input-output-hk/mithril/refs/heads/main/mithril-install.sh | sh -s -- -c mithril-client -d latest -p "$(pwd)"
```

- Download the **unstable Mithril aggregator** in the current directory:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/input-output-hk/mithril/refs/heads/main/mithril-install.sh | sh -s -- -c mithril-aggregator -d unstable -p "$(pwd)"
```

- Download the **Mithril client of distribution `2445.0`** in the current directory:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/input-output-hk/mithril/refs/heads/main/mithril-install.sh | sh -s -- -c mithril-client -d 2445.0 -p "$(pwd)"
```

#### Installer usage

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/input-output-hk/mithril/refs/heads/main/mithril-install.sh | sh -s -- -h

Install or upgrade a Mithril node
Usage: sh [-n node] [-v version] [-d distribution] [-p path]
  -c node          : Mithril node to install or upgrade (mithril-signer, mithril-aggregator, mithril-client)
  -d distribution  : Distribution to upgrade to (latest, unstable or distribution version e.g '2445.0')
  -p path          : Path to install the component

```

For any inquiries or assistance, feel free to contact the team on the [Discord channel](https://discord.gg/5kaErDKDRq).
