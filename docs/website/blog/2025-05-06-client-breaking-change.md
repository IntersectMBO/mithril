---
title: Breaking changes in client library and CLI
authors:
  - name: Mithril Team
tags:
  [mithril client, library, cli, breaking-change, Cardano database, ancillary]
---

### Breaking changes in client library and CLI

The [`2517`](https://github.com/input-output-hk/mithril/releases/tag/2517.1) release introduces breaking changes to the **Mithril client CLI** and **library**.

#### Client CLI

The command for downloading a certified Cardano database using the **Mithril client CLI** has been updated starting from version `0.12.1`:

- The existing command remains functional but no longer downloads ancillary files (ledger state snapshot and last immutable file) by default. As a result, the fast bootstrap feature is disabled, requiring the Cardano node to compute the ledger state from the genesis block during startup:

```bash
mithril-client cardano-database download latest
```

- To include ancillary files and enable fast bootstrap, use the new command with the `--include-ancillary` option:

```bash
mithril-client cardano-database download latest --include-ancillary --ancillary-verification-key <ANCILLARY_VERIFICATION_KEY>
```

:::info

The new command requires an **ancillary verification key**. This key can be provided via the `--ancillary-verification-key` option or the `ANCILLARY_VERIFICATION_KEY` environment variable. Details are available on the [Networks configuration](https://mithril.network/doc/next/manual/getting-started/network-configurations) page.

:::

To update the Mithril client CLI, use the following one-line command. By default, it downloads to the current directory. To specify a custom folder, use the `-p` option:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/input-output-hk/mithril/refs/heads/main/mithril-install.sh | sh -s -- -c mithril-client -d 2517.1 -p "$(pwd)"
```

For more details, refer to the [Mithril client node](https://mithril.network/doc/manual/develop/nodes/mithril-client) documentation.

#### Client Library

The **Mithril client library** has also been updated. By default, it no longer downloads ancillary files (ledger state snapshot and last immutable file), which disables the fast bootstrap feature. Consequently, the Cardano node must compute the ledger state from the genesis block during startup.

To enable fast bootstrap, use the `download_unpack_full` function instead of `download_unpack` and provide the `set_ancillary_verification_key` parameter:

- Set the ancillary verification key using the `set_ancillary_verification_key` method when building the client:

```rust
let client = ClientBuilder::aggregator(AGGREGATOR_ENDPOINT, GENESIS_VERIFICATION_KEY)
    .set_ancillary_verification_key(ANCILLARY_VERIFICATION_KEY.to_string()) // Added line
    .with_origin_tag(Some("EXAMPLE".to_string()))
    .build()?;
```

:::info

The **ancillary verification key** for the Mithril networks are available on the [Networks configuration](https://mithril.network/doc/next/manual/getting-started/network-configurations) page.

:::

- Use the `download_unpack_full` function to download ancillary files:

```rust
client
    .cardano_database()
    .download_unpack_full(&snapshot, target_directory)
    .await?;
```

For more information and a complete example, refer to the [Mithril client library](https://mithril.network/doc/manual/develop/nodes/mithril-client-library#cardano-database) documentation.

If you have any questions or need assistance, contact the team on the [Discord channel](https://discord.gg/5kaErDKDRq).
