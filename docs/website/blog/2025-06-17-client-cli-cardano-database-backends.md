---
title: Switching to Cardano database incremental certification
authors:
  - name: Mithril Team
tags:
  [
    mithril client,
    library,
    cli,
    Cardano database,
    Cardano database v2,
    certification,
    backend,
  ]
---

### Switching to Cardano database incremental certification

:::info[Update 2026/08/03]

The `v1` backend of the Cardano database has been **removed**. The `v2` backend is now the **only supported** backend for the Cardano database certification in the Mithril client CLI and library.

:::

A new incremental certification process has been introduced for the **Cardano node internal database**. This enhancement is part of ongoing efforts to improve the Mithril protocol and optimize Cardano node bootstrapping.

More information about the Cardano database certification is available at:

- [Cardano node database](https://mithril.network/doc/mithril/advanced/mithril-certification/cardano-node-database)
- [Cardano node database v2](https://mithril.network/doc/mithril/advanced/mithril-certification/cardano-node-database-v2).

The Cardano node database v2 certification offers incremental verification and greater efficiency compared to the original method. It will progressively replace the current certification process for the Cardano node internal database.

To facilitate this transition, updates have been made to both the **Mithril client CLI** and the **Mithril client library**. These changes are designed to support the new incremental certification process and ensure a smooth user experience.

In particular, the `cardano-db` command in the Mithril client CLI has been updated to support the new incremental certification process and eventually a seamless switch to the new backend. A new `--backend` option has been added to the command, allowing users to specify the certification version:

- `--backend v1` uses the original Cardano node database certification (this remains the default)
- `--backend v2` enables the new incremental Cardano node database certification.

To support this transition, both certification versions will remain available during the migration period, allowing users to adapt at their own pace.

- [x] **Distribution [2524](https://github.com/input-output-hk/mithril/releases/tag/2524.0)**:
  - Introduced the `--backend` parameter in the `cardano-db` command
  - The default backend is `v1`; the `v2` backend is still considered **unstable**
  - No breaking changes in the client CLI
  - The `v2` backend is accessible via the `cardano_database_v2` function in the client library.

- [x] **Distribution [2537](https://github.com/input-output-hk/mithril/releases/tag/2537.0)**:
  - The `v2` backend is promoted to **stable** status but will remain optional
  - The `v1` backend is still the default.

- [x] **Distribution [2543](https://github.com/input-output-hk/mithril/releases/tag/2543.0)**:
  - The `v2` backend is the default

- [x] **Distribution [2603](https://github.com/input-output-hk/mithril/releases/tag/2603.1)**:
  - The `v1` backend is deprecated.

- [x] **Distribution [2617](https://github.com/input-output-hk/mithril/releases/tag/2617.0)**:
  - The `v1` backend is decommissioned and removed from the client CLI and library.

- [x] **Distribution [2630](https://github.com/input-output-hk/mithril/releases/tag/2630.0)**:
  - The `v1` backend will be fully removed from the signer and aggregator.

If you have any questions or need assistance, contact the team on the [Discord channel](https://discord.gg/5kaErDKDRq).
