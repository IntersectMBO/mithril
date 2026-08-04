---
title: Certification of Cardano node database v2
authors:
  - name: Mithril Team
tags: [certification, cardano node database v2]
---

### Certification of Cardano node database v2

:::info[Update 2025/05/14]

We have activated the **Cardano node database v2 certification** on the `release-mainnet` network.

:::

:::info[Update 2025/04/25]

We have activated the **Cardano node database v2 certification** on the `release-preprod` network.

:::

With the release of the new distribution [2513](https://github.com/input-output-hk/mithril/releases/tag/2513.0), we have started to roll out the certification of the [**Cardano node database v2**](https://mithril.network/doc/mithril/advanced/mithril-certification/cardano-node-database-v2/) in the Mithril networks.

Initially, Mithril certified entire database snapshots, requiring clients to download and verify the full database to bootstrap a Cardano node. The Mithril network now provides incremental certification of the Cardano node database, allowing clients to download only the specific range of immutable files needed, accelerating the process of bootstrapping a Cardano node. The key features include:

- Certification of the Cardano node database v2 every time a new immutable file is produced
- New HTTP routes in the aggregator REST API to access this certified data
- Updates to the Mithril client library and CLI for retrieving and verifying Cardano node database v2 (will be made stable one distribution after the activation in `release-mainet`)
- Mithril Explorer now displays certified Cardano node database v2.

The roll-out plan of the feature is the following:

- [x] Distribution [2513](https://github.com/input-output-hk/mithril/releases/tag/2513.0):
  - [x] Activation of the certification of **Cardano node database v2** in the `pre-release-preview` network
  - [x] Activation of the certification of **Cardano node database v2** in the `release-preprod` network
- [x] Distribution [2517](https://github.com/input-output-hk/mithril/releases/tag/2517.1):
  - [x] Activation of the certification of **Cardano node database v2** in the `release-mainnet` network.

For any inquiries or assistance, don't hesitate to contact the team on the [Discord channel](https://discord.gg/5kaErDKDRq).
