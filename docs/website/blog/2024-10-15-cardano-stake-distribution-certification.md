---
title: Certification of Cardano stake distribution
authors:
  - name: Mithril Team
tags: [certification, cardano stake distribution]
---

### Certification of Cardano stake distribution

:::info[Update 2025/01/13]

We have activated the **Cardano stake distribution certification** on the `release-mainnet` network.

:::

:::info[Update 2024/10/21]

We have released stable support for the **Cardano stake distribution certification** with distributions [2437](https://github.com/input-output-hk/mithril/releases/tag/2437.1) and [2442](https://github.com/input-output-hk/mithril/releases/tag/2442.0).

A threshold of at least **95%** of the stake running version `0.2.182` (within **10** days after the distribution `2442` is released) is mandatory to activate the certification of the Cardano stake distribution on the `release-mainnet` network.

The [Mithril Protocol Insights](https://lookerstudio.google.com/s/mbL23-8gibI) dashboard displays the adoption rate of the different signer versions on the `release-mainnet` network.

:::

With the release of the new distribution [2437](https://github.com/input-output-hk/mithril/releases/tag/2437.1), we have started to roll out the certification of the **Cardano stake distribution** in the Mithril networks.

The Mithril network now provides certified Cardano stake distribution data without requiring a full Cardano node, a useful feature for applications such as bridges and layer 2 solutions. The key features include:

- Certification of the Cardano stake distribution of the ending epoch at each epoch transition
- New HTTP routes in the aggregator REST API to access this certified data
- Updates to the Mithril client library and CLI for retrieving and verifying Cardano stake distribution
- WASM client support for these functionalities
- Mithril Explorer now displays certified Cardano stake distribution.

The roll-out plan of the feature is the following:

- [x] Distribution [2437](https://github.com/input-output-hk/mithril/releases/tag/2437.1):
  - [x] Activation of the certification of **Cardano stake distribution** in the `pre-release-preview` network
  - [x] Activation of the certification of **Cardano stake distribution** in the `release-preprod` network
- [x] Distribution [2442](https://github.com/input-output-hk/mithril/releases/tag/2442.0):
  - [x] Activation of the certification of **Cardano stake distribution** in the `release-mainnet` network.

For any inquiries or assistance, don't hesitate to contact the team on the [Discord channel](https://discord.gg/5kaErDKDRq).
