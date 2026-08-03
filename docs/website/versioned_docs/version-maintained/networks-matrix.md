---
unlisted: true
hide_title: true
hide_table_of_contents: true
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

Here is an updated list of all **Mithril networks**, including their configurations and current statuses:

> Last update: 06/08/2026

<Tabs>
  <TabItem value="mainnet" label="Mainnet" default>

## `release-mainnet`

| Information                     | -                                                                                                                                                                                                                                                                      |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Mithril network**             | `release-mainnet`                                                                                                                                                                                                                                                      |
| **Cardano network**             | `mainnet`                                                                                                                                                                                                                                                              |
| **Cardano magic Id**            | `-`                                                                                                                                                                                                                                                                    |
| **Cardano node versions**       | `10.7`, `11.0`                                                                                                                                                                                                                                                         |
| **Mithril status**              | Stable (signer) 🟢 / Beta (aggregator/client) 🟢                                                                                                                                                                                                                       |
| **DMQ magic Id**                | `2912307721`                                                                                                                                                                                                                                                           |
| **DMQ node versions**           | `0.6.0.0`                                                                                                                                                                                                                                                              |
| **DMQ bootstrap peers**         | `35.233.75.24:6161`                                                                                                                                                                                                                                                    |
| **DMQ status**                  | Beta 🟢                                                                                                                                                                                                                                                                |
| **Aggregator endpoint**         | `https://aggregator.release-mainnet.api.mithril.network/aggregator` [:arrow_upper_right:](https://aggregator.release-mainnet.api.mithril.network/aggregator)                                                                                                           |
| **Genesis verification key**    | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-mainnet/genesis.vkey` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-mainnet/genesis.vkey)     |
| **Era reader adapter type**     | `cardano-chain`                                                                                                                                                                                                                                                        |
| **Era reader address**          | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-mainnet/era.addr` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-mainnet/era.addr)             |
| **Era reader verification key** | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-mainnet/era.vkey` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-mainnet/era.vkey)             |
| **Ancillary verification key**  | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-mainnet/ancillary.vkey` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-mainnet/ancillary.vkey) |
| **Build from**                  | **Latest release** [:arrow_upper_right:](https://github.com/IntersectMBO/mithril/releases/latest)                                                                                                                                                                      |

  </TabItem>
  <TabItem value="preprod" label="Preprod">

## `release-preprod`

| Information                     | -                                                                                                                                                                                                                                                                      |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Mithril network**             | `release-preprod` [:mag_right:](https://mithril.network/explorer?aggregator=https%3A%2F%2Faggregator.release-preprod.api.mithril.network%2Faggregator)                                                                                                                 |
| **Cardano network**             | `preprod`                                                                                                                                                                                                                                                              |
| **Cardano magic Id**            | `1`                                                                                                                                                                                                                                                                    |
| **Cardano node versions**       | `10.7`, `11.0`                                                                                                                                                                                                                                                         |
| **Mithril status**              | Stable 🟢                                                                                                                                                                                                                                                              |
| **DMQ magic Id**                | `2147483649`                                                                                                                                                                                                                                                           |
| **DMQ node versions**           | `0.6.0.0`                                                                                                                                                                                                                                                              |
| **DMQ bootstrap peers**         | `34.79.19.73:6161`,`34.79.19.73:11002`                                                                                                                                                                                                                                 |
| **DMQ status**                  | Beta 🟢                                                                                                                                                                                                                                                                |
| **Aggregator endpoint**         | `https://aggregator.release-preprod.api.mithril.network/aggregator` [:arrow_upper_right:](https://aggregator.release-preprod.api.mithril.network/aggregator)                                                                                                           |
| **Genesis verification key**    | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/genesis.vkey` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/genesis.vkey)     |
| **Era reader adapter type**     | `cardano-chain`                                                                                                                                                                                                                                                        |
| **Era reader address**          | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/era.addr` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/era.addr)             |
| **Era reader verification key** | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/era.vkey` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/era.vkey)             |
| **Ancillary verification key**  | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/ancillary.vkey` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/ancillary.vkey) |
| **Build from**                  | **Latest release** [:arrow_upper_right:](https://github.com/IntersectMBO/mithril/releases/latest)                                                                                                                                                                      |

  </TabItem>
  <TabItem value="preview" label="Preview">

## `pre-release-preview`

| Information                     | -                                                                                                                                                                                                                                                                              |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Mithril network**             | `pre-release-preview` [:mag_right:](https://mithril.network/explorer?aggregator=https%3A%2F%2Faggregator.pre-release-preview.api.mithril.network%2Faggregator)                                                                                                                 |
| **Cardano network**             | `preview`                                                                                                                                                                                                                                                                      |
| **Cardano magic Id**            | `2`                                                                                                                                                                                                                                                                            |
| **Cardano node versions**       | `10.7`, `11.0`                                                                                                                                                                                                                                                                 |
| **Mithril status**              | Pre-release 🟠                                                                                                                                                                                                                                                                 |
| **DMQ magic Id**                | `2147483650`                                                                                                                                                                                                                                                                   |
| **DMQ node versions**           | `0.6.0.0`                                                                                                                                                                                                                                                                      |
| **DMQ bootstrap peers**         | `34.76.22.193:6161`,`34.76.22.193:11002`                                                                                                                                                                                                                                       |
| **DMQ status**                  | Beta 🟢                                                                                                                                                                                                                                                                        |
| **Aggregator endpoint**         | `https://aggregator.pre-release-preview.api.mithril.network/aggregator` [:arrow_upper_right:](https://aggregator.pre-release-preview.api.mithril.network/aggregator)                                                                                                           |
| **Genesis verification key**    | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/pre-release-preview/genesis.vkey` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/pre-release-preview/genesis.vkey)     |
| **Era reader adapter type**     | `cardano-chain`                                                                                                                                                                                                                                                                |
| **Era reader address**          | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/pre-release-preview/era.addr` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/pre-release-preview/era.addr)             |
| **Era reader verification key** | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/pre-release-preview/era.vkey` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/pre-release-preview/era.vkey)             |
| **Ancillary verification key**  | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/pre-release-preview/ancillary.vkey` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/pre-release-preview/ancillary.vkey) |
| **Build from**                  | **Latest pre-release** [:arrow_upper_right:](https://github.com/IntersectMBO/mithril/releases?q=pre)                                                                                                                                                                           |

<br/>

## `testing-preview`

:::danger

This network is only for the developers of the Mithril Core team.

:::

| Information                     | -                                                                                                                                                                                                                                                                      |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Mithril network**             | `testing-preview` [:mag_right:](https://mithril.network/explorer?aggregator=https%3A%2F%2Faggregator.testing-preview.api.mithril.network%2Faggregator)                                                                                                                 |
| **Cardano network**             | `preview`                                                                                                                                                                                                                                                              |
| **Cardano magic Id**            | `2`                                                                                                                                                                                                                                                                    |
| **Cardano node versions**       | `10.7`, `11.0`                                                                                                                                                                                                                                                         |
| **Mithril status**              | Unstable 🔴                                                                                                                                                                                                                                                            |
| **DMQ magic Id**                | `2147483650`                                                                                                                                                                                                                                                           |
| **DMQ node versions**           | `0.6.0.0`                                                                                                                                                                                                                                                              |
| **DMQ bootstrap peers**         | `34.38.152.55:6161`,`34.38.152.55:11001`,`34.38.152.55:11002`,`34.38.152.55:11003`                                                                                                                                                                                     |
| **DMQ status**                  | Unstable 🔴                                                                                                                                                                                                                                                            |
| **Aggregator endpoint**         | `https://aggregator.testing-preview.api.mithril.network/aggregator` [:arrow_upper_right:](https://aggregator.testing-preview.api.mithril.network/aggregator)                                                                                                           |
| **Genesis verification key**    | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/testing-preview/genesis.vkey` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/testing-preview/genesis.vkey)     |
| **Era reader adapter type**     | `cardano-chain`                                                                                                                                                                                                                                                        |
| **Era reader address**          | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/testing-preview/era.addr` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/testing-preview/era.addr)             |
| **Era reader verification key** | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/testing-preview/era.vkey` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/testing-preview/era.vkey)             |
| **Ancillary verification key**  | `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/testing-preview/ancillary.vkey` [:arrow_upper_right:](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/testing-preview/ancillary.vkey) |
| **Build from**                  | **Main branch** [:arrow_upper_right:](https://github.com/IntersectMBO/mithril/tree/main)                                                                                                                                                                               |

  </TabItem>
</Tabs>

:::caution
In this documentation, we use the following generic identifiers:

- **YOUR_CARDANO_NETWORK** You need to replace this with the name of the network that runs on your Cardano node (eg, `preprod`)
- **YOUR_AGGREGATOR_ENDPOINT** You need to replace this with the endpoint of an aggregator that runs on the Cardano network you are targeting (eg, `https://aggregator.release-preprod.api.mithril.network/aggregator`)
- **YOUR_GENESIS_VERIFICATION_KEY** You need to replace this with the genesis verification key URL that runs on the Cardano network you are targeting (eg, `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/genesis.vkey`)
- **YOUR_ERA_READER_ADAPTER_TYPE** You need to replace this with the era reader adapter type used by the Mithril network you are targeting (eg, `cardano-chain`)
- **YOUR_ERA_READER_ADDRESS** You need to replace this with the era reader address URL used by the Mithril network you are targeting (eg, `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/era.addr`)
- **YOUR_ERA_READER_VERIFICATION_KEY** You need to replace this with the era reader verification key URL used by the Mithril network you are targeting (eg, `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/era.vkey`)
- **YOUR_ANCILLARY_VERIFICATION_KEY** You need to replace this with the ancillary verification key URL used by the Mithril network you are targeting (eg, `https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-preprod/ancillary.vkey`)

:::
