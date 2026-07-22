---
title: Multiple aggregators testing program
authors:
  - name: Mithril Team
tags: [DMQ, decentralization, testing program, aggregator, follower]
---

### Multiple aggregators testing program

:::info[Update 2026/04/28]

With the release of the [`2617.0`](https://github.com/input-output-hk/mithril/releases/tag/2617.0) distribution, the testing program for running multiple aggregators is extended on the `pre-release-preview` network to keep gathering feedback before the stable release on `release-preprod` and `release-mainnet` networks.

:::

The Mithril team is launching a testing program for running **multiple aggregators** on the `pre-release-preview` network: running multiple aggregators will help increase decentralization and resilience of the Mithril network. This initiative will help collect valuable feedback, identify potential issues, and validate Mithril architecture before broader deployment.

#### Leader/follower architecture

We have introduced a **leader/follower architecture** for aggregators. In this initial phase, only the signature diffusion is decentralized thanks to the [DMQ protocol (CIP-0137)](https://cips.cardano.org/cip/CIP-0137). IOG will continue operating the **leader aggregator**, while anyone will be able to run a **follower aggregator**.

The leader aggregator serves as the **seed for the certificate chain and the signer registration**. When a follower aggregator joins the Mithril network, it fetches the existing certificate chain from the leader to bootstrap its operations and also relies on the leader aggregator to broadcast the signer registrations.

#### Public and private aggregators

Aggregators can be either **public** or **private**:

- **Public aggregators** are accessible to anyone and contribute to the overall resilience of the network
- **Private aggregators** can be operated for internal use cases or specific communities.

A **discovery mechanism** is also being tested to allow new public aggregators to be easily found and accessible by clients across the network.

#### Call for participation

We invite **SPOs and everyone in the Cardano ecosystem** to join this testing program! Whether you want to run a public aggregator to strengthen the network or a private one for your own needs, your participation will help validate and improve the follower aggregator.

:::tip

Running a follower aggregator does not require being an SPO: only a Cardano full node is needed.

:::

If you want to participate, please reach out to the team on the Mithril Discord channel.

#### Important requirement

:::info

More information about the testing program for the DMQ network is available in this [post](https://mithril.network/doc/dev-blog/2026/01/06/dmq-testing-program).

:::

A **healthy DMQ network operated by at least 60% of the stake** is mandatory for this feature to work. The DMQ protocol enables the decentralized diffusion of signatures, which must occur before any follower aggregator can proceed with the aggregation phase. During the ramp-up phase for the DMQ network, follower aggregators may not be able to produce valid certificates if the DMQ adoption is insufficient.

:::tip

The Mithril team will provide dedicated support and guidance to help participants set up and operate their aggregator nodes.

:::

#### Rollout plan

The rollout plan of the DMQ network is the following:

- [x] **Distribution [2603](https://github.com/input-output-hk/mithril/releases/tag/2603.1)**: `unstable` on the `pre-release-preview` network
  - [x] Activation of the feature on the `pre-release-preview` network
  - [x] Released a [guide](https://mithril.network/doc/manual/operate/run-aggregator-node) for setting up a follower aggregator
  - [x] Wait for the DMQ adoption to reach the required threshold until aggregators can produce valid certificates
  - [x] 4-6 weeks testing program with selected participants
- [ ] **Distribution [2617](https://github.com/input-output-hk/mithril/releases/tag/2617.0)**: `unstable` on the `pre-release-preview` network (extended testing)
  - [ ] 4-6 weeks extended testing program with selected SPOs
- [ ] **Distribution +3**: `stable` on the `release-preprod` and `release-mainnet` networks
  - [ ] Activation of the feature on the `release-preprod` and `release-mainnet` networks
  - [ ] Release of an updated guide for setting up a follower aggregator
  - [ ] Monitoring and support for operators running follower aggregators.

For any inquiries or assistance, contact the team on the [Discord channel](https://discord.gg/5kaErDKDRq).
