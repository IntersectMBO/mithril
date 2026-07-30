---
title: DMQ testing program with SPOs
authors:
  - name: Mithril Team
tags: [DMQ, decentralization, testing program]
---

### DMQ testing program with SPOs

:::info[Update 2026/04/28]

With the release of the [`2617.0`](https://github.com/input-output-hk/mithril/releases/tag/2617.0) distribution, the DMQ node has been upgraded to version `0.4.2.0` on the `pre-release-preview` network. The testing program with SPOs is extended to keep gathering feedback before the stable release on `release-preprod` and `release-mainnet` networks.

:::

We are excited to announce the launch of a testing program for the **Decentralized Message Queue (DMQ)** feature with a group of stake pool operators (SPOs). This program will take place on the `pre-release-preview` network and aims to gather feedback, identify potential issues, and ensure the robustness of the DMQ implementation before its wider release.

#### What is DMQ?

The DMQ protocol, specified in [CIP-0137](https://cips.cardano.org/cip/CIP-0137), is a major step forward for the Mithril network. It enables **multiple aggregators** to operate simultaneously on the same Mithril network, significantly improving **decentralization** and **resilience**. This enhancement reduces single points of failure and strengthens the overall robustness of the certificate production process.

#### Call for SPO participation

We invite interested SPOs to join the testing program! The only requirement is to run a Mithril signer on the `pre-release-preview` network. If you want to participate, please reach out to us on the Mithril Discord channel.

#### Important note on adoption

:::info

Once the DMQ adoption has reached the required threshold, running multiple aggregators will be unlocked on the corresponding Mithril network. More information about the testing program for running multiple aggregators is available in this [post](https://mithril.network/doc/dev-blog/2026/01/06/multiple-aggregators-testing-program).

:::

For the DMQ protocol to operate effectively, a **minimum adoption of 60% of stake** among SPOs is required. During the ramp-up phase, the legacy signature registration mechanism will remain active to ensure continuity and avoid any disruption. Once the vast majority of SPOs have adopted DMQ, the legacy mechanism will be deactivated.

:::tip

The Mithril team will provide dedicated support and guidance to help SPOs set up and operate their DMQ nodes.

:::

#### Rollout plan

The rollout plan of the DMQ network is the following:

- [x] **Distribution [2603](https://github.com/input-output-hk/mithril/releases/tag/2603.1)**: `unstable` on the `pre-release-preview` network
  - [x] DMQ activation on the `pre-release-preview` network
  - [x] Released a [guide](https://mithril.network/doc/manual/operate/run-signer-node/#set-up-the-dmq-node-unstable) for setting up a DMQ node in the SPO infrastructure
  - [x] 4-6 weeks testing program with selected SPOs
- [ ] **Distribution [2617](https://github.com/input-output-hk/mithril/releases/tag/2617.0)**: `unstable` on the `pre-release-preview` network (extended testing)
  - [x] Upgraded the DMQ node to version `0.4.2.0` on the `pre-release-preview` network
  - [ ] 4-6 weeks extended testing program with selected SPOs
- [ ] **Distribution +3**: `stable` on the `release-preprod` and `release-mainnet` networks with fallback
  - [ ] DMQ activation on the `release-preprod` and `release-mainnet` networks
  - [ ] Activation of the fallback to the legacy signature registration mechanism for all SPOs
  - [ ] Release of an updated guide for setting up a DMQ node in the SPO infrastructure
  - [ ] Monitoring and support for SPOs running DMQ nodes
- [ ] **Distribution +4**: `stable` on the `release-preprod` and `release-mainnet` networks
  - [ ] Deactivation of the fallback to the legacy signature registration mechanism for all SPOs
  - [ ] Monitoring and support for SPOs running DMQ nodes.

For any inquiries or assistance, contact the team on the [Discord channel](https://discord.gg/5kaErDKDRq).
