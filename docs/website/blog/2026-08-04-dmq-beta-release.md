---
title: DMQ node beta on the release networks
authors:
  - name: Mithril Team
tags: [DMQ, decentralization, beta, release, distribution, 2630]
---

### DMQ node beta on the release networks

We are happy to announce that the **Decentralized Message Queue (DMQ)** node is now officially supported in **beta** on the `release-mainnet` and `release-preprod` networks. This milestone follows the [DMQ testing program with SPOs](https://mithril.network/doc/dev-blog/2026/01/06/dmq-testing-program) conducted on the `pre-release-preview` network, and would not have been possible without the feedback of the participating stake pool operators (SPOs).

With the [`2630.0`](https://github.com/IntersectMBO/mithril/releases/tag/2630.0) distribution, the DMQ node version `0.7.0.0` has been promoted as **beta**, and the DMQ network is activated on both release networks.

#### All SPOs should now run a DMQ node

Running a DMQ node next to the Mithril signer is the new standard setup for SPOs:

- Follow the [setup guide](https://mithril.network/doc/manual/operate/run-signer-node#set-up-the-dmq-node-beta) to install and operate the DMQ node version `0.7.0.0` in your infrastructure
- Use the [network configurations](https://mithril.network/doc/manual/getting-started/network-configurations) page to retrieve the DMQ parameters of your network.

:::info

During the ramp-up phase, the fallback to the legacy signature registration mechanism remains active, so signer operations are not disrupted while the DMQ network adoption grows. This fallback will be deactivated in a future distribution.

:::

#### Why this matters

The DMQ protocol, specified in [CIP-0137](https://cips.cardano.org/cip/CIP-0137), decentralizes the diffusion of the individual signatures produced by the Mithril signers. It is the foundation on which **multiple aggregators** can operate simultaneously on the same Mithril network.

:::tip

Running the DMQ network with all SPOs is what will activate multiple aggregators on the Mithril networks. The more SPOs run a DMQ node, the sooner this major decentralization step can be unlocked.

:::

A healthy DMQ network operated by a large majority of the stake is mandatory before follower aggregators can reliably produce valid certificates. Every SPO running a DMQ node directly contributes to the decentralization and the resilience of the Mithril network.

#### References

- [CIP-0137](https://cips.cardano.org/cip/CIP-0137): specification of the DMQ protocol
- [DMQ node repository](https://github.com/IntersectMBO/dmq-node): implementation of the DMQ node
- [DMQ node setup guide](https://mithril.network/doc/manual/operate/run-signer-node#set-up-the-dmq-node-beta): instructions for SPOs
- [Network configurations](https://mithril.network/doc/manual/getting-started/network-configurations): DMQ parameters per network.

For any inquiries or assistance, contact the team on the [Discord channel](https://discord.gg/5kaErDKDRq).
