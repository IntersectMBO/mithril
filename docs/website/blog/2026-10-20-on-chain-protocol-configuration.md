---
title: Protocol configuration is now read from the Cardano chain
authors:
  - name: Mithril Team
tags: [protocol, configuration, decentralization, spo, distribution, 2642]
---

### Protocol configuration is now read from the Cardano chain

With the [`2642.0`](https://github.com/IntersectMBO/mithril/releases/tag/2642.0) distribution, the Mithril signers and aggregators read the **protocol configuration** of their network from the **Cardano chain**, instead of receiving it from the leader aggregator over HTTP.

#### What is the protocol configuration?

The protocol configuration gathers the parameters shared by all the nodes of a Mithril network:

- The **protocol parameters** (`k`, `m` and `phi_f`) used to create the multi-signatures
- The **signed entity types configuration**, such as the signing step and security parameter of the Cardano transactions and of the Cardano blocks and transactions.

#### How does it work?

The release team publishes **protocol configuration markers** on the Cardano chain, each of them defining the configuration that starts at a given epoch:

- The markers are stored in transactions sent to a dedicated address, and are signed with a key held by the release team
- Each node reads the markers with the `cardano-chain` adapter, configured with this address and the verification key, so it can authenticate them without trusting an aggregator
- At startup and at every new epoch, each node rebuilds its configuration for the aggregation, next aggregation and registration epochs, so all the nodes switch to a new configuration at almost the same time.

This mechanism mirrors the era markers already used to activate new Mithril eras, and is described in [ADR 13](https://mithril.network/doc/adr/13).

#### Why this matters

Reading the protocol configuration from the chain removes the dependency of the signers and follower aggregators on the configuration served by the leader aggregator. It is another step towards a **decentralized** Mithril network, where **multiple aggregators** operate simultaneously.

#### What do you need to do?

For **SPOs** running a **Mithril signer**:

- Upgrade the signer node binary to version `1.2.5`
- Set the new `PROTOCOL_CONFIGURATION_READER_ADAPTER_CONFIG` configuration parameter by following the [signer node documentation](https://mithril.network/doc/manual/operate/run-signer-node#set-up-the-service).

:::info

There is a **grace period** for the new configuration parameter: signers without it keep working until the next distribution, which will remove the legacy fallback.

:::

For operators of a **Mithril aggregator**:

- Replace the removed `protocol_parameters`, `cardano_transactions_signing_config` and `cardano_blocks_transactions_signing_config` configuration parameters with the new `protocol_configuration_reader_adapter_config` configuration parameter, by following the [aggregator node documentation](https://mithril.network/doc/manual/operate/run-aggregator-node).

:::tip

The `protocol-configuration export-markers` command of the Mithril aggregator exports the protocol configuration read from the chain to a human readable JSON file.

:::

#### References

- [ADR 13](https://mithril.network/doc/adr/13): protocol configuration decentralization
- [Signer node setup guide](https://mithril.network/doc/manual/operate/run-signer-node#set-up-the-service): instructions for SPOs
- [Network configurations](https://mithril.network/doc/manual/getting-started/network-configurations): protocol configuration parameters per network.

For any inquiries or assistance, contact the team on the [Discord channel](https://discord.gg/5kaErDKDRq).
