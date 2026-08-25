---
sidebar_position: 1
---

# Glossary

Below is a comprehensive list of definitions for some common terms used in the Mithril guide.

## Beacon

A beacon represents a point of the blockchain for which a [Mithril certificate](#certificate) is created. It embeds the [epoch](#epoch) of the [Cardano network](#cardano-network) that is targeted, and either the block number or the [immutable file number](#immutable-file-number).

## Cardano database

A Cardano database snapshot is a signed archive of the blockchain state that can be used by [Mithril clients](#mithril-client) to restore a [Cardano full node](#cardano-node). It is uniquely identified by its fingerprint or digest which is part of the message signed by the [Mithril network](#mithril-network).

## Cardano network

The Cardano network is a proof-of-stake blockchain platform that supports the ada cryptocurrency.

> More information is available on the [introduction page](https://docs.cardano.org/introduction).

## Cardano node

A Cardano node is a node that runs in a [Cardano network](#cardano-network). There are several types of nodes, among them Cardano full nodes that hold a copy of the whole blockchain. They can be used by wallets, [stake pool operators](#stake-pool-operator-spo), exchanges or DApps. One of the uses of the [Mithril network](#mithril-network) is to rapidly bootstrap a Cardano full node.

## Cardano key pair

A Cardano key pair is an asymmetric key pair used to identify a [stake pool operator](#stake-pool-operator-spo) on the [Cardano network](#cardano-network).

## Cardano transaction

A Cardano transaction proof is a cryptographic proof that a sub-set of Cardano transactions is included in the Cardano transactions set. It is generated upon request from a [Mithril client](#mithril-client) and is signed by a [certificate](#certificate).

A Cardano transactions set snapshot represents, in a succinct way, the Cardano transactions set that was signed by Mithril at a given [Beacon](#beacon).

## Certificate

The Mithril aggregator combines the produced [multi-signature](#multi-signature) and some metadata into a Mithril certificate that will be later used by the [Mithril client](#mithril-client) to verify the authenticity of a [snapshot](#snapshot). The certificates are chained so that the [stake distribution](#stake-distribution) used to create the signatures is verifiably genuine.

> More information is available on the [certificates page](./mithril/advanced/mithril-protocol/certificates.md).

## Epoch

The [Cardano network](#cardano-network) uses epochs to group blocks computed in a certain amount of time (approximately five days). It is part of the design of its proof-of-stake consensus Ouroboros. At the end of each epoch, the [stake distribution](#stake-distribution) of the ending epoch is computed.

## Immutable file number

Inside the database of a [Cardano node](#cardano-node), the blockchain state is stored in immutable files which never change once committed. These immutable files are designed so that they are deterministically produced and thus are the same on any Cardano node. These files are created by following an incremental number, the immutable file number, and there are three different immutable files for each number (ie, _chunk_, _primary_, and _secondary_). Only the files up to the penultimate immutable file number are considered as committed and final, the last immutable file number files are constantly evolving. The [snapshots](#snapshot) produced by the [Mithril network](#mithril-network) rely on these immutable files.

## Individual signature

For each [beacon](#beacon), the [Mithril signers](#mithril-signer) will compute on their end a message representing the blockchain state, and sign it with their verification keys to create an [individual signature](#individual-signature). Upon winning one or more lotteries, the Mithril signer will be able to use this individual signature to participate in the creation of a [multi-signature](#multi-signature).

> More information is available on the [protocol page](./mithril/advanced/mithril-protocol/protocol.md).

## Mithril aggregator

The Mithril aggregator is a trustless node of the [Mithril network](#mithril-network) that orchestrates the work of the [Mithril signer](#mithril-signer) nodes and gathers their [individual signatures](#individual-signature) to produce [Mithril multi-signatures](#multi-signature) and their associated [certificates](#certificate).

It is also in charge of creating and storing the [snapshot](#snapshot) archive.

> More information is available on the [aggregator page](./mithril/advanced/mithril-network/aggregator.md).

## Mithril client

The Mithril client node within the [Mithril network](#mithril-network) is used to restore a [Cardano full node](#cardano-node) by retrieving, from a [Mithril aggregator](#mithril-aggregator), a remote [snapshot](#snapshot) and its [certificate](#certificate) chain. Finally, it is used to verify snapshot and certificate validity using the Mithril cryptographic primitives.

> More information is available on the [client page](./mithril/advanced/mithril-network/client.md).

## Mithril network

In its current version, the Mithril network is a network of nodes responsible for creating [snapshots](#snapshot) and [certificates](#certificate) that enable fast bootstrap of a [Cardano node](#cardano-node). It runs on top of the [Cardano network](#cardano-network).

> More information is available on the [architecture page](./mithril/advanced/mithril-network/architecture.md).

## Mithril protocol

The Mithril protocol allows stakeholders in a proof-of-stake blockchain network to individually sign messages that are aggregated into a multi-signature which guarantees that they represent a minimum share of the total stake.

> More information is on the [protocol page](./mithril/advanced/mithril-protocol/protocol.md).

## Mithril signer

The Mithril signer is a node of the [Mithril network](#mithril-network) that works transparently on top of the [stake pool operator](#stake-pool-operator-spo) Cardano nodes and which individually signs the ledger state.

> More information is available on the [signer page](./mithril/advanced/mithril-network/signer.md).

## Multi-signature

The Mithril multi-signature is an aggregate of [individual signatures](#individual-signature), which guarantees that a minimum share of the total stake has participated in its creation.

> More information is available on the [protocol page](./mithril/advanced/mithril-protocol/protocol.md).

## Stake distribution

The Cardano stake distribution is the list of all the [stake pool operators'](#stake-pool-operator-spo) pool Id addresses and their associated share of the total stake of the [Cardano network](#cardano-network).

The Mithril stake distribution is the list of all the [stake pool operators'](#stake-pool-operator-spo) (that are running a [Mithril signer](#mithril-signer)) pool Id addresses, their associated share of the total stake of the [Cardano network](#cardano-network), and their signing [verification key](#verification-key).

## Stake pool operator (SPO)

A stake pool operator, also known as an SPO, represents a party that holds (via delegation) stake in the [Cardano network](#cardano-network). The stake entitles it to participate in block production thanks to the Cardano consensus mechanism.

## Verification key

To create [individual signatures](#individual-signature), [Mithril signers](#mithril-signer) must register their signing public key: the verification key. To guarantee their genuineness, they are signed by the associated [Cardano key pair](#cardano-key-pair). It is worth mentioning that a [Mithril signer](#mithril-signer) must be aware of the verification keys of all the other Mithril signers to produce valid individual signatures.

> More information is available on the [protocol page](./mithril/advanced/mithril-protocol/protocol.md).
