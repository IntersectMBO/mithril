---
sidebar_position: 2
sidebar_label: Mithril aggregator
---

# Mithril aggregator

:::info

A **Mithril aggregator** is a trustless node responsible for coordinating the activities of **Mithril signer** nodes. It gathers the individual signatures from the signer nodes to generate Mithril multi-signatures along with their corresponding certificates. Additionally, the aggregator is in charge of creating and maintaining the archive for the ledger state snapshot.

:::

:::tip

- For more information about the **Mithril protocol**, see the [protocol in depth](../mithril-protocol/protocol.md) overview.

- For more information about the **Mithril aggregator**, see the [developer manual](../../../manual/develop/nodes/mithril-aggregator.md).

:::

## Trustless orchestration

The primary objective of the Mithril aggregator is to coordinate and synchronize the production of Mithril multi-signatures:

- It is responsible for broadcasting the **verification keys** (Mithril public keys) of all the registered Mithril signers

- The current protocol parameters and the available verification keys are compiled and shared in an **epoch settings** data

- Mithril signers can register with it to participate in the signature process later on.

An important point to note is that the Mithril aggregator operates in a trustless manner:

- Anyone on the network can run an aggregator

- The aggregator doesn't broadcast any _sensitive_ information, such as the _message_ requiring signing. The signer nodes handle the direct computation of this information from a **Cardano node** on which they operate.

Additionally, when it comes to aggregating individual signatures into Mithril multi-signatures, the aggregator doesn't need to represent a portion of the total stake within the Cardano network.

## Multi-signature and certificate production

The Mithril aggregator oversees the creation of Mithril multi-signatures along with their associated certificates for a part and/or the entirety of the ledger state (snapshots):

- Previously registered Mithril signers generate individual signatures. These signatures are then sent to the Mithril aggregator for validation and storage.

- Once the **quorum** of individual signatures has been reached, the Mithril aggregator can generate a multi-signature.

- Subsequently, the Mithril aggregator combines the multi-signature with relevant metadata to create a **Mithril certificate**. This certificate will later be utilized by the **Mithril client** to authenticate a snapshot's legitimacy.

:::tip

For more information about the **Mithril certificate chain**, see the [certificate chain](../mithril-protocol/certificates.md) overview.

:::

## Snapshot artifacts production

In its initial version, the Mithril aggregator also handles the production of artifacts associated with the snapshot (such as the snapshot archive, which will be used later by a Mithril client).

:::note

It's important to note that this role is presently undertaken for the sake of convenience. However, it's planned that in the long run, the production of artifacts will be assigned to a distinct **Mithril snapshotter** node.

:::

Once the snapshot artifact is created, it can be synchronized on various locations:

- On the Mithril aggregator itself
- On any cloud platform that offers a CDN
- On a distinct peer-to-peer network, such as **IPFS** or **BitTorrent**.

The Mithril certificate is part of a chain of certificates that are essential for snapshot authenticity verification and is stored in either of the following ways:

- On the Mithril aggregator itself
- On any accessible storage, such as cloud storage, for instance.

## Distribution of snapshot artifacts and certificates

If the Mithril aggregator stores the snapshot artifacts and/or the certificates, it can function as a distribution point for this data to remote clients. The clients can then use the artifacts as needed and verify their authenticity.

## Under the hood

In its initial version, the Mithril aggregator comprises two main components:

- A REST API that allows Mithril signers to:
  - Retrieve **verification keys** of other registered signers
  - Register their own verification keys
  - Register their **individual signatures**.

:::tip

The Mithril aggregator's **REST API** documentation can be found here :

- [current](/doc/aggregator-api/current)
- [next 🚧](/doc/aggregator-api/next)

:::

- A runtime powered by a state machine:
  - The runtime operates synchronously and is scheduled to execute at regular intervals
  - It encompasses four potential states: **IDLE**, **BLOCKED**, **READY**, and **SIGNING**
  - The runtime effectively manages state transitions
  - The runtime structure is illustrated in the diagram below:

![Aggregator Runtime](images/aggregator-runtime.jpg)
