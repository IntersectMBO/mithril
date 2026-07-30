---
sidebar_position: 3
sidebar_label: Threat model analysis
---

# Threat model analysis

:::danger

This is a draft version of the **Mithril threat model**, prepared by the **Mithril core team**. It is open for external feedback and contributions before being finalized.

- To contribute, use the **Edit this page** option at the bottom of the page.
- If you discover a security vulnerability, report it responsibly by following the [security vulnerability disclosure policy](https://github.com/IntersectMBO/mithril/blob/main/SECURITY.md).

:::

This document provides an analysis of various security threats and possible mitigations affecting the Mithril network and its participants. It adopts an adversarial mindset, analyzing the system from an attacker's perspective.

The threat model is a living document, updated to reflect the [latest Mithril version](https://github.com/IntersectMBO/mithril/releases/latest).

## System analysis

### System description

:::info[To do]

- Consider reducing these details and moving them into the [architecture page](https://mithril.network/doc/mithril/mithril-network/architecture).
- Also consider updating the [protocol page](https://mithril.network/doc/mithril/mithril-protocol/protocol).

:::

The system consists of three main components: signers, aggregators, and clients.

- **Mithril signers** certify Cardano chain data by using a Mithril signing key. They must have access to both a trusted `cardano-node` and the Mithril signing key to operate.
- **Mithril signing keys** are rotated every epoch and require certification by the Cardano KES key. Therefore, Mithril signers must have access to the KES key to register a signing key for each epoch.
- **Cardano KES keys** are also used by the block-producing `cardano-node` and are typically located on the same machine that produces blocks. These keys must be evolved every 36 hours, although they can be rotated from a root key when needed. For more details, see [KES period documentation](https://github.com/input-output-hk/cardano-node-wiki/blob/main/docs/stake-pool-operations/7_KES_period.md).

:::info[To do]

Is there a Cardano threat model available for this?

:::

All Mithril signers and Mithril clients connect to a single aggregator using HTTP over TLS.

Registering a Mithril signing key means that a signer sends its corresponding verification key to the aggregator, for the purpose of distribution to all other Mithril signers.

Each Mithril signer checks if there is something that can be signed independently, produces a signature of what's needed to sign and submits that to the aggregator (which verifies the signature being correct upon receiving).

The aggregator repeatedly checks whether enough valid signatures (to reach the quorum) are available to aggregate a Mithril stake-based multi-signature into a certificate.

Mithril certificates certify some chain data using an aggregated multi-signature verification key and are chained up to some genesis certificate, which is signed by a genesis signing key.

Mithril clients do connect to an aggregator using HTTP over TLS to query Mithril certificates for certified chain data and locate artifacts.

A Mithril client can verify the received Mithril certificate is linked to other certificates up to the genesis certificate and can be verified using the Mithril genesis verification key (see [details](https://mithril.network/doc/mithril/mithril-protocol/certificates/)).

:::info[To do]

Missing: the currently recommended relay (reverse proxy)

:::

#### Deployment architecture

This document focuses on the standard deployment architecture, where a Mithril signer runs alongside the block-producing node, and the aggregator is accessed only through a relay.

[![Mithril - Architecture](mithril-network/images/architecture.svg)](mithril-network/images/architecture.svg)

Additional information is available in:

- [Mithril network architecture](https://mithril.network/doc/mithril/mithril-network/architecture)
- [Run a Mithril signer as a stake pool operator (SPO)](https://mithril.network/doc/manual/getting-started/run-signer-node).

### External dependencies

Below is an example of listing dependencies for the `mithril-signer` component:

```
% cargo-deps-list -e normal -p mithril-signer
...
slog-json v2.6.1 {default}
slog-scope v4.4.0
arc-swap v1.6.0

Total dependencies: 267
```

- SPO infrastructure:
  - Block-producing host configuration
  - Relay hosts configuration
  - Firewall/private network.

### Entry points

- `mithril-aggregator` HTTP port
- `mithril-relay` HTTP port.

## Assumptions

The core Mithril protocol is considered safe, and its analysis is out of scope for this document. It is computationally infeasible to:

- Forge a valid aggregate signature from forged signing keys
- Forge individual signatures to impersonate a legitimate signer.

More information about the core Mithril protocol and its security is available in the [research paper](https://iohk.io/en/research/library/papers/mithril-stake-based-threshold-multisignatures/).

## Assets

For each asset, we first identify which part of the **CIA triad** (Confidentiality, Integrity, Availability) it requires. An asset may be a resource, a piece of data (for example, keys), or a process that may be affected. We then identify threats and possible countermeasures.

#### KES private keys

- The KES key is present only on the block-producing (BP) node but needs to be shared with both the `cardano-node` process and the `mithril-signer` process.
- KES keys are needed by `mithril-signer` to sign a verification key along with an operational certificate that authenticates the key for this stake pool ID.
- This signing happens at every epoch.

  - **Confidentiality**: Yes  
    Capturing KES private keys allows an attacker to impersonate a registered SPO on-chain and produce blocks on its behalf until the keys are rotated.

  - **Integrity**: Yes  
    Rotating a compromised KES key is a time-consuming process that can be carried out even if the associated KES period has not fully passed. See [KES period docs](https://github.com/input-output-hk/cardano-node-wiki/blob/main/docs/stake-pool-operations/7_KES_period.md).

  - **Availability**: Yes  
    If the KES key is unavailable, signing cannot proceed.

#### Block diffusion

Block diffusion ensures the timely propagation of blocks that are produced locally or received from upstream peers.

- **Confidentiality**: No (block diffusion happens openly on the network)
- **Integrity**: Yes (partially — if data is corrupted in transit, it can affect network consistency)
- **Availability**: Yes (failure to diffuse blocks harms a block producer’s economic viability and can disrupt the network).

#### Block production

Block production is the process of minting new blocks by block producers, using a stake-based random lottery. The `mithril-signer` must run on the same host as a block producer, as it requires access to the KES signing key.

- **Confidentiality**: Yes?  
  A block producer’s schedule is private information; if leaked, adversaries might carry out **grinding attacks** to manipulate the nonce to the producer’s disadvantage.

- **Integrity**: Yes  
  Incorrect or invalid data can hamper block production.

- **Availability**: Yes  
  Block production is critical for SPO revenue; preventing a producer from creating blocks can harm the SPO’s operational capabilities.

#### Cardano chain database

A `cardano-node` maintains an on-disk database containing the chain’s history. This database is updated by the node when new blocks are diffused across the network or minted, and it contains a cache of the ledger state.

The `mithril-signer` needs access to a _trusted_ and _current_ chain database to sign snapshots.

- **Confidentiality**: No (block data is publicly replicated)
- **Integrity**: Yes
- **Availability**: Yes.

#### Cardano ledger state

The Mihril signer requires access to an accurate ledger state is needed by the `mithril-signer` to retrieve a reliable _stake distribution_. This currently involves a local connection (direct with Pallas or indirect with `cardano-cli`) to a trusted `cardano-node`. The ledger state and stake distribution are also used by the node to determine leader schedules, meaning any corruption here affects block production.

- **Confidentiality**: No
- **Integrity**: Yes (same, inaccurate SD will make key registration and signing process invalid)
- **Availability**: Yes (without SD, signer cannot register keys nor validly use other signers' keys).

#### Mithril signing keys

SPOs generate their Mithril signing keys for each epoch to sign snapshots. If attackers obtain these keys, they can impersonate the SPO and produce invalid snapshots. Currently, the signing keys are stored temporarily on disk; they are used for two epochs after creation and are deleted two epochs later. Additionally, these keys are not encrypted.

- **Confidentiality**: Yes (compromise allows an attacker to impersonate the signer)
- **Integrity**: Yes (an invalid key is useless)
- **Availability**: Yes (the signer needs the key at every signing round; unavailability prevents signing).

#### Mithril signers registration

A `mithril-signer` must register a new verification key each epoch with the aggregator (and ultimately other signers).

- **Confidentiality**: No (only public verification keys and proofs of possession are exchanged)
- **Integrity**: Yes (the key registration must be correct and timely for a given epoch)
- **Availability**: Yes (the signer needs aggregator access to register its key).

#### Mithril signature diffusion

Mithril signers produce signatures for new immutable files or other relevant data in the chain database. These signatures are derived from a random lottery based on the signer’s stake and protocol parameters.  
Preventing signers from submitting signatures reduces the overall number of signatures, which could allow an attacker a greater influence over snapshot production.

- **Confidentiality**: No
- **Integrity**: No (signatures are effectively tamper-proof)
- **Availability**: Yes.

#### Mithril protocol parameters

Protocol parameters coordinate valid multi-signature production and are served by the aggregator.

- **Confidentiality**: No (these parameters must be public)
- **Integrity**: Yes (tampering with them could lead to invalid signatures)
- **Availability**: Yes.

#### Mithril genesis signing key

The genesis signing key is stored in IOG’s VaultWarden and used only once to generate the genesis certificate.

- **Confidentiality**: Yes
- **Integrity**: Yes (?)
- **Availability**: No (not needed unless a re-genesis process is required; a new key could be used in that case).

#### Era configuration files

The [Mithril network upgrade strategy](https://mithril.network/doc/adr/4) describes how Mithril eras activate features on all nodes at specific epoch boundaries.

An era address is used by signers to identify the current Mithril era, which defines the structure of snapshots and signatures. It is stored in [GitHub](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-mainnet/era.addr) and is only modifiable via a merged PR.

- **Confidentiality**: No (these are public files)
- **Integrity**: Yes (tampering could disrupt multi-signature generation)
- **Availability**: Yes.

#### Era activation

The current and next (if any) eras are announced on-chain with an era activation marker. (See [ADR](https://mithril.network/doc/adr/4#era-activation-marker).)

- **Confidentiality**: No (public)
- **Integrity**: Yes (tampering with the marker could break multi-signature generation)
- **Availability**: Yes (the marker is on-chain).

#### Era verification key

The era verification key is in [GitHub](https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-mainnet/era.vkey) and is only modifiable through a merged PR.

- **Confidentiality**: No
- **Integrity**: No (the protocol enforces integrity checks)
- **Availability**: Yes (needed to verify the certificate chain).

#### Era signing key

This key is stored in IOG’s VaultWarden and used only when a new era is announced or activated.

- **Confidentiality**: Yes
- **Integrity**: Yes (?)
- **Availability**: No.

### Client-side only assets

These assets matter only when downloading and verifying certificates and artifacts (for example, snapshots).

#### Mithril certificate verification process

Mithril clients, such as a CLI tool or the [web-based explorer](https://mithril.network/explorer/), download snapshots and verify their certificates using the `mithril-client` library.

- **Confidentiality**: No
- **Integrity**: No (snapshots and certificates are assumed to be secure by protocol design)
- **Availability**: Yes (?).

#### Mithril certificates

These are produced by the aggregator from individual signatures. Their security depends on a chain of trust that ultimately references a genesis certificate.

- **Confidentiality**: No
- **Integrity**: No (the protocol design ensures integrity)
- **Availability**: No (certificates are a fallback; a Cardano node client can retrieve data from the network, albeit more slowly).

#### Mithril artifacts

Mithril artifacts are generated by the aggregator for specific data types (for example, a compressed snapshot of a Cardano node database). The aggregator hosts these artifacts for client retrieval.

- **Confidentiality**: No
- **Integrity**: No (they are verified against their certificate)
- **Availability**: No (a fallback exists via the original Cardano network).

#### Mithril genesis verification key

The genesis verification key is stored in [GitHub](https://github.com/IntersectMBO/mithril/blob/main/mithril-infra/configuration/release-mainnet/genesis.vkey) and is only modifiable through an approved PR.

- **Confidentiality**: No
- **Integrity**: No (the protocol enforces integrity)
- **Availability**: Yes (needed to verify the entire certificate chain).

## Threats and mitigations

:::info

- This list of threats and mitigations is not exhaustive.
- [Developer Portal](https://developers.cardano.org/docs/operate-a-stake-pool/hardening-server) already provides thorough documentation on hardening a Linux-based host to run `cardano-node`.

:::

### Resource exhaustion on Cardano relay

A denial-of-service (DoS) attack targeting a `mithril-signer` running alongside a `cardano-node` acting as a relay.

- **Assets at risk**:
  - [Block diffusion](#block-diffusion)
  - [Mithril signatures diffusion](#mithril-signatures-diffusion).

#### Block diffusion exhaustion

- Diffusion is ensured through the connection between BPs, local relays, and downstream/upstream relays
- Preventing them from operating can harm the Cardano network
- Relay hosts connect the BP to the network
- Starving relay hosts prevents Mithril signatures and key registration from being shared
- Starving a `cardano-node` running on a relay host would prevent or delay the diffusion of new blocks, thus harming
- Compromising relay hosts would be an extreme form of starving resources.

### Resource exhaustion on Cardano block producer

- Assets at risk:
  - [Block production](#block-production)

#### Block production exhaustion

- A malfunctioning or malicious `mithril-signer` could starve a `cardano-node` of resources, preventing it from producing and diffusing blocks in time
- Compromising a block-producing node severely harms an SPO’s economic viability.

### Resource exhaustion on Mithril aggregator

A DoS on the `mithril-aggregator`.

- **Assets at risk**:
  - [Mithril signers registration](#mithril-signers-registration)
  - [Mithril signatures diffusion](#mithril-signatures-diffusion)
  - [Mithril certificates](#mithril-certificates)
  - [Mithril artifacts](#mithril-artifacts).

### Integrity of the Cardano block producer database

Data integrity of the Cardano block producer’s on-disk database could be compromised either by the action of the Mithril signer or by an attacker with access to the signer.

- **Assets at risk**:

  - [Block production](#block-production)
  - [Cardano chain database](#cardano-chain-database).

- **Mitigation**: assign the Mithril signer only _read-only_ permissions to the Cardano block producer’s database folder.

## References

- [SPO guide](https://developers.cardano.org/docs/operate-a-stake-pool/)
- [Mithril network architecture](https://mithril.network/doc/mithril/mithril-network/architecture)
- [Run a Mithril signer as an SPO](https://mithril.network/doc/manual/getting-started/run-signer-node)
- [Mithril: Stake-based Threshold Multisignatures](https://iohk.io/en/research/library/papers/mithril-stake-based-threshold-multisignatures/)
- [Mithril network upgrade strategy](https://mithril.network/doc/adr/4)
- [OWASP threat modeling process](https://owasp.org/www-community/Threat_Modeling_Process)
- [Lightning book security chapter](https://github.com/lnbook/lnbook/blob/develop/16_security_privacy_ln.asciidoc)
- [Lightning gossip protocol](https://github.com/lnbook/lnbook/blob/develop/11_gossip_channel_graph.asciidoc)
- [Consul security model](https://developer.hashicorp.com/consul/docs/security/security-models/core)
- [Parsec threat model](https://parallaxsecond.github.io/parsec-book/parsec_security/parsec_threat_model/threat_model.html)
- A list of [threat models](https://github.com/hysnsec/awesome-threat-modelling#threat-model-examples)
- There is even a [threat model manifesto](https://www.threatmodelingmanifesto.org) :open_mouth: !
