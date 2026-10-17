---
sidebar_position: 2
sidebar_label: Certificate chain design
---

# Certificate chain design

## Introduction

The **certificate chain** is a Mithril component that certifies the **stake distribution** used to create the multi-signature. Its primary purpose is to prevent adversaries from executing an **eclipse attack** on the blockchain.

Without the certificate, the stake distribution can't be trusted. A malicious actor could relatively easily create a fake stake distribution and use it to produce a valid multi-signature, which would be embedded in a valid but non-genuine certificate. This certificate could be served by a dishonest Mithril aggregator node, leading an honest Mithril client to restore a non-genuine snapshot.

## The certificate chain design

:::danger

The stake distribution of an epoch is computed by **Cardano nodes** at the end of each epoch. It becomes usable from the beginning of the following epoch.

:::
The way to certify the stake distribution used to create a multi-signature is by verifying that it has been previously signed in an earlier certificate. Then, one can recursively verify that the earlier certificate is valid in the same manner. This process can be structured as a chain of certificates, known as the Mithril certificate chain. The first certificate in the chain is discussed below.

Since multiple certificates can be created during the same epoch using the same stake distribution, it is not necessary to link to all of them for verification. Instead, it is sufficient to link to only one certificate from the previous epoch. By doing so, the verification process becomes faster and helps avoid network congestion.

The first certificate in the certificate chain is known as the **genesis certificate**. Validating the stake distribution embedded in the genesis certificate is only possible by signing it with a private key linked to a widely accessible public key called the **genesis key**. The use of these specific keys ensures the integrity and security of the initial stake distribution and subsequent transitions within the blockchain network.

The diagram below presents the certificate chain design:
[![Certificate Chain Design](images/certificate-chain.jpg)](images/certificate-chain.jpg)

Where the following notations have been used:

- `C(p,n)`: Certificate at trigger `p` and epoch `n`
- `FC(n)`: First certificate of epoch `n`
- `GC`: Genesis certificate
- `H()`: Hash
- `SD(n)`: Stake distribution of epoch `n`
- `VK(n)`: Verification key at epoch `n`
- `AVK(n)`: Aggregrate verification key at epoch `n` such as `AVK(n) = MKT_ROOT(SD(n) || VK(n))`
- `MKT_ROOT()`: Merkle-tree root
- `PPARAMS(n)`: Protocol parameters at epoch `n`
- `EPOCH(n)`: Epoch `n`
- `BEACON(p,n)`: Beacon at trigger `p` and epoch `n` (includes `EPOCH(n)`)
- `METADATA(p,n)`: Metadata of the certificate at trigger `p` and epoch `n`
- `MSG(p,n)`: Message of the certificate at trigger `p` and epoch `n`
- `MULTI_SIG(p,n)`: Multi-signature created to the message `H(MSG(p,n) || AVK(n-1))`
- `GENESIS_SIG(MSG)`: Genesis signature, the signature of `MSG` with the genesis keys

The hash of a certificate `H(C(p,n))` is computed as the concatenation (`||`) of all its fields. Therefore, if one field is modified, its hash is different.

Information embedded in the `METADATA(p,n)` field:

- The version of the Mithril protocol
- The parameters of the Mithril protocol (`k`, `m`, and `phi_f`)
- The date and time at which the multi-signature creation was initiated
- The date and time at which the certificate was sealed
- The list of the signers that actively contributed to the multi-signature.

The message `MSG(p,n)` is a map of multiple values associated with their respective keys. It provides a way to add more information to the certificates without breaking the chain itself. Added items can be any message that the signers can compute deterministically thanks to the Cardano consensus – an immutable files snapshot, the UTXO set, stake distribution, etc.

:::note

The **trigger** represents the instant at which a certificate should be created. It is combined with at least the associated **epoch** to create a [**beacon**](../../../glossary.md#beacon) of the certificate. In the current implementation of the Cardano node database snapshot, this trigger is a new [**immutable file number**](../../../glossary.md#immutable-file-number).

:::

:::info

The **aggregate verification key** (`AVK`) is the root of the Merkle tree where each leaf is filled with either `H(STAKE(signer) || VK(signer))` for the concatenation flavor of aggregation or `H(VK(signer) || LotteryTarget(signer))` for the non-recursive SNARK flavor where `LotteryTarget` is a value that depends on the stake of the signer and the total stake registered. The `AVK` represents the corresponding stake distribution in a condensed way.
:::

## The verification algorithm

Certificate chain verification can be stated as:

```
CHAIN_VERIFY[C(p,n(p))] = CERT_VERIFY[C(p,n(p)] ^ CERT_VERIFY[FC(n(p))] ^ CERT_VERIFY[FC(n(p)-1)] ^ ... ^ CERT_VERIFY[FC(1)] ^ CERT_VERIFY[GC]
```

Where the following notations have been used:

- The epoch `n(p)` depends on the trigger `p`
- `CHAIN_VERIFY[]`: verify all the chain backward from a certificate
- `CERT_VERIFY[]`: verify a specific certificate.

A certificate chain is considered valid when there is at least one valid certificate per epoch, starting from a certificate and going all the way up to the genesis certificate of the chain.

A **non-genesis certificate** is valid if and only if the `AVK` used to verify the multi-signature is also part of the signed message used to create a valid multi-signature in a previously sealed certificate.

The genesis certificate is valid if and only if its genesis signature is verified with the advertised public genesis key.

An implementation of the algorithm would work as follows for a certificate:

- **Step 1**: Use this certificate as the `current_certificate`
- **Step 2**: Verify (or fail) that the `current_hash` of the `current_certificate` is valid by computing it and comparing it with the `hash` field of the certificate
- **Step 3**: Get the `previous_hash` of the `previous_certificate` by reading its value in the `current_certificate`
- **Step 4**: Verify (or fail) that the `multi_signature` of the `current_certificate` is valid
- **Step 5**: Verify (or fail) that the `current_epoch` of the `current_certificate` is part of the message signed by the multi-signature of the `current_certificate`
- **Step 6**: Retrieve the `previous_certificate` that has the hash `previous_hash`:
  - **Step 6.1**: If it is not a `genesis_certificate`:
    - **Step 6.1.1**: Verify (or fail) that the `previous_hash` of the `previous_certificate` is valid by computing it and comparing it with the `hash` field of the certificate:
    - **Step 6.1.2**: Verify the `current_avk`:
      - **Step 6.1.2.1**: If the `current_certificate` is the `first_certificate` of the epoch
        - **Step 6.1.2.1.1**: Verify (or fail) that the `current_avk` of the `current_certificate` is part of the message signed by the multi-signature of the `previous_certificate`
        - **Step 6.1.2.1.2**: Verify (or fail) that the `current_protocol_parameters` of the `current_certificate` is part of the message signed by the multi-signature of the `previous_certificate`
      - **Step 6.1.2.2**: Else verify (or fail) that the `current_avk` of the `current_certificate` is the same as the `current_avk` of the `previous_certificate`
    - **Step 6.1.3**: Verify (or fail) that the `multi_signature` of the `previous_certificate` is valid
    - **Step 6.1.4**: Use the `previous_certificate` as `current_certificate` and start again at **Step 2**
  - **Step 6.2**: If it is a `genesis_certificate`:
    - **Step 6.2.1**: Verify (or fail) that the `previous_hash` of the `previous_certificate` is valid by computing it and comparing it with the `hash` field of the certificate
    - **Step 6.2.2**: Verify (or fail) that the `current_epoch` of the `previous_certificate` is part of the message signed by the genesis_certificate of the `previous_certificate`
    - **Step 6.2.3**: Verify (or fail) that the `current_avk` of the `current_certificate` is part of the message signed by the genesis signature of the `previous_certificate`
    - **Step 6.2.4**: Verify (or fail) that the `current_protocol_parameters` of the `current_certificate` is part of the message signed by the genesis signature of the `previous_certificate`
    - **Step 6.2.5**: The certificate is valid (success).

:::tip

Steps 4 and 6.1.3 check that a certificate's multi-signature is valid. Mithril supports several ways to produce and verify this, see [aggregation flavors](./aggregation/).

:::

:::tip

The recursive SNARK aggregation flavor collapses this entire walk into a single check: verifying one recursive aggregate signature is equivalent to verifying the whole chain back to genesis. See [recursive SNARK](./aggregation/recursive-snark.md).

:::

## The certificate chains of multiple aggregators

A Mithril network can be served by several aggregators:

- The **leader aggregator** creates the genesis certificate and produces the first certificates of the chain
- A **follower aggregator** synchronizes the certificate chain of the leader aggregator, from its genesis certificate to its latest certificate, then produces its own certificates chained to the last synchronized certificate.

Each aggregator collects its own set of individual signatures, so different aggregators produce different certificates for the same message.
Their certificate chains share the synchronized certificates and then diverge, so the certificates of a network form a **tree of certificate chains**: each path from a certificate back to the genesis certificate, the root of the tree, is a valid certificate chain.

:::info

A client verifies a certificate chain in the same way whatever aggregator produced it: all the certificate chains of a network are validated with the same genesis verification key.

Read the [run a Mithril aggregator node](../../../manual/operate/run-aggregator-node.md) guide for more details about the leader and follower aggregators.

:::

## The certificate chain cache

Verifying a certificate chain requires downloading and verifying every certificate back to the genesis certificate.
A client that verifies certificates regularly verifies the same older certificates again and again.
The certificate chain cache stores the certificates of a verified chain so that the next verifications can reuse them.

The cache works as follows:

- Each certificate verified during a chain verification is **staged** in the cache
- The staged certificates are **committed** only once the whole chain is validated, so a failed verification never populates the cache
- The committed certificates are stored in a **space** bound to the genesis verification key that validated them, so a certificate is only reused by a client using the same genesis verification key
- A committed certificate **expires** after a delay (one week in the client CLI) and is then ignored.

As the certificate chains of a network share the certificates close to the genesis certificate, the certificates cached while verifying the chain of an aggregator are also reused when verifying the chain of another aggregator of the same network.

The cache supports two verification modes:

| Mode                      | Verification                                                                                          | Saving                                              |
| ------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| **FullVerification**      | The whole chain is verified back to the genesis certificate, cached certificates included             | Network round-trips only                            |
| **EarlyStopVerification** | The chain is verified until a cached certificate is reached, which is trusted without re-verification | Network round-trips and cryptographic verifications |

In the **EarlyStopVerification** mode, the certificate chained to a cached certificate is verified exactly as in the **FullVerification** mode.
A previous certificate is only trusted from the cache when it is identical to the certificate committed under its hash.

:::danger

The verification modes have a different security impact:

- **FullVerification**: the cache is never trusted, as every cached certificate is cryptographically re-verified.
  A tampered cache can make a verification fail, but can never make an invalid chain valid.
- **EarlyStopVerification**: the cache becomes part of the trust base of the client.
  Anyone able to write to the cache can make the client accept a certificate chain that does not link back to the genesis certificate.
  The storage of the cache must be protected against tampering (e.g., with restricted file permissions) and must never be shared with an untrusted party.

When the storage of the cache cannot be protected, use the **FullVerification** mode.

:::

:::note

The certificate chain cache is not intended to be used with the recursive SNARK aggregation flavor: the verification of a recursive aggregate signature already attests to the whole chain back to the genesis certificate, so there is no chain to walk and nothing to save.
Enabling the cache with this flavor is harmless.

:::

:::info

The certificate chain cache is an unstable feature, available in:

- The [Mithril client library](../../../manual/develop/nodes/mithril-client-library.md#certificate-chain-cache) with the `unstable` feature
- The [Mithril client CLI](../../../manual/develop/nodes/mithril-client.md#certificate-chain-cache) with the `--unstable` and `--use-certificate-chain-cache` options
- The [Mithril client WASM library](../../../manual/develop/nodes/mithril-client-library-wasm.md#certificate-chain-cache) with the `unstable` and `enable_certificate_chain_verification_cache` options.

:::
