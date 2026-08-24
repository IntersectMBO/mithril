---
sidebar_position: 1
sidebar_label: Protocol phases
---

# Protocol phases

:::info

Mithril is based on the research paper [Mithril: Stake-based Threshold Multisignatures](https://iohk.io/en/research/library/papers/mithril-stake-based-threshold-multisignatures/).

:::

:::info

You can interact with the **Mithril protocol** through the [protocol simulation](../../../manual/develop/protocol-simulation.md). This will help you understand participants' interactions, multi-signature creation, and the influence of protocol parameters.

:::

:::tip

For more information about the **Mithril network**, please see [architecture](../mithril-network/architecture.md) overview.

:::

## Introduction

The full details of the Mithril protocol are provided in the published paper. This section is a high-level description of
the protocol.

In a nutshell, Mithril is a signature scheme that generates a certificate to convince verifiers that a portion of the stake of a system has signed a message.

However, rather than taking the whole set of stakeholders, Mithril
'randomly' selects a subset of them, and requires a portion of that subset to provide a signature.

Mithril signers participate in a lottery that defines if they are entitled to sign a particular message.
The lottery winners can then sign the message. When there are enough signatures, a certificate can be computed.

## Protocol phases

The protocol has three phases:

1. **Protocol establishment phase** during which parameters are defined for Mithril participants and a set of _allowed signers_ is defined
2. **Initialization phase** during which Mithril nodes generate and exchange keys
3. **Operations phase** during which nodes sign and aggregate signatures of messages to produce certificates.

:::note[Note]

Note that all three phases require a set of parties (`P` in the paper) to be fixed. During the protocol establishment phase
three important parameters are generated:

- `m`: defines the number of lotteries that a single user can participate in to sign a message
- `k`: defines the required number of distinct lottery indices needed to create a valid multi-signature
- `phi_f` (as denoted in the library): defines the chance of a signer to win a lottery.

:::

To generate a valid signature for message `msg` using a Mithril signature, `k` valid signatures from the subset of signers are needed.

To this end, each player can participate in `m` lotteries to see if they win the right to sign the message.

If the player does not win a lottery, they cannot submit a signature.

If the player wins at least one of the lotteries, then they
can submit the corresponding signature/s to produce a valid certificate. The chance of winning the lottery is defined by a function over `phi_f`. The closer `phi_f` is to one, the higher the chance of winning.

Under specific parameters, a message may fail to get certified using Mithril. In such cases, when an insufficient number of signers win lotteries to create a valid certificate, adjustments can be made to the parameters.

### 1. Protocol establishment phase

- Choose/establish a prime order group to serve as the foundation for the multi-signature scheme
- _When implementing bulletproof_: generate a pseudo-random string, such as hashing unpredictable data from the net (eg, latest block's hash, stock market quotes)
- Upon request from a party, provide the parameters and a random string.

This setup phase must be done only once and is valid for as long as the same proof system (eg, the parameters might be statically baked into the various systems producing and consuming Mithril proofs).

Similarly, during the protocol establishment phase, the parameters `k`, `m` and `phi_f` are defined, as well as the set of allowed signers.

### 2. Initialisation phase

This phase includes both the actual initialization phase of each party and the registration of keys.

Firstly, the party retrieves the protocol parameters.

Next, they use the parameters to generate a new key pair of a verification key and a signing key, plus a proof of possession (PoP)
`κ`. The verification key and PoP are broadcast to all other parties for registration, which is expected to last for a limited period. An important difference between the implementation and the paper is that registration is not centralized in the 'idealized' manner described in the paper. Instead, all signers will register against all other signers. Thus
each signer will trace its own registration procedure. Together with other participants' keys, the stake of each
party is stored.

Then an aggregate verification key (`AVK` in the paper) is created from the registration material, in the form of a Merkle tree.

The key dissemination process can also occur on-chain, which is logical as it provides parties with assurances about the validity of keys and stake held by each participant.

This phase happens once for each _instance_ of the running protocol.

### 3. Operations phase

Operations run in cycles, where each cycle is triggered by a message (eg, a snapshot of the UTXO set) to sign for which
a quorum of `k` valid signatures must be submitted.

- Each party needs to check for eligibility to sign the message. They may be eligible to sign the same message more than once. This check is performed for `m` distinct indices. For every index, the signer evaluates a function (parameterized with `phi_f`) that takes its stake as input. If the result of the function is `SUCCESS`, then the signer is eligible to sign this message for the given index.

- For every valid signature, the party creates a proof (`π`) containing a signature of the message, verification key, stake, and paths of the party in the Merkle tree.

- Then, multiple signatures can be aggregated together to form a certificate (`τ`) by:

  - Verifying signatures from each party:
    - Checking the party is authorized to sign for the given index (using the same procedure as signing)
    - Checking the proof is valid which means:
      - Checking the evaluation threshold is correct for the party’s stake given the message, index, and signature
      - Checking the provided path exists in the aggregate keys' Merkle tree
      - Verifying the signature of the message is valid with respect to the verification key
  - Producing an aggregation key from all verification keys
  - Producing an aggregate signature from all signatures `μ`
  - Producing a proof using the aggregate keys, the message, and the vector of individual proofs from each party:
    - In the concatenation proof system, all these values are simply packed together to form the proof
    - In the case of _bulletproof_ system, a more compact proof is generated.

- Each certificate `τ` can be verified as valid for some message, using the known setup parameters to verify the certificate’s proof and then verifying the aggregate signatures and verification keys.

:::note[Note]

Note that if the individual signatures are broadcast to all parties, then each party can independently produce the certificates. In particular, the party that performs aggregation is not required to have any specific knowledge, nor it is assumed to be honest. This means that _any_ third party that has access to the individual signatures can perform the signature aggregation.

:::

:::tip

For more information about the **Mithril network**, see [architecture](../mithril-network/architecture.md) overview.

:::
