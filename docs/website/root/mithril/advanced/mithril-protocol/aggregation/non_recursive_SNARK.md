---
sidebar_position: 2
sidebar_label: Non-recursive SNARK
---

# Non-recursive SNARK

## Introduction

A [SNARK](../../../../glossary.md#snark) can be used to generate a succinct proof that a prover knows some signatures whose winning indices reach the threshold `k`. It lets a prover verify signatures and aggregate those verifications into a unique small proof. This proof can then be checked by a verifier, confirming that all the aggregated signatures are valid and that they reach the threshold.

## The SNARK proof

To create a proof, one designs a circuit describing the relation to prove as constraints, for example that a signature is valid given a verification key. For Mithril, this means running the verification algorithm for each signature inside the circuit: checking its validity, confirming the signer's Merkle tree membership, and confirming its lottery win. To keep this efficient to prove, the signatures used are Schnorr signatures rather than BLS, and hashing uses SNARK-friendly Poseidon rather than Blake2b.

The prover selects enough valid signatures to reach the threshold `k`, and assembles them into a witness satisfying every constraint in the circuit. The resulting proof convinces a verifier that such a witness exists, without needing to reveal it: the verifier only needs this one small proof, not the signatures themselves.

```mermaid
flowchart LR
    AVK["AVK<br/>(public)"] --> Circuit
    MSG["Message<br/>(public)"] --> Circuit

    subgraph Circuit["Circuit: Per witness entry (k times)"]
        direction LR
        W["Witness: verification key,<br/>Merkle path, signature, <br/>lottery index"] --> C1["Check lottery index bound"]
        W["Witness: verification key,<br/>Merkle path, signature, <br/>lottery index"] --> C2["Check Merkle path<br/>membership under AVK"]
        W["Witness: verification key,<br/>Merkle path, signature, <br/>lottery index"] --> C3["Check signature valid<br/>over the message"]
        W["Witness: verification key,<br/>Merkle path, signature, <br/>lottery index"] --> C4["Check lottery won<br/>for the claimed index"]
    end

    Circuit --> Proof(["Proof"])
```

## What the proof attests

Given the aggregate verification key for SNARK, the root of a [Merkle tree](../../../../glossary.md#merkle-tree) committing to the stake and verification key of every registered signer, and the message being certified, the proof attests that the prover knows `k` winning lottery entries such that, for each one:

- the signer's stake and verification key form a leaf of the Merkle tree with root `AVK`, attesting it is properly registered
- the signer's signature over the message is valid under that verification key
- the signer won its lottery for the claimed index
- all `k` claimed indices are distinct and within bounds, so no lottery win is counted twice.

These conditions are encoded in a circuit that generates the proof, and verifying the proof ensures all the conditions were met. If any conditions fails, verification fails. The circuit is publicly available, so anyone can check exactly which conditions it asserts.

## How the proof is verified

The proof is verifed using the verification algorithm. It needs:

- the proof
- the verification key of the circuit used to create the proof
- the `AVK`
- the message

The circuit's verification key is a fixed piece of data, derived from the circuit and a one-time trusted setup, that matches the protocol parameters (`k`, `m`, `phi_f`) used to produce the proof. It is fixed for a given circuit and publicly available. The `AVK` is the root of a Merkle tree that can be recomputed by any party with access to the list of signers. The message is what is signed by the signers, for example a Cardano database snapshot digest, a stake distribution, or a set of transactions.
