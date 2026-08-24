---
sidebar_position: 1
sidebar_label: Concatenation
---

# Concatenation

The concatenation method for aggregating the signatures is the most straighforward one. It uses BLS signatures for its batching capability in order to have faster verification. The prover checks the validity of the signatures received and that they correctly won the lottery with their indices. It then verifies that the leaf does belong to the merkle tree using the merkle root and the merkle path. Finally, the prover selects exactly `k` valid signatures and packs them together in one structure to create the proof.

```mermaid
flowchart LR
    Sigs[Individual signer<br/>signatures] --> Loop

    subgraph Loop["Prover: Per signature received"]
        direction LR
        L["Check lottery won<br/>for the claimed index"]
        M["Check Merkle path<br/>membership under AVK"]
    end

    Loop --> Select["Select k valid<br/>signatures"]
    Select --> Proof(["Proof"])
```

## How the proof is verified

To verify the proof, a verifier does the same checks as the prover: that each of the `k `signatures won its lottery for the claimed index, and that each corresponding leaf belongs to the Merkle tree under the aggregate verification key. Since the signatures are BLS signatures, all `k` of them can be combined into a single aggregate signature and verified together in one check, rather than individually.

```mermaid
flowchart LR
    Proof(["Proof"]) --> Loop2

    subgraph Loop2["Verifier: Per signature in the proof"]
        direction LR
        L2["Check lottery won<br/>for the claimed index"]
        M2["Check Merkle path<br/>membership under AVK"]
    end

    Loop2 --> Batch["Combine k signatures into<br/>one aggregate signature"]
    Batch --> Verify["Verify the aggregate<br/>signature in one check"]
```
