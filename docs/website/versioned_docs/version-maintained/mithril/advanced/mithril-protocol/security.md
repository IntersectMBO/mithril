---
sidebar_position: 3
sidebar_label: Protocol security
---

# Protocol security

This document presents a comprehensive security analysis of Mithril, examining potential threats and the protocol’s defenses against various attack vectors. It starts with an overview of the STM protocol and the adversarial model, followed by an in-depth discussion of security measures against common cryptographic attacks. The document concludes with an analysis of parameter selection, highlighting trade-offs between security and efficiency through practical examples.

:::info

Protocol phases are described in more detail [here](./protocol.md#protocol-phases).

:::

## Adversarial model

The adversarial model specifies the capabilities and goals of potential attackers.
For Mithril, the following is considered:

- **Security assumptions**: the assumptions under which the security of Mithril is analyzed:
  - _Majority honest stake_: it is assumed that a majority of the stake is controlled by honest participants adhering to its rules
  - _Unique signature scheme_: the signature scheme ensures security by allowing only one valid signature per message for each verification key
  - _Random oracle model_: the analysis relies on secure hash functions, modeled as random oracles, to support specific security proofs
- **Security goals**:
  - _Integrity_: to ensure that only valid and legitimate participants can generate certificates and that these certificates accurately reflect the consensus of the stakeholders
  - _Resistance to attacks_: to ensure that protocol influence aligns with stake held, preventing adversaries from gaining control via multiple fake identities
  - _Forgery resistance_: to prevent the adversary from creating valid forged signatures or concatenated proofs, particularly those that could lead to double-spending or chain reorganization
  - _Long-range attack resistance_: to ensure that the old stake cannot be used to create an alternate certificate chain that could overwrite the current chain
- **Adversary capabilities**:
  - _Computational power_: the adversary may have significant computational resources but is assumed to be polynomially bounded (standard assumption in cryptographic protocols)
  - _Stake control_: the adversary may control a portion of the total stake in the system, potentially through collusion with other stakeholders or by compromising private keys
  - _Identity control_: the adversary may attempt to create multiple identities to gain influence in the protocol; however, the protocol assumes this is economically challenging due to the stake-proportional selection mechanism
  - _Forgery attempts_: the adversary may try to forge concatenated proofs or signatures, manipulate eligibility checks, or create alternate certificate chains using the old stake
- **Adversary goals**:
  - _Forge a certificate_: the adversary may attempt to generate a forged certificate by manipulating the signing process or controlling sufficient stake. A forged certificate would allow the adversary to falsely certify the information, compromising the protocol's integrity
  - _Prevent certificate production_: the adversary might attempt to prevent a certificate's legitimate production by disrupting eligible signers' participation or introducing conflicts that prevent successful aggregation. This could halt the certificate generation process
  - _Manipulate stake distribution or lottery mechanism_: the adversary may try to exploit the lottery mechanism by grinding attacks or manipulating the stake distribution to increase their chance of being selected. This could influence the certificate generation process.

## Honest majority in Mithril vs Cardano

The security of Mithril requires an **honest majority on both Mithril and Cardano**:

- Without an honest majority on Mithril, the **signing process** cannot be trusted
- Without an honest majority on Cardano, **what is being signed** cannot be trusted.

The two assumptions are similar but **separate**: an honest majority on Mithril is not automatically implied by an honest majority on Cardano. There are two reasons for this:

- **Higher threshold**: under current parameters, the majority required for Mithril ($60\%$) is higher than that required for Cardano (around $51\%$). This is unlikely to change even if the parameters are retuned
- **Voluntary participation**: SPOs may opt out of Mithril for their own reasons. As such, the SPO set of Mithril is a **subset** of Cardano's.

### Estimating the cost of a forgery attack

As an indication of the plausibility of the "Mithril has a $60\%$ honest majority" assumption, the table and chart below estimate, for a given **protocol participation**, the amount of ADA an adversary would need to control to reach $40\%$ of stake in Mithril (the **forgery threshold**).

Producing a forgery requires an adversary to control the following amount of ADA:

$$
\mathrm{ADA}_{\text{forgery}} = T_{\text{Mithril}} \times P \times \sum_{\text{SPO}} \mathrm{ADA}
$$

where:

- $T_\text{Mithril} = 40\%$ is the **Mithril forgery threshold**
- $P$ is the **protocol participation**, i.e. the fraction of total Cardano SPO stake registered in Mithril
- $\sum_\text{SPO} \mathrm{ADA}$ is the **total ADA held by Cardano SPOs**.

The chart below maps the **cost of a forgery attack** (red line and blue bars) against the **protocol participation**, both expressed as a percentage of the total Cardano SPO stake. The dashed green horizontal line marks the $40\%$ forgery threshold (the upper bound, reached only when participation is $100\%$):

<style>{`
.forgery-chart {
  padding-bottom: 3rem;
}
.forgery-chart svg {
  display: block;
  margin: 0 auto;
}
.forgery-chart .line-plot-2 {
  stroke-dasharray: 6 4;
}
`}</style>

<div className="forgery-chart" style={{textAlign: "center"}}>

```mermaid
---
config:
    xyChart:
        width: 700
        height: 400
        xAxis:
            labelPadding: 8
        yAxis:
            labelPadding: 8
    themeVariables:
        xyChart:
            plotColorPalette: "#1F77B4, #D62728, #2CA02C"
            backgroundColor: "transparent"
---
xychart-beta
    title "Cost of forgery attack vs Mithril participation"
    x-axis "Mithril participation (% of SPO stake)" [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    y-axis "Forgery cost (% of SPO stake)" 0 --> 50
    bar [4, 8, 12, 16, 20, 24, 28, 32, 36, 40]
    line [4, 8, 12, 16, 20, 24, 28, 32, 36, 40]
    line [40, 40, 40, 40, 40, 40, 40, 40, 40, 40]
```

</div>

A few reference points along this line:

| Mithril participation $P$ | Forgery cost (% of SPO stake) |
| ------------------------- | ----------------------------- |
| $25\%$                    | $10\%$                        |
| $50\%$                    | $20\%$                        |
| $75\%$                    | $30\%$                        |
| $100\%$                   | $40\%$                        |

The relationship is linear: **higher Mithril participation directly raises the cost of a forgery**, making the attack progressively more expensive as the protocol grows.

## Signature and proof integrity attacks

This section groups _concatenation forgery_ and _collusion_ attacks under signature and proof integrity attacks and discusses Mithril security regarding these attacks. Please see the Appendix for further details.

Concatenation forgery attacks involve an adversary attempting to forge a valid concatenated proof by manipulating or assembling parts of valid signatures from different contexts. Collusion attacks occur when multiple participants conspire to manipulate the system, potentially leading to consensus disruption or double-spending. Although these attacks differ in approach, they both target the protocol's signature and proof mechanisms.

### Mithril security mechanisms

1. **Contradiction soundness**:
   Mithril employs a concatenation-based proof system in which proofs are verified by checking the relation $R(x,w) = 1$
   - The key feature, contradiction soundness, ensures that any attempt to manipulate concatenated proofs results in contradictions
   - These contradictions are detectable by the verifier, thereby preventing the success of forgery attempts
   - Colluding participants cannot generate contradictory proofs without being detected, as the contradiction soundness feature makes it impossible to combine valid signatures from different contexts without producing inconsistencies
2. **Unique signature scheme**:
   - The unique signature scheme in Mithril guarantees that a verification key can produce only one valid signature $(\sigma)$ for any given message
   - This prevents adversaries from assembling multiple valid signatures into a forged concatenated proof
   - This unique signature property also restricts colluders, as they cannot produce multiple valid signatures for the same message using the same key. This ensures that even coordinated attempts to manipulate the signing process are thwarted
3. **Verification key and stake binding**:
   - Mithril binds each verification key to a specific stake
   - Only signatures associated with the valid and registered stake are considered during verification
   - This binding prevents adversaries from using unregistered or invalid keys to forge concatenated proofs
   - The same binding mechanism hinders collusion by ensuring that any signatures produced by colluders come from verifiably legitimate keys and stakes. This reduces the risk of colluders influencing the protocol with forged or manipulated signatures
4. **Threshold mechanism**:
   - Mithril requires a threshold number of signatures to create a valid multi-signature
   - This threshold mechanism ensures that colluders must control a significant portion of the network's stake to generate a valid signature
   - This makes large-scale collusion difficult and economically unfeasible
   - The threshold mechanism also indirectly supports resistance to concatenation forgery by ensuring that only a valid, sufficiently large group of participants can produce the required signatures for a valid proof
5. **Lottery mechanism and stake proportionality**:
   - The protocol uses a pseudorandom lottery mechanism to select signers based on their stake
   - This selection process is unpredictable and stake-proportional, making it challenging for colluding participants to ensure they are selected together
   - The proportionality of stake influence ensures fairness and security by requiring colluders to hold a large stake to affect outcomes significantly
   - While primarily aimed at preventing collusion, the lottery mechanism also reinforces security against forgery by ensuring that only legitimately selected participants contribute to the proof process
6. **Identity verification and protocol transparency**:
   - Mithril's identity verification process, using the $\mathcal{AVK}$ and $\mathcal{PoP}$, ensures that only legitimate participants with valid stake and keys can participate
   - The protocol's transparency allows for auditing and detecting irregularities, further deterring both forgery and collusion
   - By verifying identities and maintaining transparency, the protocol minimizes collusion and concatenation forgery risks
   - Any suspicious activity or irregular combination of signatures can be identified and addressed promptly.

Mithril’s security mechanisms are designed to resist both concatenation forgery and collusion attacks by leveraging contradiction soundness, a unique signature scheme, and strict identity verification processes. These defenses work together to ensure that any attempt to manipulate the protocol’s signatures or proofs, whether through forgery or collusion, will be detected and invalidated. By addressing these threats in a unified manner, Mithril maintains the integrity of its signature and proof processes, ensuring the overall security and robustness of the protocol.

## Identity and selection manipulation attacks

This section groups _grinding_ and _Sybil_ attacks under identity and selection manipulation attacks. Mithril’s security mechanisms are discussed in relation to these types of attacks. For further details, refer to the Appendix.

Grinding attacks involve an adversary manipulating cryptographic processes, such as key generation or stake distribution, to increase their chances of being selected as a validator. Sybil attacks, in contrast, involve creating multiple fake identities to gain disproportionate influence within the network. Both attacks undermine the protocol’s fairness and integrity, either by exploiting the selection process or overwhelming the network with fake participants.

### Mithril security mechanisms

1. **Robust randomness**:
   - Mithril utilizes cryptographic random number generators (RNGs) to ensure that the selection process for validators is both fair and unpredictable
   - The pseudorandom selection of participants is based on their stake, but the outcome is independent of the specifics of stake distribution
   - This randomness prevents an adversary from manipulating the process through key or stake grinding, as the probability of selection remains resistant to such exploitation
   - While primarily aimed at grinding, robust randomness also helps mitigate Sybil attacks by ensuring that even if multiple identities are created, the selection process remains fair and cannot be easily manipulated by simply increasing the number of identities
2. **Identity verification**:
   - During each epoch's registration process, participants must provide $\mathcal{PoP}$ to demonstrate control over the private key corresponding to their verification key
   - This requirement ensures that each identity in the protocol is backed by a legitimate cryptographic key, making it difficult for an adversary to create numerous fake identities without the corresponding cryptographic proof
   - $\mathcal{PoP}$ also plays a role in preventing grinding attacks, as it ties each registered identity to a verifiable cryptographic proof, preventing the adversary from easily generating or manipulating keys to increase their chances of selection
3. **Stake-proportional eligibility**:
   - In Mithril, the probability of being selected to sign is proportional to the participant's stake
   - This discourages the creation of multiple identities with small stake, as their collective influence remains limited
   - The protocol favors concentrated stake, making it economically impractical to launch a Sybil attack by spreading stake across many identities
   - The stake-proportional eligibility mechanism also counters grinding attacks, as generating multiple low-stake keys does not significantly increase the adversary's selection chances, ensuring that the selection process remains fair and stake-dependent
4. **Merkle tree and aggregate verification key**:
   - All registered public keys and their associated $\mathcal{PoP}$s are organized into a Merkle tree, with the root known as the $\mathcal{AVK}$
   - This structure ensures efficient and secure verification of each participant's identity
   - By verifying each identity against the $\mathcal{AVK}$, the protocol prevents the inclusion of fake or manipulated identities in the signing process
   - The Merkle tree structure ties participants' identities to their stake, ensuring eligibility determination is based on verified and legitimate identities
   - This mitigates both grinding and Sybil attacks by securing the verification process against manipulation
5. **Registration and epoch-based validation**:
   - Participants must register their stake and keys at the beginning of each epoch
   - This registration process, which includes verifying the participant's stake and associated $\mathcal{PoP}$, ensures that only active and valid participants can participate in the protocol
   - This mechanism prevents stale or fake identities from persisting across epochs without revalidation.

Mithril's security mechanisms are carefully designed to resist both grinding and Sybil attacks by employing robust randomness, thorough identity verification, and stake-proportional selection processes. These defenses work in tandem to ensure that the protocol remains secure against attempts to manipulate identity and selection mechanisms, whether through generating multiple keys or creating fake identities. By addressing these threats together, Mithril maintains the integrity and fairness of its consensus process, ensuring that only legitimate participants have influence over the network.

## Long range attacks

This section covers Mithril's security mechanisms against long range attacks. Please see the Appendix for further information.

Mithril is designed to safeguard the network against _long range attacks_, where an adversary attempts to exploit old, valid keys or stake to create an alternate certificate chain from a distant point in the past. These attacks can compromise the system's integrity by producing outdated or invalid certificates, undermining the current state. Mithril employs several mechanisms to counter this threat, ensuring the security and stability of the protocol.

#### Mithril security mechanisms

1. **Epoch-based checkpoints**:
   - Mithril divides the certificate chain into epochs, each serving as a natural checkpoint
   - At the end of every epoch, participants generate signatures that are aggregated into a certificate, which acts as a finalized record of the epoch's events
   - These epoch-based certificates ensure that the certificate chain's history is fixed and verifiable at regular intervals
   - This checkpoint system makes it highly difficult for an adversary to create a valid alternate certificate chain that diverges from the legitimate chain before the last checkpoint
   - Any attempt to do so would require reconstructing an entire epoch's worth of valid signatures, which is practically infeasible
2. **Finality of certificates**:
   - Once a certificate is generated and accepted for an epoch, it represents a finalized and irreversible protocol state
   - This strong notion of finality means that after a certificate is in place, it cannot be replaced or reorganized
   - This finality mechanism ensures that even if an adversary attempts to create an alternate chain, it will be rejected if it conflicts with finalized certificates
   - The protocol's design guarantees that once a state is finalized, it becomes a permanent part of the chain, protecting against reorganization attacks
3. **Stale stake invalidation**:
   - Mithril requires participants to register their stake and associated verification keys at the beginning of each epoch by providing $\mathcal{PoP}$
   - This process ensures that only current, active participants are included in the epoch
   - Stale stake (old, inactive keys) are effectively invalidated because they are not re-registered
   - If a participant fails to register for a new epoch, their previous $vk$ and stake are excluded from the new $\mathcal{AVK}$
   - This prevents using old keys to generate certificates for the current epoch, ensuring that only legitimate and active stake contributes to the protocol's security
4. **Robust randomness in eligibility**:
   - The selection of participants for signing certificates is determined by a pseudorandom process influenced by the current stake
   - This randomness ensures that the selection process is fair, secure, and unpredictable
   - Even if an adversary possesses old keys, they cannot predict or influence the selection process for the current epoch
   - This randomness makes it extremely difficult to manipulate the certificate creation process using outdated or compromised keys, further protecting the protocol against long range attacks.

Mithril employs a comprehensive set of mechanisms to protect against long range attacks, ensuring that the protocol remains secure even when faced with adversaries attempting to exploit old keys or stake. By integrating epoch-based checkpoints, certificate finality, stale stake invalidation, and robust randomness, Mithril ensures that the certificate chain remains intact and resistant to reorganization or manipulation, thereby maintaining the integrity and stability of the network.

## Appendices

### Concatenation forgery attacks

A concatenation forgery attack is a type of cryptographic attack in which an adversary attempts to forge a valid combined (or concatenated) proof or signature by manipulating or assembling parts of valid signatures or proofs from different sources. This type of attack is particularly relevant in protocols that involve aggregating or concatenating multiple cryptographic components to form a single composite proof or signature.
Consider a protocol where multiple participants sign different parts of a message, and these signatures are concatenated to form a final, unified signature. In a concatenation forgery attack, an adversary might try to:

- Collect valid signatures from different messages or contexts
- Reorder or selectively combine these signatures
- Present the manipulated result as a valid signature for a different message.

### Collusion attacks

Collusion attacks occur when multiple participants in a network conspire to manipulate the system for their collective benefit, undermining the consensus mechanism and potentially leading to issues like double-spending or undue network control.

Collusion involves two or more parties working together to achieve a shared malicious goal by manipulating the protocol's outcomes, such as block production or transaction validation. The attack aims to compromise the fairness and security of the network's consensus mechanism. Successful collusion can result in economic losses and weaken the network's security.

- _Double-spending_: colluders create a blockchain fork to spend the same assets multiple times
- _Validator collusion_: validators work together to control block validation, influencing consensus decisions
- _Majority stake collusion_: controlling a majority of the network’s stake to perform a '$51\%$ attack.'

### Grinding attacks

Grinding attacks in cryptography, particularly in PoS blockchains, involve an adversary manipulating the cryptographic process – such as key generation or stake distribution – to increase their chances of being selected as a validator. By generating multiple keys or adjusting their stake, the attacker seeks to gain an unfair advantage in the consensus mechanism.

- _Key grinding_: the adversary generates numerous cryptographic keys, selecting the most favorable ones in the context of eligibility or winning a lottery-based selection process
- _Stake grinding_: the adversary repeatedly modifies their stake (eg, by splitting it among multiple identities) to increase the probability of being chosen as a validator.

### Sybil attacks

A Sybil attack occurs when an attacker creates multiple fake identities within a decentralized network to gain undue influence or control. This undermines the network's integrity and fairness by centralizing power in the attacker's hands.

- The attacker generates many identities to appear as multiple independent participants
- These identities allow the attacker to disproportionately affect decisions, such as in blockchain consensus or online voting
- The attack weakens the decentralized nature of the network
- Ensuring strong, verifiable identities reduces the risk of fake accounts.

### Long range attacks

A long range attack in PoS blockchains involves an adversary using old, valid keys or stake to create an alternate blockchain starting from a distant point in the past. The attacker builds this alternative chain until it surpasses the length of the legitimate chain, potentially leading to a chain fork or takeover.

- Old keys/stake exploit previously valid, but now inactive, keys or stake
- The attacker creates a competing chain that eventually overtakes the current chain
- This can result in double spending or chain reorganization, undermining the network's integrity.

Long range attacks exploit the time-insensitivity of PoS systems, but these mitigation strategies help protect the network's security and stability.
