//! Aggregating and verifying aggregate signatures with the recursive SNARK proof system.
//!
//! This proof system is experimental. It is gated behind the `future_snark` feature and its API
//! may still change.
//!
//! Each aggregate signature carries one recursive proof attesting to the whole chain behind it, so
//! a verifier checks a single proof rather than every aggregate signature since genesis. This
//! example anchors a chain at genesis and advances it by two epochs, verifying each one as it goes.
//!
//! Run it with:
//!
//! ```text
//! cargo run --release -p mithril-stm --example recursive_snark_aggregate_signature \
//!     --features future_snark,rustls
//! ```
//!
//! Advancing an epoch proves the same circuit twice, under a different transcript each time. Only
//! the Blake2b proof travels with the aggregate signature, for a verifier to check; the Poseidon
//! proof stays with the prover, seeding the rolling state so the next step can verify it inside the
//! circuit. Anchoring at genesis costs one further Poseidon proof, so the two epochs below are five
//! proofs in all, which is most of what the run costs.
//!
//! Expect roughly four and a half minutes and about 12 GB of peak memory, measured on an Apple M4
//! Max with 16 cores and 48 GB of memory. That measurement had memory to spare; a machine with less
//! than the peak installed will page, and take correspondingly longer. The first run additionally
//! downloads the trusted setup. Every aggregation generates the circuit keys afresh, because the
//! example's parameters are sized so it can be run at all and its keys are therefore not the
//! production ones the key cache recognises.
//!
//! The signer seed below is published with this source and is therefore compromised. It is fixed
//! only so that a run this expensive behaves the same way every time, rather than depending on which
//! signers win the lottery. Never generate real key material from a fixed seed.

use std::error::Error;

use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, SeedableRng};
use sha2::{Digest, Sha256};

use mithril_stm::{
    AggregateSignatureType, AggregateVerificationKeyForSnark, AncillaryGenesisData,
    AncillaryProofInput, BaseFieldElement, Clerk, GenesisVerificationKeyBundle, Initializer,
    KeyRegistration, MithrilMembershipDigest, Parameters, SchnorrSigningKey,
    SchnorrVerificationKey, Signer, SingleSignature, Stake, circuits::halo2_ivc::PREIMAGE_SIZE,
};

type D = MithrilMembershipDigest;

const SIGNER_SEED: [u8; 32] = [0u8; 32];
const SIGNER_STAKES: [Stake; 4] = [1_000, 2_000, 3_000, 4_000];

/// Stands in for the snapshot each protocol message announces.
const SNAPSHOT_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Fills the protocol message's protocol-parameters slot: the hash a node computes for the
/// parameters below, which never change, so one value serves the whole chain.
const NEXT_PROTOCOL_PARAMETERS_HASH: [u8; 32] = [
    0x30, 0x6a, 0xd5, 0x96, 0x9f, 0xde, 0x8a, 0x09, 0x45, 0xf2, 0xf3, 0xcf, 0xe4, 0x53, 0x68, 0x85,
    0x45, 0xa3, 0x4e, 0x3a, 0xf7, 0xc5, 0x35, 0xef, 0xef, 0x94, 0x3f, 0x89, 0xb2, 0x14, 0x96, 0x15,
];

/// Assembles the protocol message preimage a step announces.
///
/// The layout is rigid: four labels at fixed offsets, each followed by a fixed-width slot. A node
/// builds this with `mithril_common::entities::ProtocolMessage::rigid_preimage`, which is the
/// canonical definition; it is reproduced here because `mithril-stm` cannot depend on the crate that
/// owns it.
fn build_protocol_message_preimage(
    aggregate_verification_key: &AggregateVerificationKeyForSnark<D>,
    epoch: u64,
) -> Result<[u8; PREIMAGE_SIZE], Box<dyn Error>> {
    // The digest slot commits to the message parts that are not rigid, hashed as label then value.
    let mut dynamic_parts = Sha256::new();
    dynamic_parts.update(b"snapshot_digest");
    dynamic_parts.update(SNAPSHOT_DIGEST.as_bytes());

    let mut preimage = Vec::with_capacity(PREIMAGE_SIZE);
    preimage.extend_from_slice(b"digest");
    preimage.extend_from_slice(&dynamic_parts.finalize());
    preimage.extend_from_slice(b"next_aggregate_verification_key");
    preimage.extend_from_slice(&aggregate_verification_key.to_rigid_slot_bytes()?);
    preimage.extend_from_slice(b"next_protocol_parameters");
    preimage.extend_from_slice(&NEXT_PROTOCOL_PARAMETERS_HASH);
    preimage.extend_from_slice(b"current_epoch");
    preimage.extend_from_slice(&epoch.to_le_bytes());

    Ok(preimage
        .try_into()
        .map_err(|_| "the preimage must be PREIMAGE_SIZE bytes")?)
}

fn main() -> Result<(), Box<dyn Error>> {
    // Not production parameters: they are small so the example is runnable.
    let parameters = Parameters {
        k: 2,
        m: 100,
        phi_f: 0.2,
    };

    // Registration. Each signer contributes a Schnorr verification key alongside its concatenation
    // key; without them the clerk cannot produce SNARK proofs at all.
    let mut rng = ChaCha20Rng::from_seed(SIGNER_SEED);
    let mut key_registration = KeyRegistration::initialize();
    let mut initializers = Vec::with_capacity(SIGNER_STAKES.len());
    for stake in SIGNER_STAKES {
        let initializer = Initializer::new(parameters, stake, &mut rng);
        key_registration.register(
            initializer.stake,
            &initializer.get_verification_key_proof_of_possession_for_concatenation(),
            initializer.get_verification_key_for_snark(),
        )?;
        initializers.push(initializer);
    }
    let closed_registration = key_registration.close_registration(&parameters)?;

    let signers = initializers
        .into_iter()
        .map(|initializer| initializer.try_create_signer(&closed_registration))
        .collect::<Result<Vec<Signer<D>>, _>>()?;
    let first_signer = signers.first().ok_or("the example registers at least one signer")?;
    let clerk = Clerk::new_clerk_from_signer(first_signer);

    let aggregate_verification_key = clerk.compute_aggregate_verification_key();
    let snark_aggregate_verification_key = aggregate_verification_key
        .to_snark_aggregate_verification_key()
        .ok_or("the registration carries Schnorr verification keys")?;

    // One protocol message per epoch, each announcing the signer set the next step is checked
    // against. Building them from the aggregate verification key computed above is what makes the
    // chain link up: the next-epoch step requires the commitment a message announces to be the one
    // the signer set produces.
    let protocol_message_preimages = [0u64, 1, 2]
        .map(|epoch| build_protocol_message_preimage(snark_aggregate_verification_key, epoch))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let genesis_protocol_message_preimage = &protocol_message_preimages[0];

    // The genesis attestation anchors the chain. It signs the genesis protocol message, and its
    // verification key is what a verifier trusts.
    let genesis_signing_key = SchnorrSigningKey::generate(&mut OsRng);
    let genesis_verification_key =
        SchnorrVerificationKey::new_from_signing_key(genesis_signing_key.clone());
    let genesis_message = BaseFieldElement::try_from(&genesis_protocol_message_preimage[..])?;
    let genesis_signature = genesis_signing_key.sign_standard(&[genesis_message], &mut OsRng)?;
    let genesis_verification_key_bundle =
        GenesisVerificationKeyBundle::new(genesis_verification_key);
    let genesis_data = AncillaryGenesisData::new(
        genesis_protocol_message_preimage.to_vec(),
        Some(genesis_signature),
        Some(genesis_verification_key),
    );

    // Advance the chain. The first step also bootstraps from genesis; each later step carries the
    // rolling state the previous one produced.
    let mut rolling_state = None;
    for (epoch, preimage) in protocol_message_preimages.iter().enumerate().skip(1) {
        // Signers sign the digest of the protocol message this step announces.
        let message: [u8; 32] = Sha256::digest(preimage).into();

        let signatures = signers
            .iter()
            .filter_map(|signer| signer.create_single_signature(&message).ok())
            .collect::<Vec<SingleSignature>>();

        let (aggregate_signature, ancillary_output) = clerk.aggregate_signatures_with_type(
            &signatures,
            &message,
            AggregateSignatureType::IvcSnark,
            AncillaryProofInput::new(rolling_state, genesis_data.clone(), preimage.to_vec()),
        )?;

        aggregate_signature.verify(
            &message,
            &aggregate_verification_key,
            &parameters,
            ancillary_output.verifier_data().cloned(),
            Some(genesis_verification_key_bundle.clone()),
        )?;

        rolling_state = Some(
            ancillary_output
                .prover_data()
                .cloned()
                .ok_or("a next-epoch step produces the rolling state the next step consumes")?,
        );

        println!("epoch {epoch}: aggregate signature produced and verified");
    }

    Ok(())
}
