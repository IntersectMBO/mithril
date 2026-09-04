//! Aggregating and verifying certificates with the recursive SNARK proof system.
//!
//! Each certificate carries one recursive proof attesting to the whole chain behind it, so a
//! verifier checks a single proof rather than every certificate since genesis. This example anchors
//! a chain at genesis and advances it by two epochs, verifying each certificate as it goes.
//!
//! Run it with:
//!
//! ```text
//! cargo run --release -p mithril-stm --example recursive_snark_aggregate_signature \
//!     --features future_snark,rustls
//! ```
//!
//! Each step produces two proofs over the same circuit, under different transcripts. The Poseidon
//! one seeds the rolling state, so the following step can verify it inside the circuit; the Blake2b
//! one travels on the certificate for verifiers outside it. A step that stays within its epoch
//! produces only the Blake2b proof, since the chain state does not advance. Advancing two epochs
//! from genesis therefore generates five proofs, which is most of what the run below costs.
//!
//! Expect roughly four and a half minutes and about 12 GB of peak memory, measured on an Apple Mac
//! Studio; a machine with 16 GB of RAM will manage it, one with 8 GB will not. The first run
//! additionally downloads the trusted setup. Every aggregation generates the circuit keys afresh,
//! because the example's parameters are sized so it can be run at all and its keys are therefore not
//! the production ones the key cache recognises.
//!
//! The signer seed below is published with this source and is therefore compromised. It is fixed
//! only so the aggregate verification key is reproducible, which is what lets the committed protocol
//! messages stay valid; the genesis key is generated freshly on each run because nothing committed
//! here depends on it. Never generate real key material from a fixed seed.

use std::error::Error;

use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, SeedableRng};
use sha2::{Digest, Sha256};

use mithril_stm::{
    AggregateSignatureType, AncillaryGenesisData, AncillaryProofInput, BaseFieldElement, Clerk,
    GenesisVerificationKeyBundle, Initializer, KeyRegistration, MithrilMembershipDigest,
    Parameters, SchnorrSigningKey, SchnorrVerificationKey, Signer, SingleSignature, Stake,
    circuits::halo2_ivc::PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES,
};

type D = MithrilMembershipDigest;

/// The protocol messages the chain advances through, one per epoch. They are committed rather than
/// built here because assembling one needs the rigid protocol message format, which belongs to the
/// node rather than to this library. They were generated together with the key material below, and
/// the two must stay in step: each message announces the aggregate verification key that the next
/// certificate is checked against.
const GENESIS_PROTOCOL_MESSAGE_PREIMAGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/assets/genesis_protocol_message_preimage.bin"
));
const FIRST_CERTIFICATE_PROTOCOL_MESSAGE_PREIMAGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/assets/first_certificate_protocol_message_preimage.bin"
));
const SECOND_CERTIFICATE_PROTOCOL_MESSAGE_PREIMAGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/assets/second_certificate_protocol_message_preimage.bin"
));

const SIGNER_SEED: [u8; 32] = [0u8; 32];
const SIGNER_STAKES: [Stake; 4] = [1_000, 2_000, 3_000, 4_000];

fn main() -> Result<(), Box<dyn Error>> {
    // XXX: not production parameters. They are small so the example is runnable.
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

    // Fail early and clearly if the signer set no longer matches the committed messages: the
    // genesis message announces the aggregate verification key every later certificate is checked
    // against, so a mismatch would otherwise surface as an opaque rejection minutes into proving.
    // Divergence in the parameters or the stakes is caught later, by the proofs themselves.
    let announced_commitment =
        &GENESIS_PROTOCOL_MESSAGE_PREIMAGE[PREIMAGE_NEXT_MERKLE_TREE_COMMITMENT_BYTES];
    let rigid_slot = aggregate_verification_key
        .to_snark_aggregate_verification_key()
        .ok_or("the registration carries Schnorr verification keys")?
        .to_rigid_slot_bytes()?;
    if announced_commitment != &rigid_slot[..announced_commitment.len()] {
        return Err("the committed protocol messages do not describe this signer set".into());
    }

    // The genesis attestation anchors the chain. It signs the genesis protocol message, and its
    // verification key is what a verifier trusts.
    let genesis_signing_key = SchnorrSigningKey::generate(&mut OsRng);
    let genesis_verification_key =
        SchnorrVerificationKey::new_from_signing_key(genesis_signing_key.clone());
    let genesis_message = BaseFieldElement::try_from(GENESIS_PROTOCOL_MESSAGE_PREIMAGE)?;
    let genesis_signature = genesis_signing_key.sign_standard(&[genesis_message], &mut OsRng)?;
    let genesis_verification_key_bundle =
        GenesisVerificationKeyBundle::new(genesis_verification_key);
    let genesis_data = AncillaryGenesisData::new(
        GENESIS_PROTOCOL_MESSAGE_PREIMAGE.to_vec(),
        Some(genesis_signature),
        Some(genesis_verification_key),
    );

    // Advance the chain. The first step also bootstraps from genesis; each later step carries the
    // rolling state the previous one produced.
    let mut rolling_state = None;
    for preimage in [
        FIRST_CERTIFICATE_PROTOCOL_MESSAGE_PREIMAGE,
        SECOND_CERTIFICATE_PROTOCOL_MESSAGE_PREIMAGE,
    ] {
        // Signers sign the digest of the protocol message the certificate announces.
        let message: [u8; 32] = Sha256::digest(preimage).into();

        let signatures = signers
            .iter()
            .filter_map(|signer| signer.create_single_signature(&message).ok())
            .collect::<Vec<SingleSignature>>();

        let (certificate, ancillary_output) = clerk.aggregate_signatures_with_type(
            &signatures,
            &message,
            AggregateSignatureType::IvcSnark,
            AncillaryProofInput::new(rolling_state, genesis_data.clone(), preimage.to_vec()),
        )?;

        certificate.verify(
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

        println!("certificate aggregated and verified");
    }

    Ok(())
}
