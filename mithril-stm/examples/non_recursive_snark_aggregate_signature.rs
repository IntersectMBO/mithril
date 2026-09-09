//! Aggregating and verifying an aggregate signature with the non-recursive SNARK proof system.
//!
//! This proof system is experimental. It is gated behind the `future_snark` feature and its API
//! may still change.
//!
//! The aggregate signature consists in a single succinct proof that the quorum was met, so a
//! verifier checks one proof rather than every individual signature. Unlike the recursive proof
//! system, each aggregate signature stands alone: nothing links it to the ones before it.
//!
//! Run it with:
//!
//! ```text
//! cargo run --release -p mithril-stm --example non_recursive_snark_aggregate_signature \
//!     --features future_snark,rustls
//! ```
//!
//! Expect about three and a half seconds and roughly 1.3 GB of peak memory once the trusted setup
//! is cached, measured on an Apple M4 Max with 16 cores and 48 GB of memory; the first run
//! additionally downloads that setup. The circuit keys are generated on each run, because the
//! example's parameters are sized so it can be run at all and its keys are therefore not the
//! production ones the key cache recognises. Verification is cheap by comparison and does not
//! download the full SRS: the KZG verifier parameters derived from the trusted setup are embedded
//! in the crate.
//!
//! The proof system is described at
//! <https://mithril.network/doc/mithril/advanced/mithril-protocol/aggregation/non-recursive-snark>.

use std::error::Error;

use rand_core::OsRng;
use sha2::{Digest, Sha256};

use mithril_stm::{
    AggregateSignatureType, AncillaryGenesisData, AncillaryProofInput, Clerk, Initializer,
    KeyRegistration, MithrilMembershipDigest, Parameters, Signer, SingleSignature, Stake,
};

type D = MithrilMembershipDigest;

const SIGNER_STAKES: [Stake; 4] = [1_000, 2_000, 3_000, 4_000];

fn main() -> Result<(), Box<dyn Error>> {
    // Not production parameters: they are small so the example is runnable, and `phi_f` of 1.0
    // makes every signer win every lottery index, so the quorum is always reached. A real deployment
    // sets it well below 1.0.
    let parameters = Parameters {
        k: 2,
        m: 100,
        phi_f: 1.0,
    };

    // Registration. Each signer contributes a Schnorr verification key alongside its concatenation
    // key; without them the clerk cannot produce SNARK proofs at all.
    let mut key_registration = KeyRegistration::initialize();
    let mut initializers = Vec::with_capacity(SIGNER_STAKES.len());
    for stake in SIGNER_STAKES {
        let initializer = Initializer::new(parameters, stake, &mut OsRng);
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

    // The SNARK proof systems sign a 32-byte digest rather than arbitrary bytes: the message is a
    // field element inside the circuit. In a node this is the hash of the protocol message.
    let message: [u8; 32] =
        Sha256::digest(b"the message this aggregate signature attests to").into();

    let signatures = signers
        .iter()
        .filter_map(|signer| signer.create_single_signature(&message).ok())
        .collect::<Vec<SingleSignature>>();

    // This proof system carries no state from one aggregate signature to the next, so the ancillary
    // input is empty and the aggregation never reads it.
    let ancillary_input = AncillaryProofInput::new(
        None,
        AncillaryGenesisData::new(Vec::new(), None, None),
        Vec::new(),
    );

    let (aggregate_signature, ancillary_output) = clerk.aggregate_signatures_with_type(
        &signatures,
        &message,
        AggregateSignatureType::Snark,
        ancillary_input,
    )?;

    // Verification needs the circuit's verifying key, which the aggregation returns as ancillary
    // verifier data, carried alongside the aggregate signature. No genesis key is involved: without
    // a chain there is nothing to anchor.
    aggregate_signature.verify(
        &message,
        &clerk.compute_aggregate_verification_key(),
        &parameters,
        ancillary_output.verifier_data().cloned(),
        None,
    )?;

    println!("aggregate signature produced and verified");

    Ok(())
}
