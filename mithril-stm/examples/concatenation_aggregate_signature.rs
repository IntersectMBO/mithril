//! Aggregating and verifying an aggregate signature with the concatenation proof system.
//!
//! This proof system is stable, needs no feature flag, and is the one currently used by the Mithril
//! network. Verification needs no trusted setup: it checks BLS signatures and a Merkle path against
//! the signer-set commitment, with no circuit and no ceremony-derived parameters. The cost is size:
//! the aggregate signature carries one entry per contributing signer, together covering at least
//! the `k` winning lottery indices the quorum requires, plus a Merkle path batched across those
//! signers.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p mithril-stm --example concatenation_aggregate_signature
//! ```
//!
//! It takes well under a second and needs no special hardware, which is why it is the one example
//! that also runs as a documentation test.

use std::error::Error;

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rayon::prelude::*;

use mithril_stm::{
    AggregateSignatureType, AncillaryGenesisData, AncillaryProofInput, Clerk, Initializer,
    KeyRegistration, MithrilMembershipDigest, Parameters, Signer, SingleSignature,
};

type D = MithrilMembershipDigest;

const SIGNER_COUNT: usize = 32;

fn main() -> Result<(), Box<dyn Error>> {
    // Seeded so the example produces the same aggregate signature on every run, which keeps it
    // documentation. Never generate real key material from a fixed seed.
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let parameters = Parameters {
        k: 357,
        m: 2642,
        phi_f: 0.2,
    };

    let mut message = [0u8; 16];
    rng.fill_bytes(&mut message);

    // Registration. Every signer publishes its verification key and stake; closing the registration
    // fixes the signer set the aggregate signature will be verified against.
    let mut key_registration = KeyRegistration::initialize();
    let mut initializers: Vec<Initializer> = Vec::with_capacity(SIGNER_COUNT);
    for _ in 0..SIGNER_COUNT {
        let stake = 1 + (rng.next_u64() % 9999);
        let initializer = Initializer::new(parameters, stake, &mut rng);
        key_registration.register(
            initializer.stake,
            &initializer.get_verification_key_proof_of_possession_for_concatenation(),
            // The SNARK proof systems need a second key per signer; the concatenation one does not,
            // so this argument only exists when the feature is enabled.
            #[cfg(feature = "future_snark")]
            initializer.get_verification_key_for_snark(),
        )?;
        initializers.push(initializer);
    }
    let closed_registration = key_registration.close_registration(&parameters)?;

    let signers = initializers
        .into_par_iter()
        .map(|initializer| initializer.try_create_signer(&closed_registration))
        .collect::<Result<Vec<Signer<D>>, _>>()?;

    // Each signer plays the lottery for every index and keeps the ones it wins. A signer that wins
    // nothing simply produces no signature.
    let signatures = signers
        .par_iter()
        .filter_map(|signer| signer.create_single_signature(&message).ok())
        .collect::<Vec<SingleSignature>>();

    let first_signer = signers.first().ok_or("the example registers at least one signer")?;
    let clerk = Clerk::new_clerk_from_signer(first_signer);
    let aggregate_verification_key = clerk.compute_aggregate_verification_key();

    // This proof system carries no state from one aggregate signature to the next, so the ancillary
    // input is empty and the aggregation never reads it.

    let ancillary_input = AncillaryProofInput::new(
        None,
        AncillaryGenesisData::new(
            #[cfg(feature = "future_snark")]
            Vec::new(),
            #[cfg(feature = "future_snark")]
            None,
            #[cfg(feature = "future_snark")]
            None,
        ),
        #[cfg(feature = "future_snark")]
        Vec::new(),
    );

    let (aggregate_signature, ancillary_output) = clerk.aggregate_signatures_with_type(
        &signatures,
        &message,
        AggregateSignatureType::Concatenation,
        ancillary_input,
    )?;

    aggregate_signature.verify(
        &message,
        &aggregate_verification_key,
        &parameters,
        ancillary_output.verifier_data().cloned(),
        None,
    )?;

    println!("aggregate signature produced and verified");

    Ok(())
}
