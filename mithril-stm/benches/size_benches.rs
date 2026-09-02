use blake2::{Blake2b, digest::consts::U64};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rayon::iter::ParallelIterator;
use rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator};

use mithril_stm::{
    AggregateSignatureType, AncillaryGenesisData, AncillaryProofInput, Clerk, Initializer,
    KeyRegistration, MembershipDigest, MithrilMembershipDigest, Parameters, Signer,
    SingleSignature,
};

#[cfg(feature = "future_snark")]
use mithril_stm::MidnightPoseidonDigest;

fn size<D>(k: u64, m: u64, nparties: usize, hash_name: &str)
where
    D: MembershipDigest,
{
    println!("+-------------------+");
    println!("| Hash: {hash_name} |");
    println!("+-------------------+");
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut msg = [0u8; 16];
    rng.fill_bytes(&mut msg);

    let parties = (0..nparties).map(|_| 1 + (rng.next_u64() % 9999)).collect::<Vec<_>>();

    let mut ps: Vec<Initializer> = Vec::with_capacity(nparties);
    let params = Parameters { k, m, phi_f: 0.2 };

    let mut key_reg = KeyRegistration::initialize();
    for stake in parties {
        let p = Initializer::new(params, stake, &mut rng);
        key_reg
            .register(
                stake,
                &p.get_verification_key_proof_of_possession_for_concatenation(),
                #[cfg(feature = "future_snark")]
                p.schnorr_verification_key,
            )
            .unwrap();
        ps.push(p);
    }

    let closed_reg = key_reg.close_registration(&params).unwrap();

    let ps = ps
        .into_par_iter()
        .map(|p| p.try_create_signer(&closed_reg).unwrap())
        .collect::<Vec<Signer<D>>>();

    let sigs = ps
        .par_iter()
        .filter_map(|p| p.create_single_signature(&msg).ok())
        .collect::<Vec<SingleSignature>>();
    let clerk = Clerk::new_clerk_from_signer(&ps[0]);

    // Aggregate with random parties
    let aggr_sig_type = AggregateSignatureType::Concatenation;
    let (aggr, _ancillary_proof_output) = clerk
        .aggregate_signatures_with_type(
            &sigs,
            &msg,
            aggr_sig_type,
            AncillaryProofInput::new(
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
            ),
        )
        .unwrap();

    println!(
        "k = {} | m = {} | nr parties = {}; {} bytes",
        k,
        m,
        nparties,
        aggr.to_bytes()
            .expect("AggregateSignature serialization should not fail")
            .len(),
    );
}

/// Only for size benches. It only overrides the concatenation hash type.
#[derive(Clone, Debug, Default)]
pub struct MembershipDigestConcatenationHashU64 {}

impl MembershipDigest for MembershipDigestConcatenationHashU64 {
    type ConcatenationHash = Blake2b<U64>;
    #[cfg(feature = "future_snark")]
    type SnarkHash = MidnightPoseidonDigest;
}

fn main() {
    println!("+-------------------+");
    println!("|   Size of proofs  |");
    println!("+-------------------+");
    println!("| Results obtained by using the parameters suggested in paper.");
    println!("+-------------------+");

    let params: [(u64, u64, usize); 2] = [(445, 2728, 3000), (554, 3597, 3000)];
    for (k, m, nparties) in params {
        size::<MembershipDigestConcatenationHashU64>(k, m, nparties, "Blake2b 512");
        size::<MithrilMembershipDigest>(k, m, nparties, "Blake2b 256");
    }
    println!("+-------------------------+");
}
