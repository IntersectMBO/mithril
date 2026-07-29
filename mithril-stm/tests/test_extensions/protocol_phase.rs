use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use rayon::prelude::*;

use mithril_stm::{
    AggregateSignature, AggregateSignatureType, AggregateVerificationKey, AncillaryGenesisData,
    AncillaryProofInput, AncillaryProofOutput, Clerk, Initializer, KeyRegistration,
    MithrilMembershipDigest, Parameters, Signer, SingleSignature, Stake, StmResult,
    VerificationKeyForConcatenation,
};

type D = MithrilMembershipDigest;

/// The result of the initialization phase of the STM protocol.
pub struct InitializationPhaseResult {
    pub signers: Vec<Signer<D>>,
    pub reg_parties: Vec<(VerificationKeyForConcatenation, Stake)>,
    pub initializers: Vec<Initializer>,
}

/// The result of the operation phase of the STM protocol.
pub struct OperationPhaseResult {
    pub msig: StmResult<(AggregateSignature<D>, AncillaryProofOutput)>,
    pub avk: AggregateVerificationKey<D>,
    pub sigs: Vec<SingleSignature>,
}

pub fn initialization_phase(
    nparties: usize,
    mut rng: ChaCha20Rng,
    params: Parameters,
) -> InitializationPhaseResult {
    let parties = (0..nparties).map(|_| 1 + (rng.next_u64() % 9999)).collect::<Vec<_>>();

    let mut key_reg = KeyRegistration::initialize();

    let mut initializers: Vec<Initializer> = Vec::with_capacity(nparties);

    let mut reg_parties: Vec<(VerificationKeyForConcatenation, Stake)> =
        Vec::with_capacity(nparties);

    for stake in parties {
        let p = Initializer::new(params, stake, &mut rng);
        let vk_pop = p.get_verification_key_proof_of_possession_for_concatenation();
        key_reg
            .register(
                stake,
                &vk_pop,
                #[cfg(feature = "future_snark")]
                p.schnorr_verification_key,
            )
            .unwrap();
        reg_parties.push((vk_pop.vk, stake));
        initializers.push(p);
    }

    let closed_reg = key_reg.close_registration(&params).unwrap();

    let signers = initializers
        .clone()
        .into_par_iter()
        .map(|p| p.try_create_signer::<D>(&closed_reg).unwrap())
        .collect::<Vec<Signer<D>>>();

    InitializationPhaseResult {
        signers,
        reg_parties,
        initializers,
    }
}

pub fn operation_phase(
    params: Parameters,
    signers: Vec<Signer<D>>,
    reg_parties: Vec<(VerificationKeyForConcatenation, Stake)>,
    msg: [u8; 32],
) -> OperationPhaseResult {
    let sigs = signers
        .par_iter()
        .filter_map(|p| p.create_single_signature(&msg).ok())
        .collect::<Vec<SingleSignature>>();

    let clerk = Clerk::new_clerk_from_signer(&signers[0]);
    let avk = clerk.compute_aggregate_verification_key();
    let aggr_sig_type = AggregateSignatureType::Concatenation;

    // Check all parties can verify every sig
    for (s, (vk, stake)) in sigs.iter().zip(reg_parties.iter()) {
        assert!(
            s.verify(
                &params,
                vk,
                stake,
                &avk,
                &msg,
                #[cfg(feature = "future_snark")]
                None,
            )
            .is_ok(),
            "Verification failed"
        );
    }

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
    let msig = clerk.aggregate_signatures_with_type(&sigs, &msg, aggr_sig_type, ancillary_input);

    OperationPhaseResult { msig, avk, sigs }
}
