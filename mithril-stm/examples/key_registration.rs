//! This example shows how Key Registration is held. It is not held by a single central party,
//! but instead by all the participants in the signature process. Contrarily to the full protocol
//! run presented in `tests/integration.rs`, we explicitly treat each party individually.
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use mithril_stm::{
    AggregateSignature, AggregateSignatureType, AncillaryGenesisData, AncillaryProofInput, Clerk,
    ClosedKeyRegistration, Initializer, KeyRegistration, MithrilMembershipDigest, Parameters,
    Stake, VerificationKeyProofOfPossessionForConcatenation,
};

type D = MithrilMembershipDigest;

fn main() {
    let nparties = 4;
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut msg = [0u8; 16];
    rng.fill_bytes(&mut msg);

    // Parameter and parties initialisation. This information is broadcast (or known) to all
    // participants.
    let params = Parameters {
        // Let's try with a quorum of 3
        k: 3,
        m: 10,
        // `phi_f` = 1, so that it always passes, for the purpose of the example
        phi_f: 1.0,
    };

    let mut total_stake: Stake = 0;
    let stakes = (0..nparties)
        .map(|_| {
            let stake = rng.next_u64() % 999;
            total_stake += stake;
            1 + stake
        })
        .collect::<Vec<_>>();

    // Each party generates their Stm keys
    let party_0_init = Initializer::new(params, stakes[0], &mut rng);
    let party_1_init = Initializer::new(params, stakes[1], &mut rng);
    let party_2_init = Initializer::new(params, stakes[2], &mut rng);
    let party_3_init = Initializer::new(params, stakes[3], &mut rng);

    // The public keys are broadcast. All participants will have the same keys.
    let parties_pks: Vec<VerificationKeyProofOfPossessionForConcatenation> = vec![
        party_0_init.get_verification_key_proof_of_possession_for_concatenation(),
        party_1_init.get_verification_key_proof_of_possession_for_concatenation(),
        party_2_init.get_verification_key_proof_of_possession_for_concatenation(),
        party_3_init.get_verification_key_proof_of_possession_for_concatenation(),
    ];

    // Now, each party generates their own KeyReg instance, and registers all other participating
    // parties. Once all parties are registered, the key registration is closed.
    let key_reg_0 = local_reg(&stakes, &parties_pks);
    let key_reg_1 = local_reg(&stakes, &parties_pks);
    let key_reg_2 = local_reg(&stakes, &parties_pks);
    let key_reg_3 = local_reg(&stakes, &parties_pks);

    // Now, with information of all participating parties (we can create the Merkle Tree), the
    // signers can be initialised.
    let party_0 = party_0_init.try_create_signer::<D>(&key_reg_0).unwrap();
    let party_1 = party_1_init.try_create_signer::<D>(&key_reg_1).unwrap();
    let party_2 = party_2_init.try_create_signer::<D>(&key_reg_2).unwrap();
    let party_3 = party_3_init.try_create_signer::<D>(&key_reg_3).unwrap();

    /////////////////////
    // operation phase //
    /////////////////////

    // Now an asynchronous phase begins. The signers no longer need to communicate among themselves
    // Given the parameters we've chosen, the signers will be eligible for all indices.
    let mut party_0_sigs = party_0
        .create_single_signature(&msg)
        .expect("Signers can sign all indices in this example");
    let mut party_1_sigs = party_1
        .create_single_signature(&msg)
        .expect("Signers can sign all indices in this example");
    let mut party_2_sigs = party_2
        .create_single_signature(&msg)
        .expect("Signers can sign all indices in this example");
    let mut party_3_sigs = party_3
        .create_single_signature(&msg)
        .expect("Signers can sign all indices in this example");

    // Parties must have signed all indices
    assert_eq!(party_0_sigs.get_concatenation_signature_indices().len(), 10);
    assert_eq!(party_1_sigs.get_concatenation_signature_indices().len(), 10);
    assert_eq!(party_2_sigs.get_concatenation_signature_indices().len(), 10);
    assert_eq!(party_3_sigs.get_concatenation_signature_indices().len(), 10);

    // Different combinations of signatures. Recall that we only need 3 signatures
    let temp_indices = &party_0_sigs.get_concatenation_signature_indices()[..2];
    party_0_sigs.set_concatenation_signature_indices(temp_indices);

    let temp_indices = &party_3_sigs.get_concatenation_signature_indices()[..2];
    party_3_sigs.set_concatenation_signature_indices(temp_indices);

    let complete_sigs_1 = vec![party_0_sigs.clone(), party_3_sigs.clone()];

    let temp_indices = &party_1_sigs.get_concatenation_signature_indices()[..5];
    party_1_sigs.set_concatenation_signature_indices(temp_indices);

    let temp_indices = &party_2_sigs.get_concatenation_signature_indices()[..5];
    party_2_sigs.set_concatenation_signature_indices(temp_indices);

    let complete_sigs_2 = vec![
        party_0_sigs.clone(),
        party_1_sigs.clone(),
        party_2_sigs.clone(),
        party_3_sigs.clone(),
    ];

    // The following is incomplete. While it has more than 3, it has a lot for the same index.
    let temp_indices = &party_1_sigs.get_concatenation_signature_indices()[..1];
    party_1_sigs.set_concatenation_signature_indices(temp_indices);

    let temp_indices = &party_2_sigs.get_concatenation_signature_indices()[..1];
    party_2_sigs.set_concatenation_signature_indices(temp_indices);

    let temp_indices = &party_3_sigs.get_concatenation_signature_indices()[..1];
    party_3_sigs.set_concatenation_signature_indices(temp_indices);

    let incomplete_sigs_3 = vec![party_0_sigs, party_1_sigs, party_2_sigs, party_3_sigs];

    let closed_registration = local_reg(&stakes, &parties_pks);
    let clerk = Clerk::new_clerk_from_closed_key_registration(&params, &closed_registration);

    // Now we aggregate the signatures
    let aggr_sig_type = AggregateSignatureType::Concatenation;
    let msig_1: AggregateSignature<MithrilMembershipDigest> = match clerk
        .aggregate_signatures_with_type(
            &complete_sigs_1,
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
        ) {
        Ok((s, _)) => s,
        Err(e) => {
            panic!("Aggregation failed: {e:?}")
        }
    };
    assert!(
        msig_1
            .verify(
                &msg,
                &clerk.compute_aggregate_verification_key(),
                &params,
                None,
                None,
            )
            .is_ok()
    );

    let msig_2: AggregateSignature<MithrilMembershipDigest> = match clerk
        .aggregate_signatures_with_type(
            &complete_sigs_2,
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
        ) {
        Ok((s, _)) => s,
        Err(e) => {
            panic!("Aggregation failed: {e:?}")
        }
    };
    assert!(
        msig_2
            .verify(
                &msg,
                &clerk.compute_aggregate_verification_key(),
                &params,
                None,
                None,
            )
            .is_ok()
    );

    let msig_3 = clerk.aggregate_signatures_with_type(
        &incomplete_sigs_3,
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
    );
    assert!(msig_3.is_err());
}

fn local_reg(
    ids: &[u64],
    pks: &[VerificationKeyProofOfPossessionForConcatenation],
) -> ClosedKeyRegistration {
    let mut local_keyreg = KeyRegistration::initialize();
    let params = Parameters {
        // Let's try with a quorum of 3
        k: 3,
        m: 10,
        // `phi_f` = 1, so that it always passes, for the purpose of the example
        phi_f: 1.0,
    };
    // data, such as the public key, stake and id.
    for (pk, _) in pks.iter().zip(ids.iter()) {
        local_keyreg
            .register(
                1,
                pk,
                #[cfg(feature = "future_snark")]
                None,
            )
            .unwrap();
    }
    local_keyreg.close_registration(&params).unwrap()
}
