use std::time::Duration;

use anyhow::Context;

use mithril_cardano_node_internal_database::{
    digesters::{CardanoImmutableDigester, ImmutableDigester},
    test::DummyCardanoDb,
};
use mithril_common::{
    StdResult,
    entities::{
        CardanoDbBeacon, Epoch, ProtocolMessage, ProtocolMessagePartKey, ProtocolParameters,
        SignedEntityType, Signer,
    },
    messages::{RegisterSignatureMessageHttp, RegisterSignerMessage, SignedEntityTypeMessage},
    protocol::ToMessage,
    test::builder::{MithrilFixture, MithrilFixtureBuilder},
};

/// Generate signer data
pub fn generate_signer_data(
    number_of_signers: usize,
    protocol_parameters: ProtocolParameters,
) -> MithrilFixture {
    MithrilFixtureBuilder::default()
        .with_signers(number_of_signers)
        .with_protocol_parameters(protocol_parameters)
        .build()
}

/// Generate signer registration message
pub fn generate_register_signer_message(
    signers: &[Signer],
    epoch: Epoch,
) -> Vec<RegisterSignerMessage> {
    signers
        .iter()
        .cloned()
        .map(|signer| RegisterSignerMessage {
            epoch,
            party_id: signer.party_id,
            verification_key_for_concatenation: signer
                .verification_key_for_concatenation
                .to_json_hex()
                .unwrap(),
            verification_key_signature_for_concatenation: signer
                .verification_key_signature_for_concatenation
                .map(|k| k.to_json_hex().unwrap()),
            operational_certificate: signer
                .operational_certificate
                .map(|o| o.to_json_hex().unwrap()),
            kes_evolutions: signer.kes_evolutions,
            #[cfg(feature = "future_snark")]
            verification_key_for_snark: signer
                .verification_key_for_snark
                .map(|k| k.to_json_hex().unwrap()),
            #[cfg(feature = "future_snark")]
            verification_key_signature_for_snark: signer
                .verification_key_signature_for_snark
                .map(|s| s.to_json_hex().unwrap()),
        })
        .collect::<Vec<_>>()
}

/// Compute all signers single signatures for mithril stake distribution for the given fixture
pub async fn compute_mithril_stake_distribution_signatures(
    epoch: Epoch,
    signers_fixture: &MithrilFixture,
    timeout: Duration,
) -> StdResult<Vec<RegisterSignatureMessageHttp>> {
    spin_while_waiting!(
        {
            let signers_fixture = signers_fixture.clone();
            let signatures = tokio::task::spawn_blocking(move || -> Vec<_> {
                let mithril_stake_distribution_message = {
                    let mut message = ProtocolMessage::new();
                    message.set_message_part(
                        ProtocolMessagePartKey::NextAggregateVerificationKey,
                        signers_fixture
                            .compute_and_encode_concatenation_aggregate_verification_key(),
                    );
                    message.set_message_part(
                        ProtocolMessagePartKey::NextProtocolParameters,
                        signers_fixture.protocol_parameters().compute_hash(),
                    );
                    message
                        .set_message_part(ProtocolMessagePartKey::CurrentEpoch, epoch.to_string());

                    message
                };

                let signed_message = mithril_stake_distribution_message.to_message();
                signers_fixture
                    .sign_all(&mithril_stake_distribution_message)
                    .into_iter()
                    .map(|s| RegisterSignatureMessageHttp {
                        signed_entity_type: SignedEntityTypeMessage::Known(
                            SignedEntityType::MithrilStakeDistribution(epoch),
                        ),
                        party_id: s.party_id.clone(),
                        signature: s.signature.clone().to_json_hex().unwrap(),
                        won_indexes: s.won_indexes.clone(),
                        signed_message: signed_message.clone(),
                    })
                    .collect()
            })
            .await?;

            Ok(signatures)
        },
        timeout,
        "Compute signatures for MithrilStakeDistribution signed entity".to_string(),
        format!("Computing signatures timeout after {timeout:?}")
    )
}

/// Compute all signers single signatures for immutable files full for the given fixture
pub async fn compute_immutable_files_signatures(
    cardano_db: &DummyCardanoDb,
    epoch: Epoch,
    signers_fixture: &MithrilFixture,
    timeout: Duration,
) -> StdResult<(CardanoDbBeacon, Vec<RegisterSignatureMessageHttp>)> {
    spin_while_waiting!(
        {
            // Minus one because the last immutable isn't "finished"
            let immutable_file_number = cardano_db.last_immutable_number().unwrap() - 1;
            let beacon = CardanoDbBeacon::new(*epoch, immutable_file_number);
            let digester = CardanoImmutableDigester::new(None, slog_scope::logger());
            let merkle_tree = digester
                .compute_merkle_tree(cardano_db.get_immutable_dir(), &beacon)
                .await
                .with_context(|| {
                    format!(
                        "Payload Builder can not compute digest of '{}'",
                        cardano_db.get_immutable_dir().display()
                    )
                })?;
            let merkle_root = merkle_tree.compute_root()?.to_hex();
            let signers_fixture = signers_fixture.clone();

            let signatures = tokio::task::spawn_blocking(move || -> Vec<_> {
                let cardano_immutable_files_full_message = {
                    let mut message = ProtocolMessage::new();
                    message.set_message_part(
                        ProtocolMessagePartKey::CardanoDatabaseMerkleRoot,
                        merkle_root,
                    );
                    message.set_message_part(
                        ProtocolMessagePartKey::NextAggregateVerificationKey,
                        signers_fixture
                            .compute_and_encode_concatenation_aggregate_verification_key(),
                    );
                    message.set_message_part(
                        ProtocolMessagePartKey::NextProtocolParameters,
                        signers_fixture.protocol_parameters().compute_hash(),
                    );
                    message
                        .set_message_part(ProtocolMessagePartKey::CurrentEpoch, epoch.to_string());

                    message
                };

                let signed_message = cardano_immutable_files_full_message.to_message();
                signers_fixture
                    .sign_all(&cardano_immutable_files_full_message)
                    .into_iter()
                    .map(|s| RegisterSignatureMessageHttp {
                        signed_entity_type: SignedEntityTypeMessage::Known(
                            SignedEntityType::CardanoDatabase(CardanoDbBeacon::new(
                                *epoch,
                                immutable_file_number,
                            )),
                        ),
                        party_id: s.party_id.clone(),
                        signature: s.signature.clone().to_json_hex().unwrap(),
                        won_indexes: s.won_indexes.clone(),
                        signed_message: signed_message.clone(),
                    })
                    .collect()
            })
            .await?;

            Ok((beacon, signatures))
        },
        timeout,
        "Compute signatures for CardanoImmutableFiles signed entity".to_string(),
        format!("Computing signatures timeout after {timeout:?}")
    )
}
