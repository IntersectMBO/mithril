use std::collections::{BTreeMap, BTreeSet};

use mithril_aggregator::ServeCommandConfiguration;
use mithril_common::{
    entities::{
        BlockNumber, BlockNumberOffset, CardanoTransactionsSigningConfig, ChainPoint, Epoch,
        ProtocolMessagePartKey, ProtocolParameters, SignedEntityType,
        SignedEntityTypeDiscriminants, SlotNumber, TimePoint,
    },
    temp_dir,
    test::builder::MithrilFixtureBuilder,
};
use mithril_protocol_config::model::{
    ConfigurationResolverFromMarkers, ProtocolConfigurationForEpoch,
};
use test_extensions::{
    ExpectedCertificate, ExpectedMetrics, RuntimeTester, utilities::get_test_dir,
};

use crate::test_extensions::utilities::tx_hash;

mod test_extensions;

#[tokio::test]
async fn prove_transactions() {
    let protocol_parameters = ProtocolParameters {
        k: 5,
        m: 150,
        phi_f: 0.95,
    };
    let configuration = ServeCommandConfiguration {
        signed_entity_types: Some(SignedEntityTypeDiscriminants::CardanoTransactions.to_string()),
        data_stores_directory: get_test_dir("prove_transactions"),
        ..ServeCommandConfiguration::new_sample(temp_dir!())
    };
    let protocol_configuration_markers = ConfigurationResolverFromMarkers::new(BTreeMap::from([(
        Epoch(0),
        ProtocolConfigurationForEpoch {
            protocol_parameters: protocol_parameters.clone(),
            enabled_signed_entity_types: BTreeSet::from([
                SignedEntityTypeDiscriminants::CardanoTransactions,
            ]),
            cardano_transactions: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(0),
                step: BlockNumber(30),
            }),
            cardano_blocks_transactions: None,
        },
    )]));
    let mut tester = RuntimeTester::build(
        TimePoint {
            epoch: Epoch(1),
            immutable_file_number: 1,
            chain_point: ChainPoint {
                slot_number: SlotNumber(10),
                block_number: BlockNumber(100),
                block_hash: "block_hash-100".to_string(),
            },
        },
        configuration,
        protocol_configuration_markers,
    )
    .await;
    let observer = tester.observer.clone();
    let prover = tester.dependencies.legacy_prover_service.clone();

    comment!("create signers & declare stake distribution");
    let fixture = MithrilFixtureBuilder::default()
        .with_signers(10)
        .with_protocol_parameters(protocol_parameters.clone())
        .build();
    let signers = &fixture.signers_fixture();

    tester.init_state_from_fixture(&fixture).await.unwrap();

    comment!("Bootstrap the genesis certificate");
    tester.register_genesis_certificate(&fixture).await.unwrap();

    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new_genesis(
            Epoch(1),
            fixture.compute_and_encode_concatenation_aggregate_verification_key()
        )
    );

    comment!("Start the runtime state machine & register signers");
    cycle!(tester, "blocked-genesis-epoch");
    tester.register_signers(signers).await.unwrap();

    comment!("Increase epoch - state machine can now go to signing");
    tester.increase_epoch().await.unwrap();
    cycle!(tester, "idle");
    cycle!(tester, "ready");

    // Lock all signed entity types except CardanoTransactions to limit the scope of the test
    for entity in SignedEntityTypeDiscriminants::all()
        .into_iter()
        .filter(|e| e != &SignedEntityTypeDiscriminants::CardanoTransactions)
    {
        tester.dependencies.signed_entity_type_lock.lock(entity).await;
    }

    comment!(
        "Increase cardano chain block number to 185, 
        the state machine should be signing CardanoTransactions up to block 179 included"
    );
    tester
        .increase_block_number_and_slot_number(85, SlotNumber(95), BlockNumber(185))
        .await
        .unwrap();
    cycle!(tester, "signing");
    tester
        .send_single_signatures(SignedEntityTypeDiscriminants::CardanoTransactions, signers)
        .await
        .unwrap();

    comment!("The state machine should issue a certificate for the CardanoTransactions");
    cycle!(tester, "ready");
    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new(
            Epoch(2),
            &signers
                .iter()
                .map(|s| s.signer_with_stake.clone().into())
                .collect::<Vec<_>>(),
            fixture.compute_and_encode_concatenation_aggregate_verification_key(),
            SignedEntityType::CardanoTransactions(Epoch(2), BlockNumber(179)),
            ExpectedCertificate::genesis_identifier(Epoch(1)),
        )
    );

    cycle!(tester, "ready");

    comment!("Get the proof for the last transaction, BlockNumber(179), and verify it");
    let last_transaction_hash = tx_hash(179, 1);
    let last_tx_snapshot = observer.get_last_cardano_transactions_snapshot().await.unwrap();
    let proof_for_last_transaction = prover
        .compute_transactions_proofs(
            last_tx_snapshot.artifact.block_number,
            std::slice::from_ref(&last_transaction_hash),
        )
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(
        proof_for_last_transaction
            .transactions_hashes()
            .contains(&last_transaction_hash)
    );

    proof_for_last_transaction.verify().unwrap();

    comment!(
        "Get the certificate associated with the last transaction and check that it matches the proof"
    );
    let proof_merkle_root = proof_for_last_transaction.merkle_root();
    let proof_certificate = observer.get_last_certificate().await.unwrap();
    assert_eq!(&last_tx_snapshot.certificate_id, &proof_certificate.hash);
    assert_eq!(
        proof_certificate
            .protocol_message
            .get_message_part(&ProtocolMessagePartKey::CardanoTransactionsMerkleRoot),
        Some(&proof_merkle_root),
        "The proof merkle root should match the one in the certificate"
    );

    assert_metrics_eq!(
        tester.metrics_verifier,
        ExpectedMetrics::new()
            .certificate_total(1)
            .artifact_cardano_transaction_total(1)
    );
}
