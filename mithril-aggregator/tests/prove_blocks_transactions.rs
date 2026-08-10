use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use mithril_aggregator::{ServeCommandConfiguration, services::ProverService};
use mithril_common::{
    entities::{
        BlockNumber, BlockNumberOffset, BlockRange, CardanoBlocksTransactionsSigningConfig,
        ChainPoint, Epoch, ProtocolMessagePartKey, ProtocolParameters, SignedEntityType,
        SignedEntityTypeDiscriminants, SlotNumber, TimePoint,
    },
    temp_dir,
    test::{builder::MithrilFixtureBuilder, entities_extensions::BlockRangeTestExtension},
};
use mithril_protocol_config::model::{
    ConfigurationResolverFromMarkers, ProtocolConfigurationForEpoch,
};
use test_extensions::{
    ExpectedCertificate, ExpectedMetrics, RuntimeTester, utilities::get_test_dir,
};

use crate::test_extensions::AggregatorObserver;
use crate::test_extensions::utilities::{block_hash, tx_hash};

mod test_extensions;

#[tokio::test]
async fn prove_blocks_transactions() {
    let protocol_parameters = ProtocolParameters {
        k: 5,
        m: 150,
        phi_f: 0.95,
    };
    comment!(
        "Configure the tester to produce `CardanoBlocksTransactions` with a signing step \
        smaller than one block range (5 blocks)"
    );
    let configuration = ServeCommandConfiguration {
        signed_entity_types: Some(
            SignedEntityTypeDiscriminants::CardanoBlocksTransactions.to_string(),
        ),
        data_stores_directory: get_test_dir("prove_blocks_transactions"),
        ..ServeCommandConfiguration::new_sample(temp_dir!())
    };
    let protocol_configuration_markers = ConfigurationResolverFromMarkers::new(BTreeMap::from([(
        Epoch(0),
        ProtocolConfigurationForEpoch {
            protocol_parameters: protocol_parameters.clone(),
            enabled_signed_entity_types: BTreeSet::from([
                SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
            ]),
            cardano_transactions: None,
            cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(0),
                step: BlockNumber(5),
            }),
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
    let prover = tester.dependencies.prover_service.clone();

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

    // Lock all signed entity types except CardanoBlocksTransactions to limit the scope of the test
    for entity in SignedEntityTypeDiscriminants::all()
        .into_iter()
        .filter(|e| e != &SignedEntityTypeDiscriminants::CardanoBlocksTransactions)
    {
        tester.dependencies.signed_entity_type_lock.lock(entity).await;
    }

    comment!(
        "Increase the Cardano chain block number to 166; \
        the state machine should sign `CardanoBlocksTransactions` up to block 165 inclusive, \
        and all block ranges should be complete"
    );
    tester
        .increase_block_number_and_slot_number(66, SlotNumber(76), BlockNumber(166))
        .await
        .unwrap();
    cycle!(tester, "signing");
    tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
            signers,
        )
        .await
        .unwrap();

    comment!("The state machine should issue a certificate for `CardanoBlocksTransactions`");
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
            SignedEntityType::CardanoBlocksTransactions(
                Epoch(2),
                BlockNumber(165),
                BlockNumberOffset(0)
            ),
            ExpectedCertificate::genesis_identifier(Epoch(1)),
        )
    );

    cycle!(tester, "ready");

    get_verify_proofs_for_blocks_and_for_transactions(BlockNumber(165), &observer, &prover).await;

    comment!("Check that the database stored the last signed block range because it is complete");
    let last_stored_block_range = observer.list_stored_block_ranges().unwrap().pop().unwrap();
    assert_eq!(BlockRange::new(150, 165), last_stored_block_range);

    comment!(
        "Increase the Cardano chain block number to 188;\
        the state machine should sign `CardanoBlocksTransactions` up to block 185 inclusive, \
        and the last block range should remain incomplete"
    );
    tester
        .increase_block_number_and_slot_number(22, SlotNumber(98), BlockNumber(188))
        .await
        .unwrap();
    cycle!(tester, "signing");
    tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
            signers,
        )
        .await
        .unwrap();

    comment!("The state machine should issue a certificate for `CardanoBlocksTransactions`");
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
            SignedEntityType::CardanoBlocksTransactions(
                Epoch(2),
                BlockNumber(185),
                BlockNumberOffset(0)
            ),
            ExpectedCertificate::identifier(&SignedEntityType::CardanoBlocksTransactions(
                Epoch(2),
                BlockNumber(165),
                BlockNumberOffset(0)
            )),
        )
    );

    cycle!(tester, "ready");

    get_verify_proofs_for_blocks_and_for_transactions(BlockNumber(185), &observer, &prover).await;

    comment!(
        "Check that the database did not store the last block range because it is partial (block range 180..194 contains transactions only up to 185)"
    );
    let last_stored_block_range = observer.list_stored_block_ranges().unwrap().pop().unwrap();
    assert_eq!(BlockRange::new(165, 180), last_stored_block_range);

    assert_metrics_eq!(
        tester.metrics_verifier,
        ExpectedMetrics::new()
            .certificate_total(2)
            .artifact_cardano_blocks_transaction_total(2)
    );
}

async fn get_verify_proofs_for_blocks_and_for_transactions(
    signed_block_number: BlockNumber,
    observer: &Arc<AggregatorObserver>,
    prover: &Arc<dyn ProverService>,
) {
    comment!(
        "The state machine should have signed `CardanoBlocksTransactions` up to block {signed_block_number}"
    );
    let last_blocks_txs_snapshot = observer
        .get_last_cardano_blocks_transactions_snapshot()
        .await
        .unwrap();
    assert_eq!(
        last_blocks_txs_snapshot.artifact.block_number_signed,
        signed_block_number
    );

    comment!(
        "Get the proof for the last block at block number {signed_block_number} and verify it"
    );
    let last_block_hash = hex::encode(block_hash(*signed_block_number));
    let proof_for_last_block = prover
        .compute_blocks_proofs(
            last_blocks_txs_snapshot.artifact.block_number_signed,
            std::slice::from_ref(&last_block_hash),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(proof_for_last_block.blocks_hashes().any(|t| t == &last_block_hash));

    proof_for_last_block.verify().unwrap();

    comment!(
        "Get the proof for the last transaction at block number {signed_block_number} and verify it"
    );
    let last_transaction_hash = tx_hash(*signed_block_number, 1);
    let proof_for_last_transaction = prover
        .compute_transactions_proofs(
            last_blocks_txs_snapshot.artifact.block_number_signed,
            std::slice::from_ref(&last_transaction_hash),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        proof_for_last_transaction
            .transactions_hashes()
            .any(|t| t == &last_transaction_hash)
    );

    proof_for_last_transaction.verify().unwrap();

    comment!(
        "Check that the proof for the last block and the proof for the last transaction share the same Merkle root"
    );
    assert_eq!(
        proof_for_last_block.merkle_root(),
        proof_for_last_transaction.merkle_root()
    );

    comment!(
        "Get the certificate for `CardanoBlocksTransactions(BlockNumber({signed_block_number}))` and check that it matches the proof"
    );
    let proof_merkle_root = proof_for_last_transaction.merkle_root();
    let proof_certificate = observer.get_last_certificate().await.unwrap();
    assert_eq!(
        &last_blocks_txs_snapshot.certificate_id,
        &proof_certificate.hash
    );
    assert_eq!(
        proof_certificate
            .protocol_message
            .get_message_part(&ProtocolMessagePartKey::CardanoBlocksTransactionsMerkleRoot),
        Some(&proof_merkle_root),
        "The proof merkle root should match the one in the certificate"
    );
}
