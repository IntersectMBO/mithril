mod test_extensions;

use std::collections::{BTreeMap, BTreeSet};

use mithril_aggregator::ServeCommandConfiguration;
use mithril_common::{
    current_function,
    entities::{
        BlockNumber, ChainPoint, Epoch, ProtocolParameters, SignedEntityType,
        SignedEntityTypeDiscriminants, SlotNumber, StakeDistributionParty, TimePoint,
    },
    temp_dir,
    test::builder::MithrilFixtureBuilder,
};
use mithril_protocol_config::model::{
    ConfigurationResolverFromMarkers, ProtocolConfigurationForEpoch,
};
use test_extensions::{ExpectedCertificate, RuntimeTester, utilities::get_test_dir};

#[tokio::test]
async fn follower_can_cycle_to_ready_to_signing_with_unknown_and_discontinued_signed_entity() {
    let protocol_parameters = ProtocolParameters {
        k: 5,
        m: 150,
        phi_f: 0.95,
    };
    let test_dir = get_test_dir(current_function!());
    let start_time_point = TimePoint {
        epoch: Epoch(1),
        immutable_file_number: 1,
        chain_point: ChainPoint {
            slot_number: SlotNumber(10),
            block_number: BlockNumber(100),
            block_hash: "block_hash-100".to_string(),
        },
    };
    let leader_configuration = ServeCommandConfiguration {
        data_stores_directory: test_dir.join("leader"),
        signed_entity_types: None,
        ..ServeCommandConfiguration::new_sample(temp_dir!())
    };
    let protocol_configuration_markers = ConfigurationResolverFromMarkers::new(BTreeMap::from([(
        Epoch(0),
        ProtocolConfigurationForEpoch {
            protocol_parameters: protocol_parameters.clone(),
            enabled_signed_entity_types: BTreeSet::from([
                SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            ]),
            cardano_transactions: None,
            cardano_blocks_transactions: None,
        },
    )]));
    let mut leader_tester = RuntimeTester::build(
        start_time_point.clone(),
        leader_configuration.clone(),
        protocol_configuration_markers.clone(),
    )
    .await;
    let leader_aggregator_http_server = leader_tester
        .build_leader_aggregator_http_server()
        .with_unknown_signed_entities_in_protocol_configuration()
        .with_discontinued_signed_entities_in_protocol_configuration()
        .spawn()
        .unwrap();

    let follower_configuration = ServeCommandConfiguration {
        data_stores_directory: test_dir.join("follower"),
        snapshot_directory: test_dir.join("follower/snapshot"),
        leader_aggregator_endpoint: Some(leader_aggregator_http_server.url().to_string()),
        ..leader_configuration
    };
    let mut follower_tester = RuntimeTester::build(
        start_time_point,
        follower_configuration,
        // Follower must retrieve parameters from the network configuration (today through the leader)
        // so this parameters should not be read
        ConfigurationResolverFromMarkers::new(BTreeMap::new()),
    )
    .await;

    comment!("create signers & declare stake distribution");
    let fixture = MithrilFixtureBuilder::default()
        .with_signers(10)
        .with_protocol_parameters(protocol_parameters.clone())
        .build();
    let signers = fixture.signers_fixture();

    leader_tester.init_state_from_fixture(&fixture).await.unwrap();
    follower_tester.init_state_from_fixture(&fixture).await.unwrap();

    comment!("Leader: bootstrap the genesis certificate");
    leader_tester.register_genesis_certificate(&fixture).await.unwrap();

    assert_last_certificate_eq!(
        leader_tester,
        ExpectedCertificate::new_genesis(
            Epoch(1),
            fixture.compute_and_encode_concatenation_aggregate_verification_key()
        )
    );

    comment!("Start the runtime state machine & register signers");
    cycle!(leader_tester, "blocked-genesis-epoch");
    leader_tester.register_signers(&signers).await.unwrap();
    cycle!(follower_tester, "blocked-genesis-epoch");

    comment!("Leader: Increase epoch");
    leader_tester.increase_epoch().await.unwrap();
    cycle!(leader_tester, "idle");
    cycle!(leader_tester, "ready");

    comment!(
        "Follower: change the epoch after leader created a certificate -- synchronise chain then sign"
    );
    follower_tester.increase_epoch().await.unwrap();
    cycle!(follower_tester, "idle");
    cycle!(follower_tester, "ready");
    cycle!(follower_tester, "signing");

    comment!("Follower: signers send their single signature");
    follower_tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            &signers,
        )
        .await
        .unwrap();
    cycle!(follower_tester, "ready");

    let expected_certificate = ExpectedCertificate::new(
        Epoch(2),
        StakeDistributionParty::from_signers(fixture.signers_with_stake()).as_slice(),
        fixture.compute_and_encode_concatenation_aggregate_verification_key(),
        SignedEntityType::MithrilStakeDistribution(Epoch(2)),
        ExpectedCertificate::genesis_identifier(Epoch(1)),
    );
    assert_last_certificate_eq!(follower_tester, expected_certificate);
}
