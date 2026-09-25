mod test_extensions;

use std::collections::{BTreeMap, BTreeSet};

use mithril_aggregator::ServeCommandConfiguration;
use mithril_cardano_node_chain::chain_observer::ChainObserver;
use mithril_common::{
    current_function,
    entities::{
        BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
        CardanoTransactionsSigningConfig, ChainPoint, Epoch, ProtocolParameters,
        SignedEntityTypeDiscriminants, SlotNumber, TimePoint,
    },
    temp_dir,
    test::builder::{MithrilFixture, MithrilFixtureBuilder},
};
use mithril_protocol_config::model::{
    ConfigurationResolverFromMarkers, ProtocolConfigurationForEpoch,
};
use test_extensions::{ExpectedMetrics, RuntimeTester, utilities::get_test_dir};

#[tokio::test]
async fn leader_signed_entity_config_propagation() {
    let protocol_parameters = ProtocolParameters {
        k: 5,
        m: 150,
        phi_f: 0.95,
    };

    let allowed_discriminants_at_start: BTreeSet<_> = SignedEntityTypeDiscriminants::all()
        .difference(&BTreeSet::from([
            SignedEntityTypeDiscriminants::CardanoTransactions,
            SignedEntityTypeDiscriminants::CardanoBlocksTransactions,
        ]))
        .cloned()
        .collect();

    // First, start a runtime without the CardanoTransactions and CardanoBlocksTransactions signed entity
    // types but their configuration set to store them in the database and diffuse them.
    let start_configuration = ServeCommandConfiguration {
        signed_entity_types: Some(
            allowed_discriminants_at_start
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join(","),
        ),
        data_stores_directory: get_test_dir(current_function!()),
        ..ServeCommandConfiguration::new_sample(temp_dir!())
    };
    let protocol_configuration_markers = ConfigurationResolverFromMarkers::new(BTreeMap::from([(
        Epoch(0),
        ProtocolConfigurationForEpoch {
            protocol_parameters: protocol_parameters.clone(),
            enabled_signed_entity_types: SignedEntityTypeDiscriminants::all(),
            cardano_transactions: Some(CardanoTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(0),
                step: BlockNumber(30),
            }),
            cardano_blocks_transactions: Some(CardanoBlocksTransactionsSigningConfig {
                security_parameter: BlockNumberOffset(0),
                step: BlockNumber(30),
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
        start_configuration.clone(),
        protocol_configuration_markers.clone(),
    )
    .await;

    comment!("create signers & declare stake distribution");
    let fixture = MithrilFixtureBuilder::default()
        .with_signers(10)
        .with_protocol_parameters(protocol_parameters.clone())
        .build();

    tester.init_state_from_fixture(&fixture).await.unwrap();

    comment!("Bootstrap the genesis certificate");
    tester.register_genesis_certificate(&fixture).await.unwrap();

    comment!("Start the runtime state machine & register signers");
    cycle!(tester, "blocked-genesis-epoch");
    tester.register_signers(&fixture.signers_fixture()).await.unwrap();

    comment!("Epoch 2 - state machine can now go to signing");
    tester.increase_epoch().await.unwrap();
    cycle!(tester, "idle");
    cycle!(tester, "ready");

    avoid_epoch_gap_in_upcoming_epoch(&mut tester, &fixture).await;
    assert_signable_discriminants_eq!(tester, allowed_discriminants_at_start);

    comment!(
        "restart the runtime state machine but with all remaining signed entity types enabled and configured"
    );
    tester
        .rebuild(
            ServeCommandConfiguration {
                signed_entity_types: Some(
                    SignedEntityTypeDiscriminants::all()
                        .iter()
                        .map(|d| d.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ..start_configuration
            },
            protocol_configuration_markers,
        )
        .await;
    cycle!(tester, "ready");
    cycle!(tester, "signing");

    comment!(
        "The signable discriminants should be immediately available has its configuration was stored in database"
    );
    assert_signable_discriminants_eq!(tester, SignedEntityTypeDiscriminants::all());

    comment!("Epoch 3 - the signed entity should still be enabled ");
    tester.increase_epoch().await.unwrap();
    cycle!(tester, "idle");
    cycle!(tester, "ready");
    avoid_epoch_gap_in_upcoming_epoch(&mut tester, &fixture).await;

    assert_signable_discriminants_eq!(tester, SignedEntityTypeDiscriminants::all());

    assert_metrics_eq!(
        tester.metrics_verifier,
        ExpectedMetrics::new()
            .certificate_total(2)
            .artifact_mithril_stake_distribution_total(2)
    );
}

#[macro_export]
macro_rules! assert_signable_discriminants_eq {
    ($tester:expr, $expected_discriminants:expr) => {
        let expected = $expected_discriminants.clone().into_iter().collect::<BTreeSet<_>>();
        let discriminants = $tester
            .observer
            .list_signable_signed_entity_discriminants()
            .await
            .unwrap();
        assert_eq!(expected, discriminants);
    };
}

// Note: this method expects the state machine to be in the "ready" state
async fn avoid_epoch_gap_in_upcoming_epoch(
    mut tester: &mut RuntimeTester,
    fixture: &MithrilFixture,
) {
    let actual_epoch = tester.chain_observer.get_current_epoch().await.unwrap().unwrap();
    cycle!(tester, "signing");

    comment!("{actual_epoch:?} - register signers");
    tester.register_signers(&fixture.signers_fixture()).await.unwrap();
    comment!(
        "{actual_epoch:?} - Make a certificate to keep the state machine running without epoch gap"
    );
    tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            &fixture.signers_fixture(),
        )
        .await
        .unwrap();
    cycle!(tester, "ready");
}
