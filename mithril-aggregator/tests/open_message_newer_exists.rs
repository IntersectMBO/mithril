mod test_extensions;

use std::collections::{BTreeMap, BTreeSet};

use mithril_aggregator::ServeCommandConfiguration;
use mithril_common::{
    entities::{
        BlockNumber, CardanoDbBeacon, ChainPoint, Epoch, ProtocolParameters, SignedEntityType,
        SignedEntityTypeDiscriminants, SlotNumber, StakeDistributionParty, TimePoint,
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

#[tokio::test]
async fn open_message_newer_exists() {
    let protocol_parameters = ProtocolParameters {
        k: 5,
        m: 150,
        phi_f: 0.95,
    };
    let configuration = ServeCommandConfiguration {
        data_stores_directory: get_test_dir("open_message_newer_exists"),
        signed_entity_types: Some(SignedEntityTypeDiscriminants::CardanoDatabase.to_string()),
        ..ServeCommandConfiguration::new_sample(temp_dir!())
    };
    let protocol_configuration_markers = ConfigurationResolverFromMarkers::new(BTreeMap::from([(
        Epoch(0),
        ProtocolConfigurationForEpoch {
            protocol_parameters: protocol_parameters.clone(),
            enabled_signed_entity_types: BTreeSet::from([
                SignedEntityTypeDiscriminants::CardanoDatabase,
            ]),
            cardano_blocks_transactions: None,
            cardano_transactions: None,
        },
    )]));
    let mut tester = RuntimeTester::build(
        TimePoint::new(
            1,
            1,
            ChainPoint::new(SlotNumber(10), BlockNumber(1), "block_hash-1"),
        ),
        configuration,
        protocol_configuration_markers,
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

    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new_genesis(
            Epoch(1),
            fixture.compute_and_encode_concatenation_aggregate_verification_key()
        )
    );

    comment!("Start the runtime state machine & register signers");
    cycle!(tester, "blocked-genesis-epoch");
    tester.register_signers(&fixture.signers_fixture()).await.unwrap();

    comment!("Increase epoch - state machine can now go to signing");
    tester.increase_epoch().await.unwrap();
    cycle!(tester, "idle");
    cycle!(tester, "ready");
    cycle!(tester, "signing");

    comment!("signers send their single signature");
    tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            &fixture.signers_fixture(),
        )
        .await
        .unwrap();

    comment!("The state machine should issue a certificate for the MithrilStakeDistribution");
    cycle!(tester, "ready");
    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new(
            Epoch(2),
            StakeDistributionParty::from_signers(fixture.signers_with_stake()).as_slice(),
            fixture.compute_and_encode_concatenation_aggregate_verification_key(),
            SignedEntityType::MithrilStakeDistribution(Epoch(2)),
            ExpectedCertificate::genesis_identifier(Epoch(1)),
        )
    );

    comment!(
        "The state machine should get back to signing to sign CardanoDatabase when a new immutable file exists"
    );
    tester.increase_immutable_number().await.unwrap();
    cycle!(tester, "signing");

    comment!(
        "The state machine should stay there as it is not able to create a certificate for the CardanoDatabase"
    );
    cycle_err!(tester, "signing");

    comment!("Increase the immutable file number");
    tester.increase_immutable_number().await.unwrap();
    cycle!(tester, "ready");

    comment!("The state machine should get back to signing to sign CardanoDatabase");
    cycle!(tester, "signing");
    let signers_for_immutables = &fixture.signers_fixture()[0..=6];
    tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::CardanoDatabase,
            signers_for_immutables,
        )
        .await
        .unwrap();

    comment!("The state machine should issue a certificate for the CardanoDatabase");
    cycle!(tester, "ready");
    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new(
            Epoch(2),
            &signers_for_immutables
                .iter()
                .map(|s| s.signer_with_stake.clone().into())
                .collect::<Vec<_>>(),
            fixture.compute_and_encode_concatenation_aggregate_verification_key(),
            SignedEntityType::CardanoDatabase(CardanoDbBeacon::new(2, 3)),
            ExpectedCertificate::identifier(&SignedEntityType::MithrilStakeDistribution(Epoch(2))),
        )
    );

    assert_metrics_eq!(
        tester.metrics_verifier,
        ExpectedMetrics::new()
            .certificate_total(2)
            .artifact_mithril_stake_distribution_total(1)
            .artifact_cardano_database_total(1)
    );
}
