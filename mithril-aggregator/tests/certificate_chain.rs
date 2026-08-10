mod test_extensions;

use std::collections::{BTreeMap, BTreeSet};

use mithril_aggregator::ServeCommandConfiguration;
use mithril_common::{
    entities::{
        BlockNumber, CardanoDbBeacon, ChainPoint, Epoch, ProtocolParameters, SignedEntityType,
        SignedEntityTypeDiscriminants, SlotNumber, StakeDistribution, StakeDistributionParty,
        TimePoint,
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
async fn certificate_chain() {
    let protocol_parameters = ProtocolParameters {
        k: 5,
        m: 100,
        phi_f: 0.95,
    };
    let configuration = ServeCommandConfiguration {
        data_stores_directory: get_test_dir("certificate_chain"),
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
    let observer = tester.observer.clone();

    comment!("Create signers & declare stake distribution");
    let initial_fixture = MithrilFixtureBuilder::default()
        .with_signers(5)
        .with_protocol_parameters(protocol_parameters.clone())
        .build();
    let signers = initial_fixture.signers_fixture();
    tester.init_state_from_fixture(&initial_fixture).await.unwrap();
    let mut current_epoch = observer.current_epoch().await;

    comment!("Bootstrap the genesis certificate, {:?}", current_epoch);
    tester.register_genesis_certificate(&initial_fixture).await.unwrap();

    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new_genesis(
            Epoch(1),
            initial_fixture.compute_and_encode_concatenation_aggregate_verification_key()
        )
    );

    comment!("Start the runtime state machine & register signers");
    cycle!(tester, "blocked-genesis-epoch");
    tester.register_signers(&signers).await.unwrap();

    comment!("Increase epoch - state machine can now go to signing");
    tester.increase_epoch().await.unwrap();
    cycle!(tester, "idle");
    cycle!(tester, "ready");
    cycle!(tester, "signing");
    tester.register_signers(&signers).await.unwrap();
    cycle_err!(tester, "signing");
    tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            &signers,
        )
        .await
        .unwrap();

    comment!("The state machine should issue a certificate for the MithrilStakeDistribution");
    cycle!(tester, "ready");
    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new(
            Epoch(2),
            StakeDistributionParty::from_signers(initial_fixture.signers_with_stake()).as_slice(),
            initial_fixture.compute_and_encode_concatenation_aggregate_verification_key(),
            SignedEntityType::MithrilStakeDistribution(Epoch(2)),
            ExpectedCertificate::genesis_identifier(Epoch(1)),
        )
    );

    comment!("The state machine should get back to signing to sign CardanoDatabase");
    cycle!(tester, "signing");
    tester
        .send_single_signatures(SignedEntityTypeDiscriminants::CardanoDatabase, &signers)
        .await
        .unwrap();
    comment!("The state machine should issue a certificate for the CardanoDatabase");
    cycle!(tester, "ready");
    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new(
            Epoch(2),
            StakeDistributionParty::from_signers(initial_fixture.signers_with_stake()).as_slice(),
            initial_fixture.compute_and_encode_concatenation_aggregate_verification_key(),
            SignedEntityType::CardanoDatabase(CardanoDbBeacon::new(2, 1)),
            ExpectedCertificate::identifier(&SignedEntityType::MithrilStakeDistribution(Epoch(2))),
        )
    );

    comment!(
        "Increase immutable number to do a second CardanoDatabase certificate for this epoch, {:?}",
        current_epoch
    );
    tester.increase_immutable_number().await.unwrap();
    cycle!(tester, "signing");
    tester
        .send_single_signatures(SignedEntityTypeDiscriminants::CardanoDatabase, &signers)
        .await
        .unwrap();
    cycle!(tester, "ready");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new(
            Epoch(2),
            StakeDistributionParty::from_signers(initial_fixture.signers_with_stake()).as_slice(),
            initial_fixture.compute_and_encode_concatenation_aggregate_verification_key(),
            SignedEntityType::CardanoDatabase(CardanoDbBeacon::new(2, 2)),
            ExpectedCertificate::identifier(&SignedEntityType::MithrilStakeDistribution(Epoch(2))),
        )
    );

    comment!("Change stake distribution");
    let next_fixture = {
        let updated_stake_distribution = StakeDistribution::from_iter(
            initial_fixture
                .signers_with_stake()
                .into_iter()
                .enumerate()
                .map(|(i, s)| (s.party_id, s.stake + (i as u64) * 1000)),
        );

        tester
            .update_stake_distribution(updated_stake_distribution)
            .await
            .unwrap()
    };
    let next_signers = next_fixture.signers_fixture();

    comment!(
        "Increase epoch, triggering stake distribution update, Next epoch: {:?}",
        current_epoch + 1
    );
    let new_epoch = tester.increase_epoch().await.unwrap();
    current_epoch = new_epoch;
    cycle!(tester, "idle");
    cycle!(tester, "ready");
    cycle!(tester, "signing");

    comment!(
        "Checking that no signers are registered for the next epoch since they did not register"
    );
    let next_epoch_verification_keys = tester
        .dependencies
        .verification_key_store
        .get_verification_keys(new_epoch.offset_to_recording_epoch())
        .await
        .expect("get_verification_keys should not fail");
    assert_eq!(
        None, next_epoch_verification_keys,
        "After a new epoch no signers should be registered for the next epoch"
    );

    comment!(
        "Signers register & send signatures, the new certificate should be link to the first of the previous epoch"
    );
    tester.register_signers(&next_signers).await.unwrap();
    tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            &signers,
        )
        .await
        .unwrap();
    cycle!(tester, "ready");
    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new(
            Epoch(3),
            StakeDistributionParty::from_signers(initial_fixture.signers_with_stake()).as_slice(),
            initial_fixture.compute_and_encode_concatenation_aggregate_verification_key(),
            SignedEntityType::MithrilStakeDistribution(Epoch(3)),
            ExpectedCertificate::identifier(&SignedEntityType::MithrilStakeDistribution(Epoch(2))),
        )
    );

    comment!(
        "Increase epoch & immutable, stake distribution updated at {} will now be signed into the certificate chain, allowing it to be used in the next epoch, Next epoch: {:?}",
        current_epoch,
        current_epoch + 1
    );
    current_epoch = tester.increase_epoch().await.unwrap();
    tester.increase_immutable_number().await.unwrap();
    cycle!(tester, "idle");
    cycle!(tester, "ready");
    tester.register_signers(&signers).await.unwrap();
    cycle!(tester, "signing");

    tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            &signers,
        )
        .await
        .unwrap();
    cycle!(tester, "ready");
    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new(
            Epoch(4),
            StakeDistributionParty::from_signers(initial_fixture.signers_with_stake()).as_slice(),
            initial_fixture.compute_and_encode_concatenation_aggregate_verification_key(),
            SignedEntityType::MithrilStakeDistribution(Epoch(4)),
            ExpectedCertificate::identifier(&SignedEntityType::MithrilStakeDistribution(Epoch(3))),
        )
    );

    comment!(
        "Increase epoch & immutable, stake distribution updated at {} should be signed in the new certificate, Next epoch: {:?}",
        current_epoch - 1,
        current_epoch + 1
    );
    current_epoch = tester.increase_epoch().await.unwrap();
    tester.increase_immutable_number().await.unwrap();
    cycle!(tester, "idle");
    cycle!(tester, "ready");
    tester.register_signers(&signers).await.unwrap();
    cycle!(tester, "signing");

    tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            &next_signers,
        )
        .await
        .unwrap();
    cycle!(tester, "ready");
    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new(
            Epoch(5),
            StakeDistributionParty::from_signers(next_fixture.signers_with_stake()).as_slice(),
            next_fixture.compute_and_encode_concatenation_aggregate_verification_key(),
            SignedEntityType::MithrilStakeDistribution(Epoch(5)),
            ExpectedCertificate::identifier(&SignedEntityType::MithrilStakeDistribution(Epoch(4))),
        )
    );

    comment!(
        "Increase immutable number to do a CardanoDatabase certificate for this epoch, {:?}",
        current_epoch
    );
    tester.increase_immutable_number().await.unwrap();
    cycle!(tester, "signing");

    tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::CardanoDatabase,
            &next_signers,
        )
        .await
        .unwrap();
    cycle!(tester, "ready");

    comment!(
        "A CardanoDatabase, linked to the MithrilStakeDistribution of the current epoch, should have been created, {:?}",
        current_epoch
    );
    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new(
            Epoch(5),
            StakeDistributionParty::from_signers(next_fixture.signers_with_stake()).as_slice(),
            next_fixture.compute_and_encode_concatenation_aggregate_verification_key(),
            SignedEntityType::CardanoDatabase(CardanoDbBeacon::new(5, 5)),
            ExpectedCertificate::identifier(&SignedEntityType::MithrilStakeDistribution(Epoch(5))),
        )
    );

    assert_metrics_eq!(
        tester.metrics_verifier,
        ExpectedMetrics::new()
            .certificate_total(7)
            .artifact_cardano_database_total(3)
            .artifact_mithril_stake_distribution_total(4)
    );
}
