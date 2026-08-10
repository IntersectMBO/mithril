mod test_extensions;

use std::collections::{BTreeMap, BTreeSet};

use mithril_aggregator::ServeCommandConfiguration;
use mithril_common::entities::SignerWithStake;
use mithril_common::temp_dir;
use mithril_common::{
    entities::{
        BlockNumber, ChainPoint, Epoch, ProtocolParameters, SignedEntityType,
        SignedEntityTypeDiscriminants, SlotNumber, StakeDistribution, StakeDistributionParty,
        TimePoint,
    },
    test::builder::MithrilFixtureBuilder,
};
use mithril_protocol_config::model::{
    ConfigurationResolverFromMarkers, ProtocolConfigurationForEpoch,
};
use test_extensions::ExpectedMetrics;
use test_extensions::{ExpectedCertificate, RuntimeTester, utilities::get_test_dir};

#[tokio::test]
async fn cardano_stake_distribution_verify_stakes() {
    let protocol_parameters = ProtocolParameters {
        k: 5,
        m: 150,
        phi_f: 0.95,
    };
    let configuration = ServeCommandConfiguration {
        signed_entity_types: Some(
            SignedEntityTypeDiscriminants::CardanoStakeDistribution.to_string(),
        ),
        data_stores_directory: get_test_dir("cardano_stake_distribution_verify_stakes"),
        ..ServeCommandConfiguration::new_sample(temp_dir!())
    };
    let protocol_configuration_markers = ConfigurationResolverFromMarkers::new(BTreeMap::from([(
        Epoch(0),
        ProtocolConfigurationForEpoch {
            protocol_parameters: protocol_parameters.clone(),
            enabled_signed_entity_types: BTreeSet::from([
                SignedEntityTypeDiscriminants::CardanoStakeDistribution,
            ]),
            cardano_blocks_transactions: None,
            cardano_transactions: None,
        },
    )]));
    let mut tester = RuntimeTester::build(
        TimePoint::new(
            2,
            1,
            ChainPoint::new(SlotNumber(10), BlockNumber(1), "block_hash-1"),
        ),
        configuration,
        protocol_configuration_markers,
    )
    .await;

    comment!("create signers & declare the initial stake distribution");
    let fixture = MithrilFixtureBuilder::default()
        .with_signers(5)
        .with_protocol_parameters(protocol_parameters.clone())
        .build();
    let signers = &fixture.signers_fixture();

    tester.init_state_from_fixture(&fixture).await.unwrap();

    comment!("Bootstrap the genesis certificate");
    tester.register_genesis_certificate(&fixture).await.unwrap();

    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new_genesis(
            Epoch(2),
            fixture.compute_and_encode_concatenation_aggregate_verification_key()
        )
    );

    comment!("Start the runtime state machine and register signers");
    cycle!(tester, "blocked-genesis-epoch");
    tester.register_signers(signers).await.unwrap();

    comment!("Increase epoch and register signers with a different stake distribution");
    tester.increase_epoch().await.unwrap();
    let signers_with_updated_stake_distribution = fixture
        .signers_with_stake()
        .iter()
        .map(|signer_with_stake| {
            SignerWithStake::from_signer(
                signer_with_stake.to_owned().into(),
                signer_with_stake.stake + 999,
            )
        })
        .collect::<Vec<_>>();
    tester
        .chain_observer
        .set_signers(signers_with_updated_stake_distribution)
        .await;
    cycle!(tester, "idle");
    cycle!(tester, "ready");
    cycle!(tester, "signing");
    tester.register_signers(signers).await.unwrap();
    tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            signers,
        )
        .await
        .unwrap();

    comment!("The state machine should issue a certificate for the MithrilStakeDistribution");
    cycle!(tester, "ready");
    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new(
            Epoch(3),
            StakeDistributionParty::from_signers(fixture.signers_with_stake()).as_slice(),
            fixture.compute_and_encode_concatenation_aggregate_verification_key(),
            SignedEntityType::MithrilStakeDistribution(Epoch(3)),
            ExpectedCertificate::genesis_identifier(Epoch(2)),
        )
    );

    comment!("Increase epoch and register signers with a different stake distribution");
    let signers_with_updated_stake_distribution = fixture
        .signers_with_stake()
        .iter()
        .map(|signer_with_stake| {
            SignerWithStake::from_signer(
                signer_with_stake.to_owned().into(),
                signer_with_stake.stake + 9999,
            )
        })
        .collect::<Vec<_>>();
    let updated_stake_distribution: StakeDistribution = signers_with_updated_stake_distribution
        .iter()
        .map(|s| (s.party_id.clone(), s.stake))
        .collect();
    tester
        .chain_observer
        .set_signers(signers_with_updated_stake_distribution)
        .await;
    tester.increase_epoch().await.unwrap();
    cycle!(tester, "idle");
    cycle!(tester, "ready");
    cycle!(tester, "signing");
    tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            signers,
        )
        .await
        .unwrap();

    comment!("The state machine should issue a certificate for the MithrilStakeDistribution");
    cycle!(tester, "ready");
    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new(
            Epoch(4),
            StakeDistributionParty::from_signers(fixture.signers_with_stake()).as_slice(),
            fixture.compute_and_encode_concatenation_aggregate_verification_key(),
            SignedEntityType::MithrilStakeDistribution(Epoch(4)),
            ExpectedCertificate::identifier(&SignedEntityType::MithrilStakeDistribution(Epoch(3))),
        )
    );

    cycle!(tester, "signing");
    tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::CardanoStakeDistribution,
            signers,
        )
        .await
        .unwrap();

    comment!("The state machine should issue a certificate for the CardanoStakeDistribution");
    cycle!(tester, "ready");
    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new(
            Epoch(4),
            StakeDistributionParty::from_signers(fixture.signers_with_stake()).as_slice(),
            fixture.compute_and_encode_concatenation_aggregate_verification_key(),
            SignedEntityType::CardanoStakeDistribution(Epoch(3)),
            ExpectedCertificate::identifier(&SignedEntityType::MithrilStakeDistribution(Epoch(4))),
        )
    );

    comment!("The message service should return the expected stake distribution");
    let message = tester
        .dependencies
        .message_service
        .get_cardano_stake_distribution_message_by_epoch(Epoch(3))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated_stake_distribution, message.stake_distribution);

    assert_metrics_eq!(
        tester.metrics_verifier,
        ExpectedMetrics::new()
            .certificate_total(3)
            .artifact_mithril_stake_distribution_total(2)
            .artifact_cardano_stake_distribution_total(1)
    );
}
