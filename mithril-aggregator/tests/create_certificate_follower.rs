mod test_extensions;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ops::Range,
};

use mithril_aggregator::ServeCommandConfiguration;
use mithril_common::{
    entities::{
        BlockNumber, ChainPoint, Epoch, ProtocolParameters, SignedEntityType,
        SignedEntityTypeDiscriminants, SlotNumber, StakeDistributionParty, TimePoint,
    },
    temp_dir,
    test::{
        TempDir,
        builder::{MithrilFixture, MithrilFixtureBuilder, StakeDistributionGenerationMethod},
    },
};
use mithril_protocol_config::model::{
    ConfigurationResolverFromMarkers, ProtocolConfigurationForEpoch,
};
use test_extensions::{ExpectedCertificate, RuntimeTester, utilities::get_test_dir};

/// Epoch fixtures helps using the fixtures in the tests
struct EpochFixtures<'a> {
    /// The fixture used for the registration of signers of the epoch
    registering: &'a MithrilFixture,
    /// The fixture used for the signing of the epoch
    current_signing: Option<&'a MithrilFixture>,
    /// The fixture used for the signing of the following epoch
    next_signing: Option<&'a MithrilFixture>,
}

/// Epoch fixtures map builders
struct EpochFixturesMapBuilder;

impl EpochFixturesMapBuilder {
    fn build_fixtures_sequence(
        epochs_range: Range<usize>,
        protocol_parameters: ProtocolParameters,
    ) -> HashMap<Epoch, MithrilFixture> {
        epochs_range
            .map(|epoch| {
                (
                    Epoch(epoch as u64),
                    MithrilFixtureBuilder::default()
                        .with_signers(epoch)
                        .with_protocol_parameters(protocol_parameters.clone())
                        .with_stake_distribution(
                            StakeDistributionGenerationMethod::RandomDistribution {
                                seed: [epoch as u8; 32],
                                min_stake: 10,
                            },
                        )
                        .build(),
                )
            })
            .collect::<HashMap<_, _>>()
    }

    fn build_epoch_fixtures_map(
        fixtures: &HashMap<Epoch, MithrilFixture>,
    ) -> HashMap<Epoch, EpochFixtures<'_>> {
        fixtures
            .iter()
            .map(|(Epoch(index), _fixture)| {
                (
                    Epoch(*index),
                    EpochFixtures {
                        registering: &fixtures[&Epoch(*index)],
                        next_signing: index
                            .checked_sub(1)
                            .map(Epoch)
                            .and_then(|e| fixtures.get(&e)),
                        current_signing: index
                            .checked_sub(2)
                            .map(Epoch)
                            .and_then(|e| fixtures.get(&e)),
                    },
                )
            })
            .collect::<HashMap<_, _>>()
    }
}

#[tokio::test]
async fn create_certificate_follower() {
    let protocol_parameters = ProtocolParameters {
        k: 5,
        m: 150,
        phi_f: 0.95,
    };
    let fixtures =
        EpochFixturesMapBuilder::build_fixtures_sequence(1..6, protocol_parameters.clone());
    let epoch_fixtures_map = EpochFixturesMapBuilder::build_epoch_fixtures_map(&fixtures);
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
        data_stores_directory: get_test_dir("create_certificate_leader"),
        signed_entity_types: Some(
            SignedEntityTypeDiscriminants::CardanoStakeDistribution.to_string(),
        ),
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
    let mut leader_tester = RuntimeTester::build(
        start_time_point.clone(),
        leader_configuration.clone(),
        protocol_configuration_markers,
    )
    .await;
    let leader_aggregator_http_server =
        leader_tester.spawn_leader_aggregator_http_server().await.unwrap();

    let follower_configuration = ServeCommandConfiguration {
        data_stores_directory: get_test_dir("create_certificate_follower"),
        snapshot_directory: TempDir::create(
            "aggregator-integration",
            "create_certificate_follower",
        ),
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

    comment!(
        "Epoch 1:
    - the leader aggregator registers the first signers
    - the leader aggregator can't transition from 'Idle' to 'Ready'
    - the follower can't synchronize its chain with the leader aggregator
    - the follower aggregator can't transition from 'Idle' to 'Ready'
    "
    );
    let epoch_fixture = &epoch_fixtures_map[&Epoch(1)];

    comment!("Leader: update stake distribution source");
    leader_tester
        .update_stake_distribution(epoch_fixture.registering.stake_distribution())
        .await
        .unwrap();

    comment!("Follower: update stake distribution source");
    follower_tester
        .update_stake_distribution(epoch_fixture.registering.stake_distribution())
        .await
        .unwrap();

    comment!("Leader: start the runtime state machine");
    cycle!(leader_tester, "blocked-no-genesis");

    comment!("Follower: start the runtime state machine");
    cycle_err!(follower_tester, "idle");

    comment!("Leader: register signers");
    leader_tester
        .register_signers(&epoch_fixture.registering.signers_fixture())
        .await
        .unwrap();
    cycle!(leader_tester, "blocked-no-genesis");

    comment!(
        "Epoch 2:
    - the leader aggregator creates its genesis certificate
    - the leader aggregator can't transition from 'Idle' to 'Ready'
    - the follower aggregator can't transition from 'Idle' to 'Ready'
    "
    );
    let epoch_fixture = &epoch_fixtures_map[&Epoch(2)];

    comment!("Leader: update stake distribution source");
    leader_tester
        .update_stake_distribution(epoch_fixture.registering.stake_distribution())
        .await
        .unwrap();

    comment!("Follower: update stake distribution source");
    follower_tester
        .update_stake_distribution(epoch_fixture.registering.stake_distribution())
        .await
        .unwrap();

    comment!("Leader: change the epoch");
    leader_tester.increase_epoch().await.unwrap();
    cycle!(leader_tester, "idle");
    cycle!(leader_tester, "blocked-no-genesis");

    comment!("Follower: change the epoch after leader");
    follower_tester.increase_epoch().await.unwrap();
    cycle_err!(follower_tester, "idle");

    comment!("Leader: register signers");
    leader_tester
        .register_signers(&epoch_fixture.registering.signers_fixture())
        .await
        .unwrap();
    cycle!(leader_tester, "blocked-no-genesis");

    comment!("Leader: bootstrap the genesis certificate");
    leader_tester
        .register_genesis_certificate(epoch_fixture.next_signing.unwrap())
        .await
        .unwrap();

    assert_last_certificate_eq!(
        leader_tester,
        ExpectedCertificate::new_genesis(
            Epoch(2),
            epoch_fixture
                .next_signing
                .unwrap()
                .compute_and_encode_concatenation_aggregate_verification_key()
        )
    );

    comment!(
        "Epoch 3:
    - the leader aggregator produces a new certificate
    - the follower aggregator synchronizes signers from the leader aggregator
    - the follower synchronizes its chain with the leader aggregator
    - the follower aggregator can transition from 'Idle' to 'Ready'
    - the follower aggregator transition from 'Ready' to 'Signing(CardanoStakeDistribution)', skipping
    MithrilStakeDistribution
    "
    );
    let epoch_fixture = &epoch_fixtures_map[&Epoch(3)];

    comment!("Leader: update stake distribution source");
    leader_tester
        .update_stake_distribution(epoch_fixture.registering.stake_distribution())
        .await
        .unwrap();

    comment!("Follower: update stake distribution source");
    follower_tester
        .update_stake_distribution(epoch_fixture.registering.stake_distribution())
        .await
        .unwrap();

    comment!("Leader: change the epoch");
    leader_tester.increase_epoch().await.unwrap();
    cycle!(leader_tester, "idle");
    cycle!(leader_tester, "ready");
    cycle!(leader_tester, "signing");

    comment!("Leader: register signers");
    leader_tester
        .register_signers(&epoch_fixture.registering.signers_fixture())
        .await
        .unwrap();

    comment!("Leader: signers send their single signature");
    leader_tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            &epoch_fixture.current_signing.unwrap().signers_fixture(),
        )
        .await
        .unwrap();
    cycle!(leader_tester, "ready");

    comment!("Leader: state machine should issue a certificate for the MithrilStakeDistribution");
    cycle!(leader_tester, "signing");

    let expected_certificate_on_both_aggregator = ExpectedCertificate::new(
        Epoch(3),
        StakeDistributionParty::from_signers(
            epoch_fixture.current_signing.unwrap().signers_with_stake(),
        )
        .as_slice(),
        epoch_fixture
            .current_signing
            .unwrap()
            .compute_and_encode_concatenation_aggregate_verification_key(),
        SignedEntityType::MithrilStakeDistribution(Epoch(3)),
        ExpectedCertificate::genesis_identifier(Epoch(2)),
    );
    assert_last_certificate_eq!(leader_tester, expected_certificate_on_both_aggregator);
    cycle_err!(leader_tester, "signing");

    comment!(
        "Follower: change the epoch after leader created a certificate and synchronize certificate chain"
    );
    follower_tester.increase_epoch().await.unwrap();
    cycle!(follower_tester, "ready");
    assert_last_certificate_eq!(
        follower_tester, synchronized_from_leader => expected_certificate_on_both_aggregator
    );
    let current_msd_open_message = follower_tester
        .observer
        .get_current_open_message(SignedEntityTypeDiscriminants::MithrilStakeDistribution)
        .await
        .unwrap();
    assert!(
        current_msd_open_message
            .as_ref()
            .is_some_and(|m| m.epoch == 3 && m.is_certified),
        "Expected a certified OpenMessage for MithrilStakeDistribution, got:\n{current_msd_open_message:#?}"
    );

    comment!(
        "Follower: transition to 'Signing(CardanoStakeDistribution)' directly since a\
        OpenMessage for MithrilStakeDistribution was stored by the synchronizer"
    );
    cycle!(follower_tester, "signing");
    let current_csd_open_message = follower_tester
        .observer
        .get_current_open_message(SignedEntityTypeDiscriminants::CardanoStakeDistribution)
        .await
        .unwrap();
    assert!(
        current_csd_open_message
            .as_ref()
            .is_some_and(|m| m.epoch == 3 && !m.is_certified),
        "Expected a non-certified OpenMessage for CardanoStakeDistribution, got:\n{current_csd_open_message:#?}"
    );

    comment!(
        "Epoch 4:
    - the leader aggregator produces a new certificate
    - the follower aggregator synchronizes signers from the leader aggregator
    - the follower aggregator produces a new certificate
    - the follower aggregator new certificate uses the same avk as the leader aggregator's new certificate"
    );
    let epoch_fixture = &epoch_fixtures_map[&Epoch(4)];

    comment!("Leader: update stake distribution source");
    leader_tester
        .update_stake_distribution(epoch_fixture.registering.stake_distribution())
        .await
        .unwrap();

    comment!("Follower: update stake distribution source");
    follower_tester
        .update_stake_distribution(epoch_fixture.registering.stake_distribution())
        .await
        .unwrap();

    comment!("Leader: change the epoch");
    leader_tester.increase_epoch().await.unwrap();
    cycle!(leader_tester, "idle");
    cycle!(leader_tester, "ready");

    comment!("Follower: change the epoch after leader");
    follower_tester.increase_epoch().await.unwrap();
    cycle!(follower_tester, "idle");
    cycle!(follower_tester, "ready");

    comment!("Leader: register signers");
    leader_tester
        .register_signers(&epoch_fixture.registering.signers_fixture())
        .await
        .unwrap();
    cycle!(leader_tester, "signing");

    comment!("Leader: signers send their single signature");
    leader_tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            &epoch_fixture.current_signing.unwrap().signers_fixture(),
        )
        .await
        .unwrap();

    comment!("Leader: state machine should issue a certificate for the MithrilStakeDistribution");
    cycle!(leader_tester, "ready");

    let leader_expected_certificate = ExpectedCertificate::new(
        Epoch(4),
        StakeDistributionParty::from_signers(
            epoch_fixture.current_signing.unwrap().signers_with_stake(),
        )
        .as_slice(),
        epoch_fixture
            .current_signing
            .unwrap()
            .compute_and_encode_concatenation_aggregate_verification_key(),
        SignedEntityType::MithrilStakeDistribution(Epoch(4)),
        ExpectedCertificate::identifier(&SignedEntityType::MithrilStakeDistribution(Epoch(3))),
    );
    assert_last_certificate_eq!(leader_tester, leader_expected_certificate);
    cycle!(leader_tester, "signing");

    comment!("Follower: signers send their single signature");
    cycle!(follower_tester, "signing");
    follower_tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            &epoch_fixture.current_signing.unwrap().signers_fixture(),
        )
        .await
        .unwrap();

    comment!("Follower: state machine should issue a certificate for the MithrilStakeDistribution");
    cycle!(follower_tester, "ready");
    let follower_expected_certificate = ExpectedCertificate::new(
        Epoch(4),
        StakeDistributionParty::from_signers(
            epoch_fixture.current_signing.unwrap().signers_with_stake(),
        )
        .as_slice(),
        epoch_fixture
            .current_signing
            .unwrap()
            .compute_and_encode_concatenation_aggregate_verification_key(),
        SignedEntityType::MithrilStakeDistribution(Epoch(4)),
        ExpectedCertificate::identifier(&SignedEntityType::MithrilStakeDistribution(Epoch(3))),
    );
    assert_last_certificate_eq!(follower_tester, follower_expected_certificate);
    let expected_avk = epoch_fixture
        .current_signing
        .unwrap()
        .compute_and_encode_concatenation_aggregate_verification_key()
        .clone();
    assert_eq!(expected_avk, leader_expected_certificate.avk());
    assert_eq!(expected_avk, follower_expected_certificate.avk());

    comment!(
        "Epoch 5:
    - the leader aggregator produces a new certificate
    - the follower aggregator produces a new certificate
    - the follower aggregator new certificate uses the same avk as the leader aggregator's new certificate
    ");
    let epoch_fixture = &epoch_fixtures_map[&Epoch(5)];

    comment!("Leader: update stake distribution source");
    leader_tester
        .update_stake_distribution(epoch_fixture.registering.stake_distribution())
        .await
        .unwrap();

    comment!("Follower: update stake distribution source");
    follower_tester
        .update_stake_distribution(epoch_fixture.registering.stake_distribution())
        .await
        .unwrap();

    comment!("Leader: change the epoch");
    leader_tester.increase_epoch().await.unwrap();
    cycle!(leader_tester, "idle");
    cycle!(leader_tester, "ready");

    comment!("Follower: change the epoch after leader");
    follower_tester.increase_epoch().await.unwrap();
    cycle!(follower_tester, "idle");
    cycle!(follower_tester, "ready");

    comment!("Leader: register signers");
    leader_tester
        .register_signers(&epoch_fixture.registering.signers_fixture())
        .await
        .unwrap();
    cycle!(leader_tester, "signing");

    comment!("Leader: signers send their single signature");
    leader_tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            &epoch_fixture.current_signing.unwrap().signers_fixture(),
        )
        .await
        .unwrap();

    comment!("Follower: signers send their single signature");
    cycle!(follower_tester, "signing");
    follower_tester
        .send_single_signatures(
            SignedEntityTypeDiscriminants::MithrilStakeDistribution,
            &epoch_fixture.current_signing.unwrap().signers_fixture(),
        )
        .await
        .unwrap();

    comment!("Leader: state machine should issue a certificate for the MithrilStakeDistribution");
    cycle!(leader_tester, "ready");
    let leader_expected_certificate = ExpectedCertificate::new(
        Epoch(5),
        StakeDistributionParty::from_signers(
            epoch_fixture.current_signing.unwrap().signers_with_stake(),
        )
        .as_slice(),
        epoch_fixture
            .current_signing
            .unwrap()
            .compute_and_encode_concatenation_aggregate_verification_key(),
        SignedEntityType::MithrilStakeDistribution(Epoch(5)),
        ExpectedCertificate::identifier(&SignedEntityType::MithrilStakeDistribution(Epoch(4))),
    );
    assert_last_certificate_eq!(leader_tester, leader_expected_certificate);

    comment!("Follower: state machine should issue a certificate for the MithrilStakeDistribution");
    cycle!(follower_tester, "ready");
    let follower_expected_certificate = ExpectedCertificate::new(
        Epoch(5),
        StakeDistributionParty::from_signers(
            epoch_fixture.current_signing.unwrap().signers_with_stake(),
        )
        .as_slice(),
        epoch_fixture
            .current_signing
            .unwrap()
            .compute_and_encode_concatenation_aggregate_verification_key(),
        SignedEntityType::MithrilStakeDistribution(Epoch(5)),
        ExpectedCertificate::identifier(&SignedEntityType::MithrilStakeDistribution(Epoch(4))),
    );
    assert_last_certificate_eq!(follower_tester, follower_expected_certificate);
    let expected_avk = epoch_fixture
        .current_signing
        .unwrap()
        .compute_and_encode_concatenation_aggregate_verification_key()
        .clone();
    assert_eq!(expected_avk, leader_expected_certificate.avk());
    assert_eq!(expected_avk, follower_expected_certificate.avk());
}
