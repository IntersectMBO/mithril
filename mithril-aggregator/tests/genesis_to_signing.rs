mod test_extensions;

use std::collections::BTreeMap;

use mithril_aggregator::ServeCommandConfiguration;
use mithril_common::{
    entities::{
        BlockNumber, ChainPoint, Epoch, ProtocolParameters, SignedEntityTypeDiscriminants,
        SlotNumber, TimePoint,
    },
    temp_dir,
    test::{
        builder::MithrilFixtureBuilder,
        entities_extensions::SignedEntityTypeDiscriminantsTestExtension,
    },
};
use mithril_protocol_config::model::{
    ConfigurationResolverFromMarkers, ProtocolConfigurationForEpoch,
};
use test_extensions::{ExpectedCertificate, RuntimeTester, utilities::get_test_dir};

#[tokio::test]
async fn genesis_to_signing_with_all_signed_entities() {
    let protocol_parameters = ProtocolParameters {
        k: 5,
        m: 100,
        phi_f: 0.65,
    };
    let configuration = ServeCommandConfiguration {
        data_stores_directory: get_test_dir("genesis_to_signing_with_all_signed_entities"),
        signed_entity_types: Some(SignedEntityTypeDiscriminants::all_with_unstable_string(",")),
        ..ServeCommandConfiguration::new_sample(temp_dir!())
    };
    let protocol_configuration_markers = ConfigurationResolverFromMarkers::new(BTreeMap::from([(
        Epoch(0),
        ProtocolConfigurationForEpoch {
            protocol_parameters: protocol_parameters.clone(),
            enabled_signed_entity_types: SignedEntityTypeDiscriminants::all_with_unstable(),
            cardano_blocks_transactions: Some(
                mithril_common::entities::CardanoBlocksTransactionsSigningConfig {
                    security_parameter: mithril_common::entities::BlockNumberOffset(120),
                    step: BlockNumber(15),
                },
            ),
            cardano_transactions: Some(
                mithril_common::entities::CardanoTransactionsSigningConfig {
                    security_parameter: mithril_common::entities::BlockNumberOffset(120),
                    step: BlockNumber(15),
                },
            ),
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

    comment!("Create signers & declare stake distribution");
    let fixture = MithrilFixtureBuilder::default()
        .with_signers(5)
        .with_protocol_parameters(protocol_parameters.clone())
        .build();
    tester.init_state_from_fixture(&fixture).await.unwrap();

    cycle!(tester, "blocked-no-genesis");

    comment!("Bootstrap the genesis certificate");
    tester.register_genesis_certificate(&fixture).await.unwrap();

    assert_last_certificate_eq!(
        tester,
        ExpectedCertificate::new_genesis(
            Epoch(1),
            fixture.compute_and_encode_concatenation_aggregate_verification_key()
        )
    );

    tester.register_signers(&fixture.signers_fixture()).await.unwrap();

    comment!("Increase immutable number - still blocked(no-genesis)");
    tester.increase_immutable_number().await.unwrap();
    cycle!(tester, "blocked-no-genesis");

    comment!("Increase epoch - can go to signing");
    tester.increase_epoch().await.unwrap();

    cycle!(tester, "idle");
    cycle!(tester, "ready");
    cycle!(tester, "signing");
}
