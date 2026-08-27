mod test_extensions;

use std::collections::{BTreeMap, BTreeSet};

use mithril_aggregator::{RuntimeError, ServeCommandConfiguration};
use mithril_common::{
    entities::{
        BlockNumber, ChainPoint, Epoch, ProtocolParameters, SignedEntityTypeDiscriminants,
        SlotNumber, SupportedEra, TimePoint,
    },
    temp_dir,
    test::{builder::MithrilFixtureBuilder, double::Dummy},
};
use mithril_era::EraMarker;

use mithril_protocol_config::model::{
    ConfigurationResolverFromMarkers, ProtocolConfigurationForEpoch,
};
use test_extensions::{RuntimeTester, utilities::get_test_dir};

#[tokio::test]
async fn testing_eras() {
    let protocol_parameters = ProtocolParameters {
        k: 5,
        m: 100,
        phi_f: 0.95,
    };
    let configuration = ServeCommandConfiguration {
        data_stores_directory: get_test_dir("testing_eras"),
        ..ServeCommandConfiguration::new_sample(temp_dir!())
    };
    let protocol_configuration_markers = ConfigurationResolverFromMarkers::new(BTreeMap::from([(
        Epoch(0),
        ProtocolConfigurationForEpoch {
            protocol_parameters: protocol_parameters.clone(),
            enabled_signed_entity_types: BTreeSet::from([
                SignedEntityTypeDiscriminants::MithrilStakeDistribution,
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
    tester.era_reader_adapter.set_markers(vec![
        EraMarker::new("unsupported", Some(Epoch(0))),
        EraMarker::new(&SupportedEra::dummy().to_string(), Some(Epoch(12))),
    ]);
    comment!("Starting the runtime at unsupported Era.");
    match tester.runtime.cycle().await {
        Err(e) => match e {
            RuntimeError::Critical {
                message: _,
                nested_error: _,
            } => {}
            _ => panic!("Expected a Critical Error, got {e:?}."),
        },
        _ => {
            panic!("Expected an error, got Ok().")
        }
    }

    // Testing the Era changes during the process
    let protocol_parameters = ProtocolParameters {
        k: 5,
        m: 100,
        phi_f: 0.95,
    };
    tester.era_reader_adapter.set_markers(vec![
        EraMarker::new(&SupportedEra::dummy().to_string(), Some(Epoch(0))),
        EraMarker::new("unsupported", Some(Epoch(2))),
    ]);
    let fixture = MithrilFixtureBuilder::default()
        .with_signers(5)
        .with_protocol_parameters(protocol_parameters.clone())
        .build();
    tester.init_state_from_fixture(&fixture).await.unwrap();

    comment!("Bootstrap the genesis certificate");
    tester.register_genesis_certificate(&fixture).await.unwrap();

    comment!("Increase immutable number");
    tester.increase_immutable_number().await.unwrap();

    comment!("start the runtime state machine");
    cycle!(tester, "blocked-genesis-epoch");

    // reach unsupported Epoch
    let current_epoch = tester.chain_observer.next_epoch().await.unwrap();
    assert_eq!(2, current_epoch, "Epoch was expected to be 2.");
    cycle!(tester, "idle");

    match tester.runtime.cycle().await {
        Err(e) => match e {
            RuntimeError::Critical {
                message: _,
                nested_error: _,
            } => {}
            _ => panic!("Expected a Critical Error, got {e:?}."),
        },
        _ => {
            panic!("Expected an error, got Ok().")
        }
    }
}
