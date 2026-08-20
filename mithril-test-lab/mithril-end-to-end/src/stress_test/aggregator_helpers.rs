use slog_scope::info;
use std::time::Duration;

use mithril_common::{
    StdResult,
    entities::{
        BlockNumber, BlockNumberOffset, CardanoBlocksTransactionsSigningConfig,
        CardanoTransactionsSigningConfig, Epoch,
    },
    test::builder::MithrilFixture,
};

use crate::{
    AggregateSignatureType, Aggregator, AggregatorConfig,
    stress_test::{entities::AggregatorParameters, fake_chain, fake_signer, wait},
};

/// Bootstrap an aggregator and make it compute its genesis certificate
pub async fn bootstrap_aggregator(
    args: &AggregatorParameters,
    signers_fixture: &MithrilFixture,
    current_epoch: &mut Epoch,
) -> StdResult<Aggregator> {
    info!(">> Launch Aggregator");
    let signed_entity_types = vec!["CardanoDatabase".to_string()];
    let chain_observer_type = "cardano-cli";

    let mut aggregator = Aggregator::new(&AggregatorConfig {
        index: 0,
        name: "genesis",
        server_port: args.server_port as u64,
        full_node: &args.full_node,
        cardano_cli_path: &args.cardano_cli_path,
        work_dir: &args.work_dir,
        store_dir: &args.work_dir.join("aggregator_store"),
        artifacts_dir: &args.work_dir.join("aggregator_artifacts"),
        bin_dir: &args.bin_dir,
        cardano_node_version: &semver::Version::new(1, 2, 3),
        mithril_run_interval: 1000,
        mithril_era: &args.mithril_era,
        mithril_era_marker_address: "",
        mithril_era_reader_adapter: "dummy",
        protocol_configuration_marker_address: "",
        protocol_configuration_reader_adapter: "dummy",
        signed_entity_types: &signed_entity_types,
        aggregate_signature_type: AggregateSignatureType::Concatenation,
        chain_observer_type,
        leader_aggregator_endpoint: &None,
        use_dmq: false,
        dmq_node_flavor: &None,
    })
    .unwrap();

    fake_chain::set_epoch(&args.mock_epoch_file_path(), *current_epoch);
    fake_chain::set_stake_distribution(&args.mock_stake_distribution_file_path(), signers_fixture);

    // Extremely large interval since, for the two following starts, only the http_server part
    // of the aggregator is relevant as we need to send signer registrations.
    aggregator.change_run_interval(Duration::from_secs(20000)).await;
    aggregator
        .set_mock_cardano_cli_file_path(
            &args.mock_stake_distribution_file_path(),
            &args.mock_epoch_file_path(),
        )
        .await;
    aggregator
        .set_protocol_parameters(&signers_fixture.protocol_parameters())
        .await;

    let cardano_transaction_signing_config = Some(CardanoTransactionsSigningConfig {
        security_parameter: BlockNumberOffset(1),
        step: BlockNumber(15),
    });

    let cardano_blocks_transactions_signing_config = Some(CardanoBlocksTransactionsSigningConfig {
        security_parameter: BlockNumberOffset(1),
        step: BlockNumber(15),
    });

    aggregator
        .set_signing_config(
            cardano_transaction_signing_config,
            cardano_blocks_transactions_signing_config,
        )
        .await;

    info!(
        ">> Starting the aggregator with a large run interval to call the http_server\
    without being bothered by the state machine cycles"
    );
    aggregator.serve().await.unwrap();
    wait::for_aggregator_http_server_to_start(&aggregator, Duration::from_secs(10)).await?;

    restart_aggregator_and_move_one_epoch_forward(&mut aggregator, current_epoch, args).await?;

    fake_signer::try_register_signer_until_registration_round_is_open(
        &aggregator,
        &signers_fixture.signers()[0],
        *current_epoch + 1,
        Duration::from_secs(60),
    )
    .await?;

    info!(">> Send the Signer Key Registrations payloads for the genesis signers");
    let errors = fake_signer::register_signers_to_aggregator(
        &aggregator,
        &signers_fixture.signers(),
        *current_epoch + 1,
    )
    .await?;
    assert_eq!(0, errors);

    fake_signer::try_register_signer_until_registration_round_is_open(
        &aggregator,
        &signers_fixture.signers()[0],
        *current_epoch + 1,
        Duration::from_secs(60),
    )
    .await?;

    restart_aggregator_and_move_one_epoch_forward(&mut aggregator, current_epoch, args).await?;

    info!(">> Send the Signer Key Registrations payloads for next genesis signers");
    let errors = fake_signer::register_signers_to_aggregator(
        &aggregator,
        &signers_fixture.signers(),
        *current_epoch + 1,
    )
    .await?;
    assert_eq!(0, errors);
    aggregator.stop().await.unwrap();

    {
        info!(">> Compute genesis certificate");
        let genesis_aggregator = Aggregator::copy_configuration(&aggregator);
        genesis_aggregator
            .bootstrap_genesis(&args.mithril_era)
            .await
            .expect("Genesis aggregator should be able to bootstrap genesis");
    }

    info!(">> Restart aggregator with a normal run interval");
    aggregator.change_run_interval(Duration::from_secs(3)).await;
    aggregator.serve().await.unwrap();

    wait::for_aggregator_http_server_to_start(&aggregator, Duration::from_secs(10)).await?;

    info!(">> Aggregator bootrapped");

    Ok(aggregator)
}

async fn restart_aggregator_and_move_one_epoch_forward(
    aggregator: &mut Aggregator,
    current_epoch: &mut Epoch,
    args: &AggregatorParameters,
) -> StdResult<()> {
    info!(">> Stop the aggregator to move one epoch forward");
    aggregator.stop().await.unwrap();

    *current_epoch += 1;
    fake_chain::set_epoch(&args.mock_epoch_file_path(), *current_epoch);

    info!(">> Restarting the aggregator with a large run interval");
    aggregator.serve().await.unwrap();
    wait::for_aggregator_http_server_to_start(aggregator, Duration::from_secs(10)).await?;
    wait::for_epoch_settings_at_epoch(aggregator, Duration::from_secs(10), *current_epoch).await?;

    Ok(())
}
