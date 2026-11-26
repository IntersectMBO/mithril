use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, anyhow};
use slog_scope::info;

use mithril_common::StdResult;
use mithril_common::entities::Epoch;
use mithril_common::messages::AggregatorStatusMessage;

use crate::toolkit::ScenarioToolkitContext;
use crate::{
    Aggregator, Devnet, EraMarkersDatumFormat, MithrilInfrastructure, ProtocolConfiguration,
};

#[derive(Debug, Clone)]
pub struct ExecToolkit {
    _context: ScenarioToolkitContext,
}

impl ExecToolkit {
    pub fn new(context: ScenarioToolkitContext) -> Self {
        Self { _context: context }
    }

    /// Retrieve the current Mithril era from a running aggregator by querying its `/status` route.
    pub async fn retrieve_current_era(&self, aggregator: &Aggregator) -> StdResult<String> {
        let url = format!("{}/status", aggregator.endpoint());
        let response = reqwest::get(&url)
            .await
            .with_context(|| format!("Failed to query aggregator status at `{url}`"))?;
        let status_message: AggregatorStatusMessage = response
            .json()
            .await
            .with_context(|| "Failed to parse aggregator status response")?;

        Ok(status_message.mithril_era.to_string())
    }

    pub async fn bootstrap_genesis_certificate(&self, aggregator: &Aggregator) -> StdResult<()> {
        info!("Bootstrap genesis certificate"; "aggregator" => &aggregator.name());
        info!("> retrieving current era from aggregator"; "aggregator" => &aggregator.name());
        let mithril_era = self.retrieve_current_era(aggregator).await?;
        info!("> stopping aggregator"; "aggregator" => &aggregator.name());
        aggregator.stop().await?;
        info!("> bootstrapping genesis using signers registered two epochs ago..."; "aggregator" => &aggregator.name());
        aggregator.bootstrap_genesis(&mithril_era).await?;
        info!("> done, restarting aggregator"; "aggregator" => &aggregator.name());
        aggregator.serve().await?;

        Ok(())
    }

    pub async fn register_era_marker(
        &self,
        aggregator: &Aggregator,
        devnet: &Devnet,
        mithril_era: &str,
        era_epoch: Epoch,
        datum_formats: &[EraMarkersDatumFormat],
    ) -> StdResult<()> {
        info!("Register '{mithril_era}' era marker"; "aggregator" => &aggregator.name(), "datum_formats" => ?datum_formats);
        if datum_formats.len() > 2 {
            return Err(anyhow!(
                "At most two era markers datums can be stored on the Cardano chain"
            ));
        }
        let mut datum_file_paths = vec![];
        for datum_format in datum_formats {
            info!("> generating era marker tx datum..."; "aggregator" => &aggregator.name(), "datum_format" => ?datum_format);
            let datum_file_path = devnet.artifacts_dir().join(datum_format.datum_file_name());
            aggregator
                .era_generate_tx_datum(&datum_file_path, mithril_era, era_epoch, *datum_format)
                .await?;
            datum_file_paths.push(datum_file_path);
        }
        let (datum_file_path, additional_datum_file_paths) = datum_file_paths
            .split_first()
            .ok_or_else(|| anyhow!("No era markers datum to store on the Cardano chain"))?;

        info!("> writing '{mithril_era}' era marker on the Cardano chain..."; "aggregator" => &aggregator.name());
        devnet
            .write_era_marker(
                datum_file_path,
                additional_datum_file_paths.first().map(|path| path.as_path()),
            )
            .await?;

        Ok(())
    }

    pub async fn register_protocol_configurations(
        &self,
        aggregator: &Aggregator,
        devnet: &Devnet,
        protocol_configurations: Vec<ProtocolConfiguration>,
    ) -> StdResult<()> {
        info!("Register protocol configuration marker"; "aggregator" => &aggregator.name());

        info!("> generating protocol configuration json input file..."; "aggregator" => &aggregator.name());
        let json_protocol_configurations = serde_json::to_string(&protocol_configurations)?;
        let json_protocol_configurations_path = devnet
            .artifacts_dir()
            .join(PathBuf::from("protocol-configurations.json".to_string()));
        let mut json_protocol_configurations_file =
            File::create(&json_protocol_configurations_path)?;
        json_protocol_configurations_file.write_all(json_protocol_configurations.as_bytes())?;

        info!("> generating protocol configuration tx datum..."; "aggregator" => &aggregator.name());
        let tx_datum_file_path = devnet.artifacts_dir().join(PathBuf::from(
            "protocol-configurations-datum.txt".to_string(),
        ));
        aggregator
            .protocol_configuration_generate_tx_datum(
                &json_protocol_configurations_path,
                &tx_datum_file_path,
            )
            .await?;

        info!("> writing protocol configuration on the Cardano chain..."; "aggregator" => &aggregator.name());
        devnet
            .write_protocol_configuration_markers(&tx_datum_file_path)
            .await?;

        Ok(())
    }

    pub async fn delegate_stakes_to_pools(
        &self,
        devnet: &Devnet,
        delegation_round: u16,
    ) -> StdResult<()> {
        info!("Delegate stakes to the cardano pools");

        devnet.delegate_stakes(delegation_round).await?;

        Ok(())
    }

    pub async fn transfer_funds(&self, devnet: &Devnet) -> StdResult<()> {
        info!("Transfer funds on the devnet");

        devnet.transfer_funds().await?;

        Ok(())
    }

    pub async fn update_protocol_parameters(
        &self,
        aggregator: &Aggregator,
        infrastructure: &MithrilInfrastructure,
        epoch: Epoch,
    ) -> StdResult<()> {
        let protocol_parameters_new = Aggregator::updated_protocol_parameters(
            infrastructure.most_constraining_aggregate_signature_type(),
        );

        if aggregator.is_reading_protocol_configurations_on_chain() {
            info!("> updating on-chain protocol parameters to {protocol_parameters_new:?}...");
            let protocol_configurations = Vec::from([
                infrastructure.startup_protocol_configuration().clone(),
                ProtocolConfiguration {
                    epoch,
                    protocol_parameters: protocol_parameters_new,
                    ..infrastructure.startup_protocol_configuration().clone()
                },
            ]);
            self.register_protocol_configurations(
                aggregator,
                infrastructure.devnet(),
                protocol_configurations,
            )
            .await?;
        } else {
            info!("Update protocol parameters"; "aggregator" => &aggregator.name());
            info!("> stopping aggregator");
            aggregator.stop().await?;
            info!(
                "> updating protocol parameters to {protocol_parameters_new:?}..."; "aggregator" => &aggregator.name()
            );
            aggregator.set_protocol_parameters(&protocol_parameters_new).await;
            info!("> done, restarting aggregator"; "aggregator" => &aggregator.name());
            aggregator.serve().await?;
        }

        Ok(())
    }
}
