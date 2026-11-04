mod v1;
mod v2;

use v1::execute as certify_v1;
use v2::execute as certify_v2;

use clap::Parser;
use std::collections::HashMap;
use std::sync::Arc;

use mithril_client::MithrilResult;
use mithril_client::common::SignedEntityTypeDiscriminants;

use crate::commands::cardano_transaction::CardanoTransactionCommandsBackend;
use crate::utils::{IndicatifFeedbackReceiver, ProgressOutputType, ProgressPrinter};
use crate::{
    CommandContext,
    configuration::{ConfigError, ConfigSource},
};

/// Clap command to certify that given Cardano transaction hashes are included in a Mithril-certified Cardano transaction set.
#[derive(Parser, Debug, Clone)]
pub struct CardanoTransactionsCertifyCommand {
    ///Backend to use, either: `v1` (default) or `v2`
    #[arg(short, long, value_enum, default_value_t)]
    backend: CardanoTransactionCommandsBackend,

    /// Genesis verification key to check the certificate chain.
    #[clap(long, env = "GENESIS_VERIFICATION_KEY")]
    genesis_verification_key: Option<String>,

    /// Hashes of the transactions to certify.
    #[clap(value_delimiter = ',', required = true)]
    transactions_hashes: Vec<String>,
}

impl CardanoTransactionsCertifyCommand {
    /// Cardano transaction certify command
    pub async fn execute(&self, mut context: CommandContext) -> MithrilResult<()> {
        context.config_parameters_mut().add_source(self)?;
        let logger = context.logger();

        let progress_output_type = if context.is_json_output_enabled() {
            ProgressOutputType::JsonReporter
        } else {
            ProgressOutputType::Tty
        };
        let progress_printer = ProgressPrinter::new(progress_output_type, 4);
        let feedback_receiver = Arc::new(IndicatifFeedbackReceiver::new(
            progress_output_type,
            logger.clone(),
        ));

        match self.backend {
            CardanoTransactionCommandsBackend::V1 => {
                let client = context
                    .setup_mithril_client_builder()?
                    .with_capabilities(SignedEntityTypeDiscriminants::CardanoTransactions.into())
                    .add_feedback_receiver(feedback_receiver)
                    .build()?;
                certify_v1(
                    &self.transactions_hashes,
                    client,
                    progress_printer,
                    context.is_json_output_enabled(),
                    logger.clone(),
                )
                .await?;
            }
            CardanoTransactionCommandsBackend::V2 => {
                context.require_unstable(
                    "cardano-transaction certify <tx1>,<tx2>,...,<txn> --backend v2",
                    None,
                )?;
                let client = context
                    .setup_mithril_client_builder()?
                    .with_capabilities(
                        SignedEntityTypeDiscriminants::CardanoBlocksTransactions.into(),
                    )
                    .add_feedback_receiver(feedback_receiver)
                    .build()?;
                certify_v2(
                    &self.transactions_hashes,
                    client,
                    progress_printer,
                    context.is_json_output_enabled(),
                    logger.clone(),
                )
                .await?;
            }
        }

        Ok(())
    }
}

impl ConfigSource for CardanoTransactionsCertifyCommand {
    fn collect(&self) -> Result<HashMap<String, String>, ConfigError> {
        let mut map = HashMap::new();

        if let Some(genesis_verification_key) = self.genesis_verification_key.clone() {
            map.insert(
                "genesis_verification_key".to_string(),
                genesis_verification_key,
            );
        }

        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use slog::{Logger, o};

    use crate::configuration::ConfigParameters;

    use super::*;

    fn context_without_genesis_verification_key(unstable_enabled: bool) -> CommandContext {
        CommandContext::new(
            ConfigParameters::build(&[("aggregator_endpoint", "http://127.0.0.1:1/aggregator")]),
            unstable_enabled,
            true,
            Logger::root(slog::Discard, o!()),
        )
    }

    fn certify_command(
        backend: CardanoTransactionCommandsBackend,
    ) -> CardanoTransactionsCertifyCommand {
        CardanoTransactionsCertifyCommand {
            backend,
            genesis_verification_key: None,
            transactions_hashes: vec!["tx-hash".to_string()],
        }
    }

    #[tokio::test]
    async fn certify_without_genesis_verification_key_fails() {
        let error = certify_command(CardanoTransactionCommandsBackend::V1)
            .execute(context_without_genesis_verification_key(false))
            .await
            .expect_err("the command must fail without a genesis verification key");

        assert!(
            format!("{error:?}").contains("genesis_verification_key"),
            "the error must name the missing key, got: {error:?}"
        );
    }

    #[tokio::test]
    async fn certify_v2_without_genesis_verification_key_fails() {
        let error = certify_command(CardanoTransactionCommandsBackend::V2)
            .execute(context_without_genesis_verification_key(true))
            .await
            .expect_err("the command must fail without a genesis verification key");

        assert!(
            format!("{error:?}").contains("genesis_verification_key"),
            "the error must name the missing key, got: {error:?}"
        );
    }
}
