use anyhow::{Context, anyhow};
use clap::Parser;
use cli_table::{Cell, Table, print_stdout};
use slog::debug;
use std::collections::HashMap;
use std::sync::Arc;

use mithril_client::common::{BlockHash, SignedEntityTypeDiscriminants};
use mithril_client::{
    CardanoBlocksProofs, MessageBuilder, MithrilCertificate, MithrilResult, VerifiedCardanoBlocks,
    VerifyProofsV2Error,
};

use crate::utils::{IndicatifFeedbackReceiver, ProgressOutputType, ProgressPrinter, compute_depth};
use crate::{
    CommandContext,
    configuration::{ConfigError, ConfigSource},
};

/// Clap command to certify that given Cardano block hashes are included in a Mithril-certified Cardano block set.
#[derive(Parser, Debug, Clone)]
pub struct CardanoBlocksCertifyCommand {
    /// Genesis verification key to check the certificate chain.
    #[clap(long, env = "GENESIS_VERIFICATION_KEY")]
    genesis_verification_key: Option<String>,

    /// Hashes of the blocks to certify.
    #[clap(value_delimiter = ',', required = true)]
    blocks_hashes: Vec<String>,
}

impl CardanoBlocksCertifyCommand {
    /// Cardano block certify command
    pub async fn execute(&self, mut context: CommandContext) -> MithrilResult<()> {
        context.require_unstable("cardano-block certify <block1>,<block2>,...,<blockn>", None)?;
        context.config_parameters_mut().add_source(self)?;
        let logger = context.logger();
        let progress_output_type = if context.is_json_output_enabled() {
            ProgressOutputType::JsonReporter
        } else {
            ProgressOutputType::Tty
        };
        let progress_printer = ProgressPrinter::new(progress_output_type, 4);
        let client_builder = context.setup_mithril_client_builder_with_fallback_genesis_key()?;
        let client = context
            .add_certificate_chain_cache(client_builder)?
            .add_feedback_receiver(Arc::new(IndicatifFeedbackReceiver::new(
                progress_output_type,
                logger.clone(),
            )))
            .with_capabilities(SignedEntityTypeDiscriminants::CardanoBlocksTransactions.into())
            .build()?;

        Self::certify(
            &self.blocks_hashes,
            client,
            progress_printer,
            context.is_json_output_enabled(),
            logger.clone(),
        )
        .await?;

        Ok(())
    }

    /// Certify that a given list of block hashes are included in the Cardano block set
    pub async fn certify(
        blocks_hashes: &[String],
        client: mithril_client::Client,
        progress_printer: ProgressPrinter,
        is_json_output_enabled: bool,
        logger: slog::Logger,
    ) -> MithrilResult<()> {
        progress_printer.report_step(1, "Fetching a proof for the given blocks…")?;
        let cardano_block_proof = client
            .cardano_block()
            .get_proof(blocks_hashes)
            .await
            .with_context(|| {
                format!(
                    "Can not get proof from aggregator, blocks hashes: '{:?}'",
                    blocks_hashes
                )
            })?;
        debug!(logger, "Got Proof from aggregator"; "proof" => ?cardano_block_proof);
        let verified_blocks =
            Self::verify_proof_validity(2, &progress_printer, &cardano_block_proof)?;

        progress_printer.report_step(
            3,
            "Fetching the associated certificate and verifying the certificate chain…",
        )?;
        let certificate = client
            .certificate()
            .verify_chain(&cardano_block_proof.certificate_hash)
            .await
            .with_context(|| {
                format!(
                    "Can not verify the certificate chain from certificate_hash: '{}'",
                    verified_blocks.certificate_hash()
                )
            })?;

        Self::verify_proof_match_certificate(4, &progress_printer, &certificate, &verified_blocks)?;
        Self::log_certify_information(
            &verified_blocks,
            &cardano_block_proof.non_certified_blocks,
            is_json_output_enabled,
        )
    }

    fn verify_proof_validity(
        step_number: u16,
        progress_printer: &ProgressPrinter,
        cardano_block_proof: &CardanoBlocksProofs,
    ) -> MithrilResult<VerifiedCardanoBlocks> {
        progress_printer.report_step(step_number, "Verifying the proof…")?;
        match cardano_block_proof.verify() {
            Ok(verified_blocks) => Ok(verified_blocks),
            Err(VerifyProofsV2Error::NoCertifiedItem(..)) => Err(anyhow!(
                "Mithril could not certify any of the given blocks.

Mithril may not have signed those blocks yet, please try again later."
            )),
            err => err.with_context(|| "Proof verification failed"),
        }
    }

    fn verify_proof_match_certificate(
        step_number: u16,
        progress_printer: &ProgressPrinter,
        certificate: &MithrilCertificate,
        verified_blocks: &VerifiedCardanoBlocks,
    ) -> MithrilResult<()> {
        progress_printer.report_step(
            step_number,
            "Verify that the proof is signed in the associated certificate",
        )?;
        let message = MessageBuilder::new()
            .compute_cardano_blocks_proofs_message(certificate, verified_blocks);
        if !certificate.match_message(&message) {
            return Err(anyhow!(
                "Proof and certificate don't match (certificate hash = '{}').",
                certificate.hash
            ));
        }

        Ok(())
    }

    fn log_certify_information(
        verified_blocks: &VerifiedCardanoBlocks,
        non_certified_blocks: &[BlockHash],
        json_output: bool,
    ) -> MithrilResult<()> {
        let latest_certified_block_number = verified_blocks.latest_certified_block_number();
        let security_parameter = verified_blocks.security_parameter();

        if json_output {
            println!(
                r#"{{"certified_blocks": {}, "non_certified_blocks": {}}}"#,
                serde_json::to_string(
                    &verified_blocks
                        .certified_blocks()
                        .iter()
                        .map(|block| {
                            serde_json::json!({
                                "block_hash": block.block_hash,
                                "block_number": block.block_number,
                                "slot_number": block.slot_number,
                                "block_depth": compute_depth(
                                    latest_certified_block_number,
                                    security_parameter,
                                    block.block_number,
                                ),
                            })
                        })
                        .collect::<Vec<_>>()
                )?,
                serde_json::to_string(non_certified_blocks)?,
            );
        } else {
            println!(
                r###"Cardano blocks proof has been successfully signed in the associated Mithril certificate."###,
            );

            if !non_certified_blocks.is_empty() {
                println!(
                    r###"
No proof could be computed for some Cardano blocks. Mithril may not have signed those blocks yet, please try again later."###,
                );
            }

            let result_table = verified_blocks
                .certified_blocks()
                .iter()
                .map(|block| {
                    vec![
                        block.block_hash.clone().cell(),
                        format!("{}", block.block_number).cell(),
                        format!("{}", block.slot_number).cell(),
                        format!(
                            "{}",
                            compute_depth(
                                latest_certified_block_number,
                                security_parameter,
                                block.block_number,
                            )
                        )
                        .cell(),
                        "✅".cell().justify(cli_table::format::Justify::Center),
                    ]
                })
                .chain(non_certified_blocks.iter().map(|block| {
                    vec![
                        block.clone().cell(),
                        String::new().cell(),
                        String::new().cell(),
                        String::new().cell(),
                        "❌".cell().justify(cli_table::format::Justify::Center),
                    ]
                }))
                .table()
                .title(vec![
                    "Block Hash".cell(),
                    "Block Number".cell(),
                    "Slot Number".cell(),
                    "Block depth".cell(),
                    "Certified".cell(),
                ]);

            print_stdout(result_table)?
        }

        Ok(())
    }
}

impl ConfigSource for CardanoBlocksCertifyCommand {
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
