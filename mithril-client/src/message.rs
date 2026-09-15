use anyhow::Context;
use slog::{Logger, o};

use mithril_common::{
    crypto_helper::ProtocolKey, logging::LoggerExtensions, protocol::SignerBuilder,
    signable_builder::CardanoStakeDistributionSignableBuilder,
};

#[cfg(feature = "fs")]
use crate::common::MKProof;
use crate::{
    CardanoStakeDistribution, MithrilCertificate, MithrilResult, MithrilSigner,
    MithrilStakeDistribution, VerifiedCardanoTransactions,
    common::{ProtocolMessage, ProtocolMessagePartKey},
};

#[cfg(feature = "unstable")]
use crate::{VerifiedCardanoBlocks, VerifiedCardanoTransactionsV2};

/// A [MessageBuilder] can be used to compute the message of Mithril artifacts.
pub struct MessageBuilder {
    logger: Logger,
}

impl MessageBuilder {
    /// Constructs a new `MessageBuilder`.
    pub fn new() -> MessageBuilder {
        let logger = Logger::root(slog::Discard, o!());
        Self { logger }
    }

    /// Set the [Logger] to use.
    pub fn with_logger(mut self, logger: Logger) -> Self {
        self.logger = logger.new_with_component_name::<Self>();
        self
    }

    cfg_fs! {
        /// Compute message for a Cardano database.
        pub async fn compute_cardano_database_message(
        &self,
            certificate: &MithrilCertificate,
            merkle_proof: &MKProof,
        ) -> MithrilResult<ProtocolMessage> {
            let mut message = certificate.protocol_message.clone();
            message.set_message_part(
                ProtocolMessagePartKey::CardanoDatabaseMerkleRoot,
                merkle_proof.root().to_hex(),
            );
            Ok(message)
        }
    }

    /// Compute message for a Mithril stake distribution.
    pub fn compute_mithril_stake_distribution_message(
        &self,
        certificate: &MithrilCertificate,
        mithril_stake_distribution: &MithrilStakeDistribution,
    ) -> MithrilResult<ProtocolMessage> {
        let signers =
            MithrilSigner::try_into_signers(mithril_stake_distribution.signers_with_stake.clone())
                .with_context(|| "Could not compute message: conversion failure")?;

        let signer_builder = SignerBuilder::new(
            &signers,
            &mithril_stake_distribution.protocol_parameters,
            #[cfg(feature = "future_snark")]
            mithril_stake_distribution.epoch,
        )
        .with_context(
            || "Could not compute message: aggregate verification key computation failed",
        )?;

        let aggregate_verification_key = signer_builder.compute_aggregate_verification_key();

        let avk = ProtocolKey::new(
            aggregate_verification_key
                .to_concatenation_aggregate_verification_key()
                .to_owned(),
        )
        .to_json_hex()
        .with_context(|| "Could not compute message: aggregate verification key encoding failed")?;

        let mut message = certificate.protocol_message.clone();
        message.set_message_part(ProtocolMessagePartKey::NextAggregateVerificationKey, avk);

        #[cfg(feature = "future_snark")]
        if certificate
            .protocol_message
            .get_message_part(&ProtocolMessagePartKey::NextSnarkAggregateVerificationKey)
            .is_some()
        {
            let snark_avk = aggregate_verification_key
                .to_snark_aggregate_verification_key()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Could not compute message: SNARK aggregate verification key is unavailable"
                    )
                })?;
            let snark_avk_encoded = ProtocolKey::new(snark_avk.to_owned())
                .to_bytes_hex()
                .with_context(|| {
                    "Could not compute message: SNARK aggregate verification key encoding failed"
                })?;
            message.set_message_part(
                ProtocolMessagePartKey::NextSnarkAggregateVerificationKey,
                snark_avk_encoded,
            );
        }

        Ok(message)
    }

    /// Compute message for a Cardano Transactions Proofs.
    pub fn compute_cardano_transactions_proofs_message(
        &self,
        transactions_proofs_certificate: &MithrilCertificate,
        verified_transactions: &VerifiedCardanoTransactions,
    ) -> ProtocolMessage {
        let mut message = transactions_proofs_certificate.protocol_message.clone();
        verified_transactions.fill_protocol_message(&mut message);
        message
    }

    cfg_unstable! {
        /// Compute message for a Cardano Blocks Proofs.
        pub fn compute_cardano_blocks_proofs_message(
            &self,
            blocks_proofs_certificate: &MithrilCertificate,
            verified_blocks: &VerifiedCardanoBlocks,
        ) -> ProtocolMessage {
            let mut message = blocks_proofs_certificate.protocol_message.clone();
            message.set_message_part(
                ProtocolMessagePartKey::CardanoBlocksTransactionsMerkleRoot,
                verified_blocks.certified_merkle_root().to_string(),
            );
            message.set_message_part(
                ProtocolMessagePartKey::LatestBlockNumber,
                verified_blocks.latest_certified_block_number().to_string(),
            );
            message.set_message_part(
                ProtocolMessagePartKey::CardanoBlocksTransactionsBlockNumberOffset,
                verified_blocks.security_parameter().to_string(),
            );
            message
        }

        /// Compute message for a Cardano Transaction V2 Proofs.
        pub fn compute_cardano_transactions_proofs_v2_message(
            &self,
            transactions_proofs_certificate: &MithrilCertificate,
            verified_transactions: &VerifiedCardanoTransactionsV2,
        ) -> ProtocolMessage {
            let mut message = transactions_proofs_certificate.protocol_message.clone();
            message.set_message_part(
                ProtocolMessagePartKey::CardanoBlocksTransactionsMerkleRoot,
                verified_transactions.certified_merkle_root().to_string(),
            );
            message.set_message_part(
                ProtocolMessagePartKey::LatestBlockNumber,
                verified_transactions.latest_certified_block_number().to_string(),
            );
            message.set_message_part(
                ProtocolMessagePartKey::CardanoBlocksTransactionsBlockNumberOffset,
                verified_transactions.security_parameter().to_string(),
            );
            message
        }
    }

    /// Compute message for a Cardano stake distribution.
    pub fn compute_cardano_stake_distribution_message(
        &self,
        certificate: &MithrilCertificate,
        cardano_stake_distribution: &CardanoStakeDistribution,
    ) -> MithrilResult<ProtocolMessage> {
        let mk_tree =
            CardanoStakeDistributionSignableBuilder::compute_merkle_tree_from_stake_distribution(
                cardano_stake_distribution.stake_distribution.clone(),
            )?;

        let mut message = certificate.protocol_message.clone();
        message.set_message_part(
            ProtocolMessagePartKey::CardanoStakeDistributionEpoch,
            cardano_stake_distribution.epoch.to_string(),
        );
        message.set_message_part(
            ProtocolMessagePartKey::CardanoStakeDistributionMerkleRoot,
            mk_tree.compute_root()?.to_hex(),
        );

        Ok(message)
    }
}

impl Default for MessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}
