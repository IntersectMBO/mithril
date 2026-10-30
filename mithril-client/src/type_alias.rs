/// Mithril result type, an alias of [anyhow::Result]
pub type MithrilResult<T> = anyhow::Result<T>;

/// Mithril error type, an alias of [anyhow::Error]
pub type MithrilError = anyhow::Error;

/// A Cardano node database snapshot
///
pub use mithril_common::messages::CardanoDatabaseSnapshotMessage as CardanoDatabaseSnapshot;

/// List items of Cardano node database snapshot
///
pub use mithril_common::messages::CardanoDatabaseSnapshotListItemMessage as CardanoDatabaseSnapshotListItem;

/// A Mithril stake distribution.
///
pub use mithril_common::messages::MithrilStakeDistributionMessage as MithrilStakeDistribution;

/// List item of Mithril stake distributions.
///
pub use mithril_common::messages::MithrilStakeDistributionListItemMessage as MithrilStakeDistributionListItem;

/// A Mithril certificate.
///
pub use mithril_common::messages::CertificateMessage as MithrilCertificate;

pub use mithril_common::messages::CertificateMetadataMessagePart as MithrilCertificateMetadata;

/// List item of Mithril certificates
///
pub use mithril_common::messages::CertificateListItemMessage as MithrilCertificateListItem;

pub use mithril_common::messages::CertificateListItemMessageMetadata as MithrilCertificateListItemMetadata;

/// An individual signer of a [Mithril certificate][MithrilCertificate]
///
pub use mithril_common::messages::SignerWithStakeMessagePart as MithrilSigner;

pub use mithril_common::messages::CardanoTransactionsProofsMessage as CardanoTransactionsProofs;

pub use mithril_common::messages::CardanoTransactionsSetProofMessagePart as CardanoTransactionsSetProof;

cfg_unstable! {
    pub use mithril_common::messages::CardanoTransactionsProofsV2Message as CardanoTransactionsProofsV2;

    pub use mithril_common::messages::CardanoBlocksProofsMessage as CardanoBlocksProofs;

    pub use mithril_common::messages::MkSetProofMessagePart as MkSetProof;

    pub use mithril_common::messages::CardanoBlockMessagePart as CardanoBlock;

    pub use mithril_common::messages::CardanoTransactionMessagePart as CardanoTransaction;

    pub use mithril_common::messages::VerifiedCardanoTransactionsV2;

    pub use mithril_common::messages::VerifiedCardanoBlocks;

    pub use mithril_common::messages::VerifyProofsV2Error;

    pub use mithril_common::messages::CardanoBlocksTransactionsSnapshotMessage as CardanoBlocksTransactionsSnapshot;

    pub use mithril_common::messages::CardanoBlocksTransactionsSnapshotListItemMessage as CardanoBlocksTransactionsSnapshotListItem;
}

pub use mithril_common::messages::VerifiedCardanoTransactions;

pub use mithril_common::messages::VerifyCardanoTransactionsProofsError;

/// A snapshot that allow to know up to which [point of time][common::CardanoDbBeacon] Mithril have certified Cardano transactions.
pub use mithril_common::messages::CardanoTransactionSnapshotMessage as CardanoTransactionSnapshot;

/// List item of a Cardano transaction snapshot.
pub use mithril_common::messages::CardanoTransactionSnapshotListItemMessage as CardanoTransactionSnapshotListItem;

/// A Cardano stake distribution.
pub use mithril_common::messages::CardanoStakeDistributionMessage as CardanoStakeDistribution;

/// List item of Cardano stake distributions.
pub use mithril_common::messages::CardanoStakeDistributionListItemMessage as CardanoStakeDistributionListItem;

/// `mithril-common` re-exports
pub mod common {
    pub use mithril_common::AggregateSignatureType;
    pub use mithril_common::crypto_helper::MKProof;
    pub use mithril_common::entities::{
        AncillaryLocation, BlockHash, BlockNumber, BlockNumberOffset, CardanoDbBeacon,
        CardanoNetwork, ChainPoint, CompressionAlgorithm, DigestLocation, Epoch, EpochSpecifier,
        ImmutableFileNumber, ImmutablesLocation, MagicId, MithrilNetwork, MultiFilesUri,
        Percentage, ProtocolMessage, ProtocolMessagePartKey, ProtocolParameters, SignedEntityType,
        SignedEntityTypeDiscriminants, SlotNumber, StakeDistribution, SupportedEra, TemplateUri,
        TransactionHash,
    };
    pub use mithril_common::messages::{
        AncillaryMessagePart, DigestsMessagePart, ImmutablesMessagePart,
        SignedEntityTypeDiscriminantsMessage, SignedEntityTypeMessage,
    };

    /// Test utilities.
    ///
    /// ⚠ Do not use in production code ⚠
    pub mod test {
        pub use mithril_common::test::double::Dummy;
    }
}

/// Required capabilities for an aggregator.
#[cfg(not(target_family = "wasm"))]
pub use mithril_aggregator_discovery::RequiredAggregatorCapabilities;
