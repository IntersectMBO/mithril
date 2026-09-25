use crate::crypto_helper::cardano::{
    KeyRegWrapper, ProtocolInitializerErrorWrapper, ProtocolRegistrationErrorWrapper,
    StmInitializerWrapper,
};

use mithril_stm::{
    AggregationError, Clerk, ClosedKeyRegistration, LotteryIndex, MithrilMembershipDigest,
    Parameters, Signer, Stake,
};

/// A protocol version
pub type ProtocolVersion<'a> = &'a str;

/// Alias of [MithrilStm:MithrilMembershipDigest](struct@mithril_stm::MithrilMembershipDigest).
pub type ProtocolMembershipDigest = MithrilMembershipDigest;

/// The id of a Mithril party.
pub type ProtocolPartyId = String;

/// The raw hash of a Mithril party id.
pub type ProtocolPartyIdBytes = [u8; 28];

/// Alias of [MithrilStm:Stake](type@mithril_stm::Stake).
pub type ProtocolStake = Stake;

/// A list of [Party Id][ProtocolPartyId] associated with its [Stake][ProtocolStake].
pub type ProtocolStakeDistribution = Vec<(ProtocolPartyId, ProtocolStake)>;

/// Alias of [MithrilStm::Parameters](struct@mithril_stm::Parameters).
pub type ProtocolParameters = Parameters;

/// Alias of [MithrilStm::LotteryIndex](type@mithril_stm::LotteryIndex).
pub type ProtocolLotteryIndex = LotteryIndex;

/// Alias of [MithrilStm:Signer](struct@mithril_stm::Signer).
pub type ProtocolSigner = Signer<ProtocolMembershipDigest>;

/// Alias of a wrapper of [MithrilStm:Initializer](struct@mithril_stm::Initializer).
pub type ProtocolInitializer = StmInitializerWrapper;

/// Alias of [MithrilStm:Clerk](struct@mithril_stm::Clerk).
pub type ProtocolClerk = Clerk<ProtocolMembershipDigest>;

/// Alias of a wrapper of [MithrilStm:KeyRegistration](struct@mithril_stm::KeyRegistration).
pub type ProtocolKeyRegistration = KeyRegWrapper;

/// Alias of a wrapper of [MithrilStm:ClosedKeyRegistration](struct@mithril_stm::ClosedKeyRegistration).
pub type ProtocolClosedKeyRegistration = ClosedKeyRegistration;

// Error alias
/// Alias of a wrapper of [MithrilCommon:ProtocolRegistrationErrorWrapper](enum@ProtocolRegistrationErrorWrapper).
pub type ProtocolRegistrationError = ProtocolRegistrationErrorWrapper;

/// Alias of a wrapper of [MithrilCommon:ProtocolInitializerErrorWrapper](enum@ProtocolInitializerErrorWrapper).
pub type ProtocolInitializerError = ProtocolInitializerErrorWrapper;

/// Alias of [MithrilStm:AggregationError](enum@mithril_stm::AggregationError).
pub type ProtocolAggregationError = AggregationError;
