//! Protocol module
//!
//! This module contains types that standardize and make easier mithril protocol operations
//! such as issuing single signatures, aggregating them as multi-signatures or computing
//! aggregate verification keys.

mod ancillary;
mod multi_signer;
mod signer_builder;
mod single_signer;

pub use ancillary::build_ancillary_proof_input;
pub use multi_signer::{MultiSignatureWithAncillaryData, MultiSigner};
pub use signer_builder::{SignerBuilder, SignerBuilderError};
pub use single_signer::SingleSigner;

use crate::entities::ProtocolMessage;

/// Trait to convert a type to a message that can be signed or verified by the Mithril protocol.
pub trait ToMessage: Sync + Send {
    /// Return a String representation of the message.
    fn to_message(&self) -> String;
}

impl ToMessage for String {
    fn to_message(&self) -> String {
        self.clone()
    }
}

impl ToMessage for &str {
    fn to_message(&self) -> String {
        self.to_string()
    }
}

impl ToMessage for ProtocolMessage {
    fn to_message(&self) -> String {
        self.compute_hash()
    }
}
