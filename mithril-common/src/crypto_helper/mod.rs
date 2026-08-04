//! Tools and types to abstract the use of the [Mithril STM library](https://mithril.network/rust-doc/mithril_stm/index.html)

mod cardano;
mod codec;
mod conversions;
pub mod ed25519;
mod ed25519_alias;
mod genesis;
#[cfg(feature = "future_snark")]
pub mod schnorr;
mod types;

pub use cardano::ColdKeyGenerator;

pub use cardano::{
    CodecParseError, KesEvolutions, KesPeriod, KesSigner, KesSignerStandard, KesVerifier,
    KesVerifierStandard, KesVerifyError, OpCert, OpCertWithoutColdVerificationKey,
    ProtocolInitializerErrorWrapper, ProtocolRegistrationErrorWrapper, SerDeShelleyFileFormat,
    SignerRegistrationParameters, Sum6KesBytes,
};
pub use codec::*;
pub use ed25519_alias::{era::*, manifest::*, protocol_configuration::*};
pub use genesis::*;
pub use mithril_merkle_tree::{
    Bytes, MKMap, MKMapKey, MKMapNode, MKMapProof, MKMapValue, MKProof, MKTree, MKTreeLeafIndexer,
    MKTreeLeafPosition, MKTreeNode, MKTreeStoreInMemory, MKTreeStorer,
};
pub use types::*;

/// The current protocol version
pub const PROTOCOL_VERSION: ProtocolVersion = "0.1.0";
