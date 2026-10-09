//! Constraint gadgets used by the recursive IVC circuit.

mod byte_combination;
mod protocol_message_hash;
mod schnorr_signature;

pub(crate) use byte_combination::combine_bytes;
pub(crate) use protocol_message_hash::protocol_message_hash_to_field_element;
pub(crate) use schnorr_signature::{GenesisSchnorrSignatureInputs, verify_genesis_signature};
