use sha2::{Digest, Sha256};
use std::ops::Deref;

use crate::{BaseFieldElement, StmResult, circuits::halo2_ivc::types::MessageHash};

/// Preimage of the genesis protocol message, hashed to the genesis message field element that
/// anchors an IVC chain.
#[derive(Clone, Debug)]
pub struct GenesisMessagePreimage(Vec<u8>);

impl GenesisMessagePreimage {
    /// Returns the preimage bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for GenesisMessagePreimage {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&GenesisMessagePreimage> for MessageHash {
    type Error = anyhow::Error;

    fn try_from(preimage: &GenesisMessagePreimage) -> StmResult<Self> {
        let genesis_preimage_hash: [u8; 32] = Sha256::digest(&preimage.0).into();
        let genesis_message_field_elem = BaseFieldElement::from_raw(&genesis_preimage_hash)?.0;
        Ok(MessageHash::from_field(genesis_message_field_elem))
    }
}

impl Deref for GenesisMessagePreimage {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq<[u8]> for GenesisMessagePreimage {
    fn eq(&self, other: &[u8]) -> bool {
        self.0 == other
    }
}
