//! DMQ network, guessed from the Cardano network it is paired with

use crate::guessing::CardanoNetwork;

/// A DMQ network (see `DmqNetwork` in `mithril-dmq`)
///
/// The DMQ network has its own magic number, distinct from the one of the Cardano network, but
/// each Cardano network is paired with one DMQ network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmqNetwork {
    /// The DMQ network paired with the Cardano mainnet
    Mainnet,

    /// The DMQ network paired with the Cardano preprod test network
    Preprod,

    /// The DMQ network paired with the Cardano preview test network
    Preview,

    /// The DMQ network paired with a local development network
    Devnet,

    /// Any other DMQ network, identified by its magic number
    Private(u64),
}

impl DmqNetwork {
    const MAINNET_MAGIC: u64 = 2912307721;
    const PREPROD_MAGIC: u64 = 2147483649;
    const PREVIEW_MAGIC: u64 = 2147483650;
    const DEVNET_MAGIC: u64 = 2147483690;

    /// DMQ network paired with the given Cardano network
    ///
    /// A private Cardano network is not paired, since its DMQ magic number can not be deduced.
    pub fn from_cardano_network(network: CardanoNetwork) -> Option<Self> {
        match network {
            CardanoNetwork::Mainnet => Some(Self::Mainnet),
            CardanoNetwork::Preprod => Some(Self::Preprod),
            CardanoNetwork::Preview => Some(Self::Preview),
            CardanoNetwork::Devnet => Some(Self::Devnet),
            CardanoNetwork::Private(_) => None,
        }
    }

    /// Magic number of the network
    pub fn magic(&self) -> u64 {
        match self {
            Self::Mainnet => Self::MAINNET_MAGIC,
            Self::Preprod => Self::PREPROD_MAGIC,
            Self::Preview => Self::PREVIEW_MAGIC,
            Self::Devnet => Self::DEVNET_MAGIC,
            Self::Private(magic) => *magic,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_the_known_cardano_networks_with_their_dmq_network() {
        assert_eq!(
            Some(DmqNetwork::Mainnet),
            DmqNetwork::from_cardano_network(CardanoNetwork::Mainnet)
        );
        assert_eq!(
            Some(DmqNetwork::Preprod),
            DmqNetwork::from_cardano_network(CardanoNetwork::Preprod)
        );
        assert_eq!(
            Some(DmqNetwork::Preview),
            DmqNetwork::from_cardano_network(CardanoNetwork::Preview)
        );
        assert_eq!(
            Some(DmqNetwork::Devnet),
            DmqNetwork::from_cardano_network(CardanoNetwork::Devnet)
        );
    }

    #[test]
    fn does_not_pair_a_private_cardano_network_since_its_dmq_magic_is_unknown() {
        assert_eq!(
            None,
            DmqNetwork::from_cardano_network(CardanoNetwork::Private(4))
        );
    }

    #[test]
    fn gives_the_magic_of_the_network_like_mithril_dmq() {
        assert_eq!(2912307721, DmqNetwork::Mainnet.magic());
        assert_eq!(2147483649, DmqNetwork::Preprod.magic());
        assert_eq!(2147483650, DmqNetwork::Preview.magic());
        assert_eq!(2147483690, DmqNetwork::Devnet.magic());
        assert_eq!(3141592, DmqNetwork::Private(3141592).magic());
    }
}
