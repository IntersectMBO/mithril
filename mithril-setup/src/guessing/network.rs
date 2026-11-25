//! Cardano network, guessed from the magic number of the Shelley genesis

/// A Cardano network, named like the Mithril signer expects it (see `CardanoNetwork` in
/// `mithril-common`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardanoNetwork {
    /// The Cardano mainnet
    Mainnet,

    /// The Cardano preprod test network
    Preprod,

    /// The Cardano preview test network
    Preview,

    /// A local development network
    Devnet,

    /// Any other test network, identified by its magic number
    Private(u32),
}

impl CardanoNetwork {
    const MAINNET_MAGIC: u32 = 764824073;
    const PREPROD_MAGIC: u32 = 1;
    const PREVIEW_MAGIC: u32 = 2;
    const DEVNET_MAGIC: u32 = 42;

    /// Network identified by the given magic number
    pub fn from_magic(magic: u32) -> Self {
        match magic {
            Self::MAINNET_MAGIC => Self::Mainnet,
            Self::PREPROD_MAGIC => Self::Preprod,
            Self::PREVIEW_MAGIC => Self::Preview,
            Self::DEVNET_MAGIC => Self::Devnet,
            _ => Self::Private(magic),
        }
    }

    /// Network identified by the given name, ie: `preview`, ignoring case
    ///
    /// A `private` network is not identified, since its name does not give its magic number.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "mainnet" => Some(Self::Mainnet),
            "preprod" => Some(Self::Preprod),
            "preview" => Some(Self::Preview),
            "devnet" => Some(Self::Devnet),
            _ => None,
        }
    }

    /// Magic number of the network
    pub fn magic(&self) -> u32 {
        match self {
            Self::Mainnet => Self::MAINNET_MAGIC,
            Self::Preprod => Self::PREPROD_MAGIC,
            Self::Preview => Self::PREVIEW_MAGIC,
            Self::Devnet => Self::DEVNET_MAGIC,
            Self::Private(magic) => *magic,
        }
    }

    /// Name of the network, ie: `preview`
    pub fn name(&self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Preprod => "preprod",
            Self::Preview => "preview",
            Self::Devnet => "devnet",
            Self::Private(_) => "private",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_the_known_networks_by_their_magic() {
        assert_eq!(
            CardanoNetwork::Mainnet,
            CardanoNetwork::from_magic(764824073)
        );
        assert_eq!(CardanoNetwork::Preprod, CardanoNetwork::from_magic(1));
        assert_eq!(CardanoNetwork::Preview, CardanoNetwork::from_magic(2));
        assert_eq!(CardanoNetwork::Devnet, CardanoNetwork::from_magic(42));
    }

    #[test]
    fn identifies_any_other_magic_as_a_private_network() {
        assert_eq!(CardanoNetwork::Private(4), CardanoNetwork::from_magic(4));
    }

    #[test]
    fn gives_back_the_magic_of_the_network() {
        for magic in [764824073, 1, 2, 42, 4] {
            assert_eq!(magic, CardanoNetwork::from_magic(magic).magic());
        }
    }

    #[test]
    fn names_the_networks_like_the_mithril_signer_expects() {
        assert_eq!("mainnet", CardanoNetwork::Mainnet.name());
        assert_eq!("preprod", CardanoNetwork::Preprod.name());
        assert_eq!("preview", CardanoNetwork::Preview.name());
        assert_eq!("devnet", CardanoNetwork::Devnet.name());
        assert_eq!("private", CardanoNetwork::Private(4).name());
    }

    #[test]
    fn identifies_the_known_networks_by_their_name() {
        assert_eq!(
            Some(CardanoNetwork::Mainnet),
            CardanoNetwork::from_name("mainnet")
        );
        assert_eq!(
            Some(CardanoNetwork::Preprod),
            CardanoNetwork::from_name("preprod")
        );
        assert_eq!(
            Some(CardanoNetwork::Preview),
            CardanoNetwork::from_name("preview")
        );
        assert_eq!(
            Some(CardanoNetwork::Devnet),
            CardanoNetwork::from_name("devnet")
        );
    }

    #[test]
    fn identifies_a_network_by_its_name_ignoring_case() {
        assert_eq!(
            Some(CardanoNetwork::Preview),
            CardanoNetwork::from_name("Preview")
        );
    }

    #[test]
    fn does_not_identify_a_private_network_by_its_name_since_its_magic_is_unknown() {
        assert_eq!(None, CardanoNetwork::from_name("private"));
    }

    #[test]
    fn does_not_identify_an_unknown_name() {
        assert_eq!(None, CardanoNetwork::from_name("sanchonet"));
    }

    #[test]
    fn gives_back_the_network_from_its_name() {
        for network in [
            CardanoNetwork::Mainnet,
            CardanoNetwork::Preprod,
            CardanoNetwork::Preview,
            CardanoNetwork::Devnet,
        ] {
            assert_eq!(Some(network), CardanoNetwork::from_name(network.name()));
        }
    }
}
