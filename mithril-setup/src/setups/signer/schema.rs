//! Configuration values expected by the Mithril signer setup

use crate::rules::{integer_between, one_of, valid_path};
use crate::schema::{FieldSpec, Presence};

/// Key of the Cardano node socket path
pub const CARDANO_NODE_SOCKET_PATH: &str = "cardano_node_socket_path";

/// Key of the Cardano network name
pub const NETWORK: &str = "network";

/// Key of the Cardano network magic
pub const NETWORK_MAGIC: &str = "network_magic";

/// Configuration values expected to setup a Mithril signer
pub fn signer_schema() -> Vec<FieldSpec> {
    vec![
        FieldSpec {
            key: CARDANO_NODE_SOCKET_PATH,
            label: "Cardano node socket path",
            description: "Path of the IPC socket of the Cardano node",
            presence: Presence::Required,
            rules: vec![valid_path()],
        },
        FieldSpec {
            key: NETWORK,
            label: "Network",
            description: "Name of the Cardano network",
            presence: Presence::Required,
            rules: vec![one_of(&["mainnet", "preprod", "preview"])],
        },
        FieldSpec {
            key: NETWORK_MAGIC,
            label: "Network magic",
            description: "Magic number of the Cardano network",
            presence: Presence::Optional,
            rules: vec![integer_between(0, u32::MAX as u64)],
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::schema::check_store;
    use crate::store::{Origin, Store};

    use super::*;

    fn valid_store() -> Store {
        let mut store = Store::default();
        store.set(
            CARDANO_NODE_SOCKET_PATH,
            "/ipc/node.socket",
            Origin::Discovered,
        );
        store.set(NETWORK, "preview", Origin::Guessed);
        store.set(NETWORK_MAGIC, "2", Origin::Guessed);
        store
    }

    #[test]
    fn accepts_a_valid_store() {
        assert_eq!(Ok(()), check_store(&signer_schema(), &valid_store()));
    }
}
