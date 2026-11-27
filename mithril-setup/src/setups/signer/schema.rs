//! Configuration values expected by the Mithril signer setup

use crate::rules::{
    FieldRule, absolute_path, http_url, integer_between, ip_address, json_object, no_whitespace,
    one_of, valid_path,
};
use crate::schema::{FieldSpec, Presence};

/// Key of the Cardano node socket path
pub const CARDANO_NODE_SOCKET_PATH: &str = "cardano_node_socket_path";

/// Key of the Cardano CLI path
pub const CARDANO_CLI_PATH: &str = "cardano_cli_path";

/// Key of the Cardano node database directory
pub const DB_DIRECTORY: &str = "db_directory";

/// Key of the Cardano network name
pub const NETWORK: &str = "network";

/// Key of the Cardano network magic
pub const NETWORK_MAGIC: &str = "network_magic";

/// Key of the Cardano KES secret key path
pub const KES_SECRET_KEY_PATH: &str = "kes_secret_key_path";

/// Key of the Cardano operational certificate path
pub const OPERATIONAL_CERTIFICATE_PATH: &str = "operational_certificate_path";

/// Key of the Mithril aggregator endpoint
pub const AGGREGATOR_ENDPOINT: &str = "aggregator_endpoint";

/// Key of the Mithril relay endpoint
pub const RELAY_ENDPOINT: &str = "relay_endpoint";

/// Key of the era reader adapter type
pub const ERA_READER_ADAPTER_TYPE: &str = "era_reader_adapter_type";

/// Key of the era reader adapter parameters
pub const ERA_READER_ADAPTER_PARAMS: &str = "era_reader_adapter_params";

/// Key of the protocol configuration reader adapter configuration
pub const PROTOCOL_CONFIGURATION_READER_ADAPTER_CONFIG: &str =
    "protocol_configuration_reader_adapter_config";

/// Key of the signer data stores directory
pub const DATA_STORES_DIRECTORY: &str = "data_stores_directory";

/// Key of the signer store retention limit
pub const STORE_RETENTION_LIMIT: &str = "store_retention_limit";

/// Key of the signer run interval
pub const RUN_INTERVAL: &str = "run_interval";

/// Key of the signer metrics server activation
pub const ENABLE_METRICS_SERVER: &str = "enable_metrics_server";

/// Key of the signer metrics server IP
pub const METRICS_SERVER_IP: &str = "metrics_server_ip";

/// Key of the signer metrics server port
pub const METRICS_SERVER_PORT: &str = "metrics_server_port";

/// Names of the Cardano networks, as discovered and as expected by the Mithril signer
const NETWORK_NAMES: &[&str] = &["mainnet", "preprod", "preview", "devnet", "private"];

/// Types of the era reader adapter expected by the Mithril signer
// `dummy` is left out, it is for tests only
const ERA_READER_ADAPTER_TYPES: &[&str] =
    &["cardano-chain", "file", "bootstrap", "bootstrap-latest"];

/// Values of a boolean setting
const BOOLEAN_VALUES: &[&str] = &["true", "false"];

/// Rules of a path in the generated configuration
fn path_rules() -> Vec<FieldRule> {
    vec![valid_path(), absolute_path(), no_whitespace()]
}

/// Rules of an endpoint in the generated configuration
fn endpoint_rules() -> Vec<FieldRule> {
    vec![http_url(), no_whitespace()]
}

/// Configuration values expected to setup a Mithril signer
pub fn signer_schema() -> Vec<FieldSpec> {
    vec![
        // Cardano node
        FieldSpec {
            key: CARDANO_NODE_SOCKET_PATH,
            label: "Cardano node socket path",
            description: "Path of the IPC socket of the Cardano node",
            presence: Presence::Required,
            rules: path_rules(),
        },
        FieldSpec {
            key: CARDANO_CLI_PATH,
            label: "Cardano CLI path",
            description: "Path of the cardano-cli executable, or its name if it is in the PATH",
            presence: Presence::Required,
            // Not required to be absolute, the signer accepts a command name like cardano-cli
            rules: vec![valid_path(), no_whitespace()],
        },
        FieldSpec {
            key: DB_DIRECTORY,
            label: "DB directory",
            description: "Directory of the Cardano node database",
            presence: Presence::Required,
            rules: path_rules(),
        },
        FieldSpec {
            key: NETWORK,
            label: "Network",
            description: "Name of the Cardano network: mainnet, preprod, preview, devnet or private",
            presence: Presence::Required,
            rules: vec![one_of(NETWORK_NAMES)],
        },
        FieldSpec {
            key: NETWORK_MAGIC,
            label: "Network magic",
            description: "Magic number of the Cardano network, for the devnet and private networks",
            presence: Presence::Optional,
            rules: vec![integer_between(0, u64::MAX)],
        },
        FieldSpec {
            key: KES_SECRET_KEY_PATH,
            label: "KES secret key path",
            description: "Path of the Cardano KES secret key file of the pool",
            presence: Presence::Required,
            rules: path_rules(),
        },
        FieldSpec {
            key: OPERATIONAL_CERTIFICATE_PATH,
            label: "Operational certificate path",
            description: "Path of the Cardano operational certificate file of the pool",
            presence: Presence::Required,
            rules: path_rules(),
        },
        // Mithril network
        FieldSpec {
            key: AGGREGATOR_ENDPOINT,
            label: "Aggregator endpoint",
            description: "Endpoint of the Mithril aggregator of the network",
            presence: Presence::Required,
            rules: endpoint_rules(),
        },
        FieldSpec {
            key: RELAY_ENDPOINT,
            label: "Relay endpoint",
            description: "Endpoint of the Mithril relay sending the signatures to the aggregator",
            presence: Presence::Optional,
            rules: endpoint_rules(),
        },
        FieldSpec {
            key: ERA_READER_ADAPTER_TYPE,
            label: "Era reader adapter type",
            description: "Type of the era reader adapter: cardano-chain, file, bootstrap or bootstrap-latest",
            presence: Presence::Required,
            rules: vec![one_of(ERA_READER_ADAPTER_TYPES)],
        },
        FieldSpec {
            key: ERA_READER_ADAPTER_PARAMS,
            label: "Era reader adapter params",
            description: "Parameters of the era reader adapter, as a JSON object",
            presence: Presence::Optional,
            rules: vec![json_object()],
        },
        FieldSpec {
            key: PROTOCOL_CONFIGURATION_READER_ADAPTER_CONFIG,
            label: "Protocol config reader",
            description: "Configuration of the protocol configuration reader adapter, as a JSON object",
            presence: Presence::Optional,
            rules: vec![json_object()],
        },
        // Mithril signer
        FieldSpec {
            key: DATA_STORES_DIRECTORY,
            label: "Data stores directory",
            description: "Directory where the signer stores its data",
            presence: Presence::Required,
            rules: path_rules(),
        },
        FieldSpec {
            key: STORE_RETENTION_LIMIT,
            label: "Store retention limit",
            description: "Maximum number of records kept in the signer stores, no limit if unset",
            presence: Presence::Optional,
            rules: vec![integer_between(1, u64::MAX)],
        },
        FieldSpec {
            key: RUN_INTERVAL,
            label: "Run interval",
            description: "Interval between two runtime cycles of the signer, in milliseconds",
            presence: Presence::Required,
            rules: vec![integer_between(1, u64::MAX)],
        },
        FieldSpec {
            key: ENABLE_METRICS_SERVER,
            label: "Enable metrics server",
            description: "Whether the signer runs its metrics server (Prometheus endpoint on /metrics): true or false",
            presence: Presence::Required,
            rules: vec![one_of(BOOLEAN_VALUES)],
        },
        FieldSpec {
            key: METRICS_SERVER_IP,
            label: "Metrics server IP",
            description: "IP address the signer metrics server listens on, 0.0.0.0 if unset",
            presence: Presence::Optional,
            rules: vec![ip_address()],
        },
        FieldSpec {
            key: METRICS_SERVER_PORT,
            label: "Metrics server port",
            description: "Listening port of the signer metrics server, 9090 if unset",
            presence: Presence::Optional,
            rules: vec![integer_between(1, u16::MAX as u64)],
        },
    ]
}

#[cfg(test)]
mod tests {
    use crate::schema::{FieldError, check_store};
    use crate::store::{Origin, Store};

    use super::*;

    fn valid_store() -> Store {
        let mut store = Store::default();
        for (key, value) in [
            (CARDANO_NODE_SOCKET_PATH, "/ipc/node.socket"),
            (CARDANO_CLI_PATH, "/usr/local/bin/cardano-cli"),
            (DB_DIRECTORY, "/cardano/db"),
            (NETWORK, "preview"),
            (KES_SECRET_KEY_PATH, "/cardano/keys/kes.skey"),
            (OPERATIONAL_CERTIFICATE_PATH, "/cardano/keys/node.cert"),
            (
                AGGREGATOR_ENDPOINT,
                "https://aggregator.example.com/aggregator",
            ),
            (ERA_READER_ADAPTER_TYPE, "cardano-chain"),
            (ERA_READER_ADAPTER_PARAMS, r#"{"address": "addr_test1"}"#),
            (DATA_STORES_DIRECTORY, "/opt/mithril/stores"),
            (RUN_INTERVAL, "60000"),
            (ENABLE_METRICS_SERVER, "true"),
        ] {
            store.set(key, value, Origin::Guessed);
        }
        store
    }

    #[test]
    fn accepts_a_valid_store() {
        assert_eq!(Ok(()), check_store(&signer_schema(), &valid_store()));
    }

    #[test]
    fn accepts_the_network_names_of_the_discovery() {
        for network in NETWORK_NAMES {
            let mut store = valid_store();
            store.set(NETWORK, network, Origin::Discovered);

            assert_eq!(Ok(()), check_store(&signer_schema(), &store), "{network}");
        }
    }

    #[test]
    fn accepts_the_era_reader_adapter_types_of_the_signer() {
        for adapter_type in ERA_READER_ADAPTER_TYPES {
            let mut store = valid_store();
            store.set(ERA_READER_ADAPTER_TYPE, adapter_type, Origin::User);

            assert_eq!(
                Ok(()),
                check_store(&signer_schema(), &store),
                "{adapter_type}"
            );
        }
    }

    #[test]
    fn accepts_a_cardano_cli_command_name_instead_of_a_path() {
        let mut store = valid_store();
        store.set(CARDANO_CLI_PATH, "cardano-cli", Origin::User);

        assert_eq!(Ok(()), check_store(&signer_schema(), &store));
    }

    #[test]
    fn a_path_can_fail_several_rules_at_once() {
        let mut store = valid_store();
        store.set(DB_DIRECTORY, "my db", Origin::User);

        assert_eq!(
            Err(vec![
                FieldError::new(DB_DIRECTORY, "'my db' is not an absolute path"),
                FieldError::new(DB_DIRECTORY, "'my db' contains whitespace"),
            ]),
            check_store(&signer_schema(), &store)
        );
    }
}
