use std::fs;
use std::path::Path;

use anyhow::Context;
use serde_json::{Map, Value, json};

use mithril_client::MithrilResult;

/// A setting of the Kubo configuration
#[derive(Debug, Clone, PartialEq)]
pub struct KuboConfigSetting {
    /// Dotted key of the setting, e.g. `Provide.Enabled`
    pub key: &'static str,
    /// JSON value of the setting
    pub value: Value,
}

impl KuboConfigSetting {
    /// Set this setting in the JSON `config` of a Kubo repository, creating the missing (or null)
    /// objects of its key, as `ipfs config --json <key> <value>` does
    pub fn apply_to(&self, config: &mut Value) -> MithrilResult<()> {
        let mut current = config;
        for part in self.key.split('.') {
            if current.is_null() {
                *current = Value::Object(Map::new());
            }
            current = current
                .as_object_mut()
                .with_context(|| {
                    format!(
                        "Can not set the Kubo setting '{}': the parent of '{part}' is not an object",
                        self.key
                    )
                })?
                .entry(part)
                .or_insert(Value::Null);
        }
        *current = self.value.clone();

        Ok(())
    }
}

/// Configuration of the short-lived Kubo node managed by the client for the duration of a
/// download.
///
/// The node:
/// - exposes its RPC API on a random port of the loopback interface only (the actual address is
///   written by Kubo in the `api` file of its repository), and no gateway
/// - does not scan the local network nor open ports through UPnP, and does not dial nor announce
///   private and loopback addresses (`server` profile), so peers only reachable on a private
///   network can not be used
/// - does not listen for inbound connections, which it does not need as it only downloads (and
///   would otherwise trigger a firewall prompt on each run on Windows and macOS)
/// - connects to its peers through TCP only, as the QUIC throughput is capped by the default UDP
///   receive buffer size of the OS, which can only be raised with admin privileges
/// - leaves no trace on the network once removed: it does not announce the downloaded blocks in
///   the DHT, is a DHT client only, does not serve blocks to other peers, does not relay nor
///   get relayed, does not request an AutoTLS certificate, and does not send telemetry
/// - soft bounds its datastore with a frequent automatic GC, as the default GC period (1 h) never
///   triggers during a download and the datastore otherwise grows to the size of the downloaded
///   files. The GC only runs once the datastore exceeds the `StorageGCWatermark` percentage of
///   `StorageMax`, so the datastore can grow up to this threshold plus what is downloaded during
///   one `GCPeriod`. The GC can remove the blocks of a file that is still streamed, which Kubo
///   then fetches again from the network (or ends the stream with an `X-Stream-Error` trailer
///   if it can not)
pub struct KuboNodeConfig;

impl KuboNodeConfig {
    /// Arguments of the `ipfs` command that initializes the repository
    pub fn init_args() -> Vec<&'static str> {
        vec!["init", "--profile", "server"]
    }

    /// Settings applied to the initialized repository, before starting the daemon
    pub fn settings() -> Vec<KuboConfigSetting> {
        [
            ("Addresses.API", json!("/ip4/127.0.0.1/tcp/0")),
            ("Addresses.Gateway", json!([])),
            ("Addresses.Swarm", json!([])),
            ("Swarm.Transports.Network.QUIC", json!(false)),
            ("Swarm.Transports.Network.WebTransport", json!(false)),
            ("Swarm.Transports.Network.WebRTCDirect", json!(false)),
            ("Swarm.RelayClient.Enabled", json!(false)),
            ("Swarm.RelayService.Enabled", json!(false)),
            ("Routing.Type", json!("autoclient")),
            ("Provide.Enabled", json!(false)),
            ("Bitswap.ServerEnabled", json!(false)),
            ("AutoTLS.Enabled", json!(false)),
            ("Plugins.Plugins.telemetry.Config.Mode", json!("off")),
            ("Datastore.StorageMax", json!("2GB")),
            ("Datastore.StorageGCWatermark", json!(90)),
            ("Datastore.GCPeriod", json!("15s")),
        ]
        .into_iter()
        .map(|(key, value)| KuboConfigSetting { key, value })
        .collect()
    }

    /// Apply the [settings][Self::settings] to the JSON configuration file of an initialized
    /// repository, keeping its other values
    pub fn apply_settings_to_file(config_path: &Path) -> MithrilResult<()> {
        let mut config: Value = serde_json::from_str(
            &fs::read_to_string(config_path)
                .with_context(|| format!("Failed to read '{}'", config_path.display()))?,
        )
        .with_context(|| format!("Failed to parse '{}'", config_path.display()))?;
        for setting in Self::settings() {
            setting.apply_to(&mut config)?;
        }
        fs::write(config_path, serde_json::to_string_pretty(&config)?)
            .with_context(|| format!("Failed to write '{}'", config_path.display()))?;

        Ok(())
    }

    /// Arguments of the `ipfs` command that starts the daemon
    pub fn daemon_args() -> Vec<&'static str> {
        vec!["daemon", "--enable-gc"]
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::temp_dir_create;

    use super::*;

    fn setting_value(key: &str) -> Value {
        KuboNodeConfig::settings()
            .into_iter()
            .find(|setting| setting.key == key)
            .unwrap_or_else(|| panic!("No setting for key '{key}'"))
            .value
    }

    mod settings {
        use super::*;

        #[test]
        fn repository_is_initialized_with_the_server_profile_to_not_scan_the_local_network() {
            assert_eq!(
                vec!["init", "--profile", "server"],
                KuboNodeConfig::init_args()
            );
        }

        #[test]
        fn rpc_api_listens_on_a_random_port_of_the_loopback_interface() {
            assert_eq!(
                json!("/ip4/127.0.0.1/tcp/0"),
                setting_value("Addresses.API")
            );
        }

        #[test]
        fn gateway_is_disabled() {
            assert_eq!(json!([]), setting_value("Addresses.Gateway"));
        }

        #[test]
        fn swarm_does_not_listen_and_uses_tcp_only() {
            assert_eq!(json!([]), setting_value("Addresses.Swarm"));
            // QUIC throughput is capped by the default UDP receive buffer size of the OS
            for transport in ["QUIC", "WebTransport", "WebRTCDirect"] {
                assert_eq!(
                    json!(false),
                    setting_value(&format!("Swarm.Transports.Network.{transport}")),
                    "{transport} transport should be disabled"
                );
            }
        }

        #[test]
        fn downloaded_blocks_are_not_provided_to_the_dht() {
            assert_eq!(json!(false), setting_value("Provide.Enabled"));
        }

        #[test]
        fn auto_tls_is_disabled() {
            assert_eq!(json!(false), setting_value("AutoTLS.Enabled"));
        }

        #[test]
        fn node_does_not_relay_and_is_not_relayed() {
            assert_eq!(json!(false), setting_value("Swarm.RelayClient.Enabled"));
            assert_eq!(json!(false), setting_value("Swarm.RelayService.Enabled"));
        }

        #[test]
        fn node_is_a_dht_client_only() {
            assert_eq!(json!("autoclient"), setting_value("Routing.Type"));
        }

        #[test]
        fn downloaded_blocks_are_not_served_to_other_peers() {
            assert_eq!(json!(false), setting_value("Bitswap.ServerEnabled"));
        }

        #[test]
        fn telemetry_is_disabled() {
            assert_eq!(
                json!("off"),
                setting_value("Plugins.Plugins.telemetry.Config.Mode")
            );
        }

        #[test]
        fn datastore_is_bounded_by_a_frequent_automatic_gc() {
            assert_eq!(json!("2GB"), setting_value("Datastore.StorageMax"));
            assert_eq!(json!(90), setting_value("Datastore.StorageGCWatermark"));
            assert_eq!(json!("15s"), setting_value("Datastore.GCPeriod"));
            assert_eq!(vec!["daemon", "--enable-gc"], KuboNodeConfig::daemon_args());
        }

        #[test]
        fn each_setting_key_is_set_once() {
            let mut keys: Vec<&str> =
                KuboNodeConfig::settings().iter().map(|setting| setting.key).collect();
            let settings_count = keys.len();
            keys.sort();
            keys.dedup();

            assert_eq!(settings_count, keys.len());
        }
    }

    mod apply_settings_to_file {
        use super::*;

        #[test]
        fn applies_the_settings_and_keeps_the_other_values() {
            let config_path = temp_dir_create!().join("config");
            fs::write(&config_path, r#"{"Identity": {"PeerID": "peer"}}"#).unwrap();

            KuboNodeConfig::apply_settings_to_file(&config_path).unwrap();

            let config: Value =
                serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
            assert_eq!("peer", config["Identity"]["PeerID"]);
            for setting in KuboNodeConfig::settings() {
                let pointer = format!("/{}", setting.key.replace('.', "/"));
                assert_eq!(
                    Some(&setting.value),
                    config.pointer(&pointer),
                    "{}",
                    setting.key
                );
            }
        }

        #[test]
        fn fails_when_the_config_file_does_not_exist() {
            KuboNodeConfig::apply_settings_to_file(&temp_dir_create!().join("config"))
                .expect_err("Should fail when the config file does not exist");
        }
    }

    mod apply_to {
        use super::*;

        fn setting(key: &'static str, value: Value) -> KuboConfigSetting {
            KuboConfigSetting { key, value }
        }

        #[test]
        fn replaces_the_value_of_an_existing_key_and_keeps_the_others() {
            let mut config = json!({"Addresses": {"API": "/ip4/127.0.0.1/tcp/5001", "Gateway": "x"}, "Other": 1});

            setting("Addresses.API", json!("/ip4/127.0.0.1/tcp/0"))
                .apply_to(&mut config)
                .unwrap();

            assert_eq!(
                json!({"Addresses": {"API": "/ip4/127.0.0.1/tcp/0", "Gateway": "x"}, "Other": 1}),
                config
            );
        }

        #[test]
        fn creates_the_missing_or_null_objects_of_the_key() {
            let mut config = json!({"Plugins": {"Plugins": null}});

            setting("Plugins.Plugins.telemetry.Config.Mode", json!("off"))
                .apply_to(&mut config)
                .unwrap();

            assert_eq!(
                json!({"Plugins": {"Plugins": {"telemetry": {"Config": {"Mode": "off"}}}}}),
                config
            );
        }

        #[test]
        fn fails_when_a_parent_of_the_key_is_not_an_object() {
            let mut config = json!({"Addresses": "not an object"});

            setting("Addresses.API", json!("/ip4/127.0.0.1/tcp/0"))
                .apply_to(&mut config)
                .expect_err("Should fail when a parent of the key is not an object");
        }
    }
}
