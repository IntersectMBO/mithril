use serde_json::{Value, json};

/// A setting of the Kubo configuration, applied with `ipfs config --json <key> <value>`
#[derive(Debug, Clone, PartialEq)]
pub struct KuboConfigSetting {
    /// Dotted key of the setting, e.g. `Provide.Enabled`
    pub key: &'static str,
    /// JSON value of the setting
    pub value: Value,
}

impl KuboConfigSetting {
    /// Arguments of the `ipfs` command that applies this setting
    pub fn config_args(&self) -> Vec<String> {
        vec![
            "config".to_string(),
            "--json".to_string(),
            self.key.to_string(),
            self.value.to_string(),
        ]
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

    /// Arguments of the `ipfs` command that starts the daemon
    pub fn daemon_args() -> Vec<&'static str> {
        vec!["daemon", "--enable-gc"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setting_value(key: &str) -> Value {
        KuboNodeConfig::settings()
            .into_iter()
            .find(|setting| setting.key == key)
            .unwrap_or_else(|| panic!("No setting for key '{key}'"))
            .value
    }

    #[test]
    fn config_args_set_the_json_encoded_value() {
        let setting = KuboConfigSetting {
            key: "Addresses.Swarm",
            value: json!(["/ip4/0.0.0.0/tcp/0"]),
        };

        assert_eq!(
            vec!["config", "--json", "Addresses.Swarm", r#"["/ip4/0.0.0.0/tcp/0"]"#],
            setting.config_args()
        );
    }

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
