//! Parsing of the `cardano-node run` command line

/// Options of a `cardano-node run` command line relevant to the discovery
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct NodeCommandLine {
    pub socket_path: Option<String>,
    pub database_path: Option<String>,
    pub config: Option<String>,
    pub topology: Option<String>,
    pub kes_key: Option<String>,
    pub operational_certificate: Option<String>,
    pub host_addr: Option<String>,
    pub host_ipv6_addr: Option<String>,
    pub port: Option<String>,
    pub kes_agent_socket: Option<String>,
    pub bulk_credentials_file: Option<String>,
    pub immutable_database_path: Option<String>,
    pub volatile_database_path: Option<String>,
    pub start_as_non_producing_node: bool,
}

impl NodeCommandLine {
    /// Parse the arguments (without the program name) of a `cardano-node` process
    ///
    /// Supports both the `--option value` and `--option=value` forms, unknown arguments are ignored.
    pub fn parse(args: &[String]) -> Self {
        let mut command_line = Self::default();
        let mut args = args.iter().peekable();

        while let Some(arg) = args.next() {
            let Some(option) = arg.strip_prefix("--") else {
                continue;
            };
            if NON_PRODUCING_NODE_FLAGS.contains(&option) {
                command_line.start_as_non_producing_node = true;
                continue;
            }
            let (name, value) = match option.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (
                    option,
                    args.next_if(|next| !next.starts_with("--")).cloned(),
                ),
            };

            let field = match name {
                "socket-path" => &mut command_line.socket_path,
                "database-path" => &mut command_line.database_path,
                "config" => &mut command_line.config,
                "topology" => &mut command_line.topology,
                "shelley-kes-key" => &mut command_line.kes_key,
                "shelley-operational-certificate" => &mut command_line.operational_certificate,
                "host-addr" => &mut command_line.host_addr,
                "host-ipv6-addr" => &mut command_line.host_ipv6_addr,
                "port" => &mut command_line.port,
                "shelley-kes-agent-socket" => &mut command_line.kes_agent_socket,
                "bulk-credentials-file" => &mut command_line.bulk_credentials_file,
                "immutable-database-path" => &mut command_line.immutable_database_path,
                "volatile-database-path" => &mut command_line.volatile_database_path,
                _ => continue,
            };
            if value.is_some() {
                *field = value;
            }
        }

        command_line
    }

    /// A block producer is started with its credentials, and not as a non-producing node
    ///
    /// The credentials are either a KES key with an operational certificate, a KES agent socket
    /// (the agent provides both), or a bulk credentials file.
    pub fn is_block_producer(&self) -> bool {
        let has_credentials = (self.kes_key.is_some() && self.operational_certificate.is_some())
            || self.kes_agent_socket.is_some()
            || self.bulk_credentials_file.is_some();

        has_credentials && !self.start_as_non_producing_node
    }
}

/// Flags (without value) starting the node as a non-producing node, the second one is deprecated
const NON_PRODUCING_NODE_FLAGS: [&str; 2] = ["start-as-non-producing-node", "non-producing-node"];

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> NodeCommandLine {
        let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
        NodeCommandLine::parse(&args)
    }

    #[test]
    fn parses_an_empty_command_line() {
        assert_eq!(NodeCommandLine::default(), parse(&[]));
    }

    #[test]
    fn parses_all_the_options_of_a_block_producer() {
        let command_line = parse(&[
            "run",
            "--topology",
            "/opt/cardano/topology.json",
            "--database-path",
            "/opt/cardano/db",
            "--socket-path",
            "/opt/cardano/node.socket",
            "--host-addr",
            "0.0.0.0",
            "--host-ipv6-addr",
            "::",
            "--port",
            "3001",
            "--config",
            "/opt/cardano/config.json",
            "--shelley-kes-key",
            "/opt/cardano/kes.skey",
            "--shelley-vrf-key",
            "/opt/cardano/vrf.skey",
            "--shelley-operational-certificate",
            "/opt/cardano/node.cert",
        ]);

        assert_eq!(
            NodeCommandLine {
                socket_path: Some("/opt/cardano/node.socket".to_string()),
                database_path: Some("/opt/cardano/db".to_string()),
                config: Some("/opt/cardano/config.json".to_string()),
                topology: Some("/opt/cardano/topology.json".to_string()),
                kes_key: Some("/opt/cardano/kes.skey".to_string()),
                operational_certificate: Some("/opt/cardano/node.cert".to_string()),
                host_addr: Some("0.0.0.0".to_string()),
                host_ipv6_addr: Some("::".to_string()),
                port: Some("3001".to_string()),
                ..NodeCommandLine::default()
            },
            command_line
        );
    }

    #[test]
    fn parses_the_alternative_credentials_and_database_options() {
        let command_line = parse(&[
            "run",
            "--shelley-kes-agent-socket",
            "/run/kes-agent.socket",
            "--bulk-credentials-file",
            "/opt/cardano/bulk.creds",
            "--immutable-database-path",
            "/mnt/slow/immutable",
            "--volatile-database-path",
            "/mnt/fast/volatile",
        ]);

        assert_eq!(
            NodeCommandLine {
                kes_agent_socket: Some("/run/kes-agent.socket".to_string()),
                bulk_credentials_file: Some("/opt/cardano/bulk.creds".to_string()),
                immutable_database_path: Some("/mnt/slow/immutable".to_string()),
                volatile_database_path: Some("/mnt/fast/volatile".to_string()),
                ..NodeCommandLine::default()
            },
            command_line
        );
    }

    #[test]
    fn parses_the_non_producing_node_flag_and_its_deprecated_alias() {
        assert!(!parse(&["run"]).start_as_non_producing_node);
        assert!(parse(&["run", "--start-as-non-producing-node"]).start_as_non_producing_node);
        assert!(parse(&["run", "--non-producing-node"]).start_as_non_producing_node);
    }

    #[test]
    fn a_value_less_flag_does_not_take_the_next_argument_as_its_value() {
        let command_line = parse(&["--start-as-non-producing-node", "run", "--port", "3001"]);

        assert!(command_line.start_as_non_producing_node);
        assert_eq!(Some("3001".to_string()), command_line.port);
    }

    #[test]
    fn parses_options_given_with_an_equal_sign() {
        let command_line = parse(&["run", "--socket-path=/ipc/node.socket", "--port=6000"]);

        assert_eq!(
            NodeCommandLine {
                socket_path: Some("/ipc/node.socket".to_string()),
                port: Some("6000".to_string()),
                ..NodeCommandLine::default()
            },
            command_line
        );
    }

    #[test]
    fn ignores_unknown_arguments_and_flags() {
        let command_line = parse(&[
            "run",
            "--validate-db",
            "--mempool-capacity-override",
            "1000",
            "--port",
            "3001",
        ]);

        assert_eq!(
            NodeCommandLine {
                port: Some("3001".to_string()),
                ..NodeCommandLine::default()
            },
            command_line
        );
    }

    #[test]
    fn ignores_an_option_missing_its_value() {
        assert_eq!(NodeCommandLine::default(), parse(&["run", "--port"]));
    }

    #[test]
    fn a_node_with_a_kes_key_and_an_operational_certificate_is_a_block_producer() {
        let command_line = parse(&[
            "run",
            "--shelley-kes-key",
            "kes.skey",
            "--shelley-operational-certificate",
            "node.cert",
        ]);

        assert!(command_line.is_block_producer());
    }

    #[test]
    fn a_node_without_kes_key_or_operational_certificate_is_not_a_block_producer() {
        assert!(!parse(&["run", "--port", "3001"]).is_block_producer());
        assert!(!parse(&["run", "--shelley-kes-key", "kes.skey"]).is_block_producer());
        assert!(
            !parse(&["run", "--shelley-operational-certificate", "node.cert"]).is_block_producer()
        );
    }

    #[test]
    fn a_node_using_a_kes_agent_is_a_block_producer() {
        // The KES agent provides both the KES key and the operational certificate
        let command_line = parse(&["run", "--shelley-kes-agent-socket", "/run/kes-agent.socket"]);

        assert!(command_line.is_block_producer());
    }

    #[test]
    fn a_node_using_a_bulk_credentials_file_is_a_block_producer() {
        let command_line = parse(&["run", "--bulk-credentials-file", "bulk.creds"]);

        assert!(command_line.is_block_producer());
    }

    #[test]
    fn a_node_started_as_non_producing_is_not_a_block_producer_even_with_credentials() {
        let command_line = parse(&[
            "run",
            "--shelley-kes-key",
            "kes.skey",
            "--shelley-operational-certificate",
            "node.cert",
            "--start-as-non-producing-node",
        ]);

        assert!(!command_line.is_block_producer());
    }
}
