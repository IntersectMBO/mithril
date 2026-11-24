use anyhow::Context;
use serde::Deserialize;

/// Node topology file (the file given by `--topology`), only the keys used by the discovery
///
/// Both the P2P format (`localRoots`) and the legacy format (`Producers`) are supported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct TopologyConfiguration {
    /// Groups of peers the node always stays connected to (P2P format)
    #[serde(rename = "localRoots", default)]
    pub local_roots: Vec<LocalRootGroup>,

    /// Peers the node connects to (legacy format)
    #[serde(rename = "Producers", default)]
    pub producers: Vec<LegacyProducer>,
}

/// A group of local root peers of the P2P topology format
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct LocalRootGroup {
    /// Peers of the group
    #[serde(rename = "accessPoints", default)]
    pub access_points: Vec<Peer>,

    /// Whether the group is advertised to other nodes (P2P format)
    #[serde(default)]
    pub advertised: Option<bool>,

    /// Whether the group is trustable by other nodes (P2P format)
    #[serde(default)]
    pub trustable: Option<bool>,
}

/// A peer of the legacy topology format
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct LegacyProducer {
    /// IP address or DNS name of the peer
    pub addr: String,

    /// Port of the peer
    pub port: u16,
}

/// A peer the node connects to
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Peer {
    /// IP address or DNS name of the peer
    pub address: String,

    /// Port of the peer
    pub port: u16,

    /// Whether the group is advertised to other nodes (P2P format)
    pub advertised: Option<bool>,

    /// Whether the group is trustable by other nodes (P2P format)
    pub trustable: Option<bool>,
}

impl TopologyConfiguration {
    /// Parse the content of a node topology file
    pub fn parse(content: &str) -> anyhow::Result<Self> {
        serde_json::from_str(content).context("The node topology is not a valid JSON")
    }

    /// Peers of the pool the node always stays connected to
    ///
    /// On a block producer, these are the relays of the pool. Public roots and bootstrap peers
    /// are not part of the pool and are left out.
    pub fn pool_peers(&self) -> Vec<Peer> {
        let local_roots = self.local_roots.iter().flat_map(|group| group.access_points.clone());
        let producers = self.producers.iter().map(|producer| Peer {
            address: producer.addr.clone(),
            port: producer.port,
            advertised: None,
            trustable: None,
        });

        local_roots.chain(producers).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(address: &str, port: u16) -> Peer {
        Peer {
            address: address.to_string(),
            port,
            advertised: None,
            trustable: None,
        }
    }

    #[test]
    fn gives_the_local_roots_of_a_p2p_topology_as_pool_peers() {
        let topology = TopologyConfiguration::parse(
            r#"{
            "localRoots": [
                {
                "accessPoints": [
                    { "address": "relay1.example.com", "port": 3001 },
                    { "address": "192.168.1.30", "port": 3002 }
                ]
                },
                {
                "accessPoints": [{ "address": "10.0.0.5", "port": 6000 }]
                }
            ]
        }"#,
        )
        .unwrap();

        assert_eq!(
            vec![
                peer("relay1.example.com", 3001),
                peer("192.168.1.30", 3002),
                peer("10.0.0.5", 6000),
            ],
            topology.pool_peers()
        );
    }

    #[test]
    fn gives_the_producers_of_a_legacy_topology_as_pool_peers() {
        let topology = TopologyConfiguration::parse(
            r#"{
            "Producers": [
                { "addr": "relay1.example.com", "port": 3001 },
                { "addr": "192.168.1.30", "port": 3002 }
            ]
            }"#,
        )
        .unwrap();

        assert_eq!(
            vec![peer("relay1.example.com", 3001), peer("192.168.1.30", 3002)],
            topology.pool_peers()
        );
    }

    #[test]
    fn reads_the_advertised_and_trustable_flags_of_a_local_root_group() {
        let topology = TopologyConfiguration::parse(
            r#"{
            "localRoots": [
                {
                "accessPoints": [{ "address": "relay1.example.com", "port": 3001 }],
                "advertised": true,
                "trustable": false
                },
                {
                "accessPoints": [{ "address": "relay2.example.com", "port": 3002 }],
                "advertised": false,
                "trustable": true
                }
            ]
        }"#,
        )
        .unwrap();

        let flags: Vec<_> = topology
            .local_roots
            .iter()
            .map(|group| (group.advertised, group.trustable))
            .collect();
        assert_eq!(vec![(Some(true), Some(false)), (Some(false), Some(true))], flags);
    }

    #[test]
    fn leaves_the_advertised_and_trustable_flags_of_a_local_root_group_unset_when_missing() {
        let topology = TopologyConfiguration::parse(
            r#"{
            "localRoots": [
                { "accessPoints": [{ "address": "relay1.example.com", "port": 3001 }] }
            ]
        }"#,
        )
        .unwrap();

        let group = &topology.local_roots[0];
        assert_eq!((None, None), (group.advertised, group.trustable));
    }

    #[test]
    fn reads_the_advertised_and_trustable_flags_of_a_local_root_peer() {
        let topology = TopologyConfiguration::parse(
            r#"{
            "localRoots": [
                {
                "accessPoints": [
                    { "address": "relay1.example.com", "port": 3001, "advertised": true, "trustable": false },
                    { "address": "relay2.example.com", "port": 3002, "advertised": false, "trustable": true },
                    { "address": "relay3.example.com", "port": 3003 }
                ]
                }
            ]
        }"#,
        )
        .unwrap();

        assert_eq!(
            vec![
                Peer {
                    advertised: Some(true),
                    trustable: Some(false),
                    ..peer("relay1.example.com", 3001)
                },
                Peer {
                    advertised: Some(false),
                    trustable: Some(true),
                    ..peer("relay2.example.com", 3002)
                },
                peer("relay3.example.com", 3003),
            ],
            topology.pool_peers()
        );
    }

    #[test]
    fn fails_on_a_local_root_group_with_non_boolean_advertised_or_trustable_flags() {
        for flags in [r#""advertised": "yes""#, r#""trustable": 1"#] {
            let result = TopologyConfiguration::parse(&format!(
                r#"{{ "localRoots": [{{ "accessPoints": [], {flags} }}] }}"#
            ));

            assert!(result.is_err(), "Expected Err for {flags}, got {result:?}");
        }
    }

    #[test]
    fn has_no_pool_peers_when_the_topology_has_no_local_roots() {
        let topology = TopologyConfiguration::parse(r#"{ "localRoots": [] }"#).unwrap();

        assert_eq!(Vec::<Peer>::new(), topology.pool_peers());
    }

    #[test]
    fn fails_on_an_invalid_json() {
        let result = TopologyConfiguration::parse("{ not json");

        assert!(result.is_err(), "Expected Err, got {result:?}");
    }

    #[test]
    fn fails_on_a_peer_with_an_invalid_port() {
        let result = TopologyConfiguration::parse(
            r#"{ "localRoots": [{ "accessPoints": [{ "address": "relay1", "port": 99999 }] }] }"#,
        );

        assert!(result.is_err(), "Expected Err, got {result:?}");
    }
}
