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
