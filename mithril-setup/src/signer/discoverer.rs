//! Signer discoverer implementation

use anyhow::Context;

use crate::orchestrator::interfaces::Discoverer;

/// A discoverer for the signer
pub struct SignerDiscoverer;

/// A discoverer result for the signer
pub struct SignerDiscovery {
    /// Cardano network
    pub network: String,

    /// The magic ID
    pub magic_id: String,
}

impl Discoverer for SignerDiscoverer {
    type Output = SignerDiscovery;

    fn discover(&self) -> anyhow::Result<Self::Output> {
        let network = SignerDiscoverer::discover_network()?;
        let magic_id = SignerDiscoverer::discover_magic_id()?;

        Ok(SignerDiscovery { network, magic_id })
    }
}

impl SignerDiscoverer {
    fn discover_network() -> anyhow::Result<String> {
        std::env::var("NETWORK").context("Environment variable 'NETWORK' not found")
    }

    fn discover_magic_id() -> anyhow::Result<String> {
        Ok("1".to_string())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_signer_discoverer_must_discover_network_throught_env_variable() {
        //set env variable
        unsafe { std::env::set_var("NETWORK", "mainnet") };

        let discoverer = SignerDiscoverer;
        let discovery = discoverer.discover().unwrap();

        assert_eq!("mainnet".to_string(), discovery.network);
    }
}
