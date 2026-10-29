//! Signer discoverer implementation

use anyhow::Context;

use crate::orchestrator::interfaces::Discoverer;

/// A discoverer for the signer
pub struct SignerDiscoverer;

/// A discoverer result for the signer
pub struct SignerDiscovery {
    /// Cardano network
    pub network: String,

    ///Dummy field
    pub toto: String,
}

impl Discoverer for SignerDiscoverer {
    type Output = SignerDiscovery;

    fn run(&self) -> anyhow::Result<Self::Output> {
        let network = SignerDiscoverer::discover_network()?;
        let toto = SignerDiscoverer::discover_toto()?;

        Ok(SignerDiscovery { network, toto })
    }
}

impl SignerDiscoverer {
    fn discover_network() -> anyhow::Result<String> {
        std::env::var("NETWORK").context("Environment variable 'NETWORK' not found")
    }

    fn discover_toto() -> anyhow::Result<String> {
        Ok("toto".to_string())
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
        let discovery = discoverer.run().unwrap();

        assert_eq!("mainnet".to_string(), discovery.network);
    }
}
