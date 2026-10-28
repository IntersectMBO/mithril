//! Signer discoverer implementation

use anyhow::Context;

use crate::orchestrator::interfaces::Discoverer;

/// A discoverer for the signer
pub struct SignerDiscoverer {
    /// Cardano network
    pub network: String,

    ///Dummy field
    pub toto: String,
}

impl Discoverer for SignerDiscoverer {
    fn run() -> anyhow::Result<Self> {
        let network = SignerDiscoverer::discover_network()?;
        let toto = SignerDiscoverer::discover_toto()?;

        Ok(Self { network, toto })
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

        let signer_discoverer = SignerDiscoverer::run().unwrap();

        assert_eq!("mainnet".to_string(), signer_discoverer.network);
    }
}
