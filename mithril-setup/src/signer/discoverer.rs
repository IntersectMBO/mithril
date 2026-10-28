//! Signer discoverer implementation

use anyhow::Context;

use crate::orchestrator::interfaces::Discoverer;

/// A discoverer for the signer
pub struct SignerDiscoverer {
    network: String,
}

impl Discoverer for SignerDiscoverer {
    fn run() -> anyhow::Result<Self> {
        let network = SignerDiscoverer::discover_network()?;

        Ok(Self { network })
    }
}

impl SignerDiscoverer {
    fn discover_network() -> anyhow::Result<String> {
        std::env::var("NETWORK").context("Environment variable 'NETWORK' not found")
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
