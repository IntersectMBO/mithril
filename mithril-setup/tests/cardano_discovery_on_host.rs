//! Manual check of the Cardano discovery against the machine running the test
//!
//! Ignored by default since its outcome depends on the machine, run it with:
//! ```shell
//! cargo test -p mithril-setup --test cardano_discovery_on_host -- --ignored --nocapture
//! ```
//!
//! Run it as root (or as the node's user) to read the `exe` and `cwd` links of the node process:
//! ```shell
//! cargo test -p mithril-setup --test cardano_discovery_on_host --no-run
//! sudo <path of the test binary printed above> --ignored --nocapture
//! ```
//! In parallel, you can run the node using mithril-end-to-end, for example:
//! ```shell
//! cargo run -p mithril-end-to-end -- -vv --bin-directory target/release \
//!  --devnet-scripts-directory=mithril-test-lab/cardano-devnet/ \
//!  --number-of-signers 1 run-only
//! ```

use mithril_setup::discovery::cardano::CardanoDiscoverer;

#[tokio::test]
#[ignore = "depends on the Cardano nodes running on the machine"]
async fn discover_the_cardano_block_producer_running_on_this_machine() {
    let discoverer = CardanoDiscoverer::host();

    let nodes = discoverer.detect_nodes().await;
    println!("Detected Cardano nodes: {nodes:#?}");

    let discovery = discoverer.discover().await;
    match &discovery {
        Ok(discovery) => println!("Discovered block producer: {discovery:#?}"),
        Err(error) => println!("Discovery failed: {error:?}"),
    }

    assert!(discovery.is_ok(), "Discovery failed: {discovery:?}");
}
