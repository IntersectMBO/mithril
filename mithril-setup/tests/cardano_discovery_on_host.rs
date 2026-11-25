//! Manual check of the Cardano discovery against the machine running the test
//!
//! Ignored by default since its outcome depends on the machine.
//!
//! ## Run a Cardano node
//!
//! Start a Cardano devnet with mithril-end-to-end, from the root of the repository, and keep it
//! running in another terminal:
//! ```shell
//! cargo build --release
//! cargo run -p mithril-end-to-end -- -vv --bin-directory target/release --devnet-scripts-directory=mithril-test-lab/cardano-devnet/ --number-of-signers 1 run-only
//! ```
//!
//! ## Run the test
//!
//! Run the ignored test, printing the discovery logs down to the debug level:
//! ```shell
//! cargo nextest run -p mithril-setup --test cardano_discovery_on_host --run-ignored only --no-capture
//! ```
//!
//! Run it as the node's user, or as root, to read the `exe` and `cwd` links of the node process.

use mithril_setup::discovery::cardano::CardanoDiscoverer;

/// Install a logger printing the logs down to the debug level, shown with `--no-capture`
fn test_logger() {
    // Fails when a subscriber is already installed, the logs are then printed by that one
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
}

#[tokio::test]
#[ignore = "Require Cardano nodes running on the machine"]
async fn discover_the_cardano_block_producer_running_on_this_machine() {
    test_logger();
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
