//! Embed the Mithril networks of `networks.json`, with the configuration of their readers taken
//! from `mithril-infra/configuration`, so that the setup guesses them without any download.
//!
//! The configuration of a reader is found by convention: for the `release-mainnet` network, the
//! era reader address is `mithril-infra/configuration/release-mainnet/era.addr`. The build fails
//! when the convention is not followed by `networks.json`, or when a file is missing.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// Readers declared in `networks.json`, with the prefix of their configuration files
const READERS: [(&str, &str); 2] = [
    ("era-reader", "era"),
    ("protocol-configuration-reader", "protocol-config"),
];

fn main() {
    let repository = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("..");
    let networks_json = repository.join("networks.json");
    let configuration_dir = repository.join("mithril-infra").join("configuration");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", networks_json.display());
    println!("cargo:rerun-if-changed={}", configuration_dir.display());

    let content = fs::read_to_string(&networks_json)
        .unwrap_or_else(|error| panic!("Could not read '{}': {error}", networks_json.display()));
    let networks: Value = serde_json::from_str(&content).unwrap_or_else(|error| {
        panic!("'{}' is not a valid JSON: {error}", networks_json.display())
    });

    let readers_configuration = mithril_networks(&networks)
        .map(|(name, network)| {
            let [era_reader, protocol_configuration_reader] = READERS.map(|(reader, prefix)| {
                reader_configuration(&configuration_dir, name, network.get(reader), prefix)
            });
            format!("    ({name:?}, {era_reader}, {protocol_configuration_reader}),\n")
        })
        .collect::<String>();

    let code = format!(
        "/// Content of `networks.json`\n\
         pub(super) const NETWORKS_JSON: &str = include_str!({networks_json:?});\n\
         \n\
         /// Address and verification key of a reader, `None` when the network does not declare it\n\
         pub(super) type ReaderConfiguration = Option<(&'static str, &'static str)>;\n\
         \n\
         /// Readers configuration of each Mithril network: its name, then the configuration of\n\
         /// its era reader and of its protocol configuration reader\n\
         pub(super) const READERS_CONFIGURATION: &[(&str, ReaderConfiguration, ReaderConfiguration)] = &[\n\
         {readers_configuration}];\n",
        networks_json = path_literal(&networks_json),
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out_dir.join("embedded_mithril_networks.rs"), code).unwrap();
}

/// Mithril networks of `networks.json`, with their name, for all the Cardano networks
fn mithril_networks(networks: &Value) -> impl Iterator<Item = (&str, &Value)> {
    networks
        .as_object()
        .expect("'networks.json' must be a JSON object")
        .values()
        .filter_map(|cardano_network| cardano_network.get("mithril-networks")?.as_array())
        .flatten()
        .filter_map(Value::as_object)
        .flatten()
        .map(|(name, network)| (name.as_str(), network))
}

/// Code of the configuration of a reader: `None` when the network does not declare it, or the
/// `include_str!` of its address and verification key files
fn reader_configuration(
    configuration_dir: &Path,
    network: &str,
    reader: Option<&Value>,
    prefix: &str,
) -> String {
    let Some(reader) = reader else {
        return "None".to_string();
    };

    let [address, verification_key] =
        [("address", "addr"), ("verification-key", "vkey")].map(|(key, extension)| {
            let file_name = format!("{prefix}.{extension}");
            let url = reader
                .get(key)
                .and_then(|reference| reference.get("url"))
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("No '{key}' url for the reader of '{network}'"));
            if !url.ends_with(&format!("/{network}/{file_name}")) {
                panic!(
                    "The '{key}' url of the reader of '{network}' must end with \
                     '{network}/{file_name}' to be embedded, got '{url}'"
                );
            }

            let file = configuration_dir.join(network).join(&file_name);
            if !file.is_file() {
                panic!("Missing file '{}' to embed", file.display());
            }
            format!("include_str!({:?})", path_literal(&file))
        });

    format!("Some(({address}, {verification_key}))")
}

/// Absolute path, as expected by `include_str!` in a file generated in `OUT_DIR`
fn path_literal(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|error| panic!("Could not resolve '{}': {error}", path.display()))
        .to_string_lossy()
        .into_owned()
}
