use std::path::{Path, PathBuf};

use anyhow::Context;
use config::{Config, File, FileFormat};
use serde::Deserialize;

/// Node configuration file (ie: `configuration.yml`), only the keys used by the discovery
///
/// The file is either in JSON or in YAML, whatever its name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct CardanoConfiguration {
    /// Path of the Shelley genesis file, relative to the directory of the configuration file
    #[serde(rename = "ShelleyGenesisFile")]
    pub shelley_genesis_file: Option<String>,
}

impl CardanoConfiguration {
    /// Parse the content of a node configuration file, in JSON or in YAML
    pub fn parse(content: &str) -> anyhow::Result<Self> {
        if let Ok(configuration) = serde_json::from_str(content) {
            return Ok(configuration);
        }

        Config::builder()
            .add_source(File::from_str(content, FileFormat::Yaml))
            .build()
            .and_then(Config::try_deserialize)
            .context("The node configuration is neither a valid JSON nor a valid YAML")
    }

    /// Path of the Shelley genesis file, resolved like the node does: against the directory of
    /// the configuration file
    pub fn shelley_genesis_path(&self, config_file: &Path) -> Option<PathBuf> {
        let genesis_file = Path::new(self.shelley_genesis_file.as_deref()?);

        Some(match config_file.parent() {
            Some(config_dir) => config_dir.join(genesis_file),
            None => genesis_file.to_path_buf(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_yaml_configuration() {
        let configuration = CardanoConfiguration::parse(
            r#"
                AlonzoGenesisFile: alonzo/genesis.json
                ByronGenesisFile: byron/genesis.json
                ShelleyGenesisFile: shelley/genesis.json
            "#,
        )
        .unwrap();

        assert_eq!(
            Some("shelley/genesis.json".to_string()),
            configuration.shelley_genesis_file
        );
    }

    #[test]
    fn parses_a_json_configuration() {
        let configuration = CardanoConfiguration::parse(
            r#"{
                "AlonzoGenesisFile": "alonzo/genesis.json",
                "ByronGenesisFile": "byron/genesis.json",
                "ShelleyGenesisFile": "shelley/genesis.json"
            }"#,
        )
        .unwrap();

        assert_eq!(
            Some("shelley/genesis.json".to_string()),
            configuration.shelley_genesis_file
        );
    }

    #[test]
    fn leaves_the_shelley_genesis_file_unknown_when_absent() {
        let configuration = CardanoConfiguration::parse("Protocol: Cardano").unwrap();

        assert_eq!(CardanoConfiguration::default(), configuration);
    }

    #[test]
    fn fails_on_a_content_that_is_neither_json_nor_yaml() {
        let result = CardanoConfiguration::parse("{ not: [valid");

        assert!(result.is_err(), "Expected Err, got {result:?}");
    }

    #[test]
    fn fails_on_a_content_that_is_not_a_map() {
        let result = CardanoConfiguration::parse("- a\n- list");

        assert!(result.is_err(), "Expected Err, got {result:?}");
    }

    fn with_genesis(path: &str) -> CardanoConfiguration {
        CardanoConfiguration {
            shelley_genesis_file: Some(path.to_string()),
        }
    }

    #[test]
    fn resolves_a_relative_genesis_path_against_the_configuration_directory() {
        let path = with_genesis("shelley/genesis.json")
            .shelley_genesis_path(Path::new("/opt/cardano/configuration.yml"));

        assert_eq!(
            Some(PathBuf::from("/opt/cardano/shelley/genesis.json")),
            path
        );
    }

    #[test]
    fn keeps_an_absolute_genesis_path() {
        let path = with_genesis("/etc/cardano/shelley-genesis.json")
            .shelley_genesis_path(Path::new("/opt/cardano/configuration.yml"));

        assert_eq!(
            Some(PathBuf::from("/etc/cardano/shelley-genesis.json")),
            path
        );
    }

    #[test]
    fn keeps_a_relative_genesis_path_when_the_configuration_path_has_no_directory() {
        let path = with_genesis("shelley/genesis.json")
            .shelley_genesis_path(Path::new("configuration.yml"));

        assert_eq!(Some(PathBuf::from("shelley/genesis.json")), path);
    }

    #[test]
    fn has_no_genesis_path_when_the_genesis_file_is_unknown() {
        let path = CardanoConfiguration::default()
            .shelley_genesis_path(Path::new("/opt/cardano/configuration.yml"));

        assert_eq!(None, path);
    }
}
