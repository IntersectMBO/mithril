use anyhow::{Context, anyhow};
use async_trait::async_trait;
use hex::FromHex;
use nom::IResult;
use rand_core::RngCore;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;
use tokio::process::Command;

use mithril_common::crypto_helper::{KesPeriod, encode_bech32};
use mithril_common::entities::{BlockNumber, ChainPoint, Epoch, SlotNumber, StakeDistribution};
use mithril_common::{CardanoNetwork, StdResult};

use crate::entities::{ChainAddress, TxDatum};

use super::interface::{ChainObserver, ChainObserverError};

const CARDANO_ERA: &str = "latest";

/// `CliRunner` trait defines the asynchronous methods
/// for interaction with the Cardano CLI.
#[async_trait]
pub trait CliRunner {
    /// Launches a UTxO.
    async fn launch_utxo(&self, address: &str) -> StdResult<String>;
    /// Launches the stake distribution.
    async fn launch_stake_distribution(&self) -> StdResult<String>;
    /// Launches the stake snapshot.
    async fn launch_stake_snapshot(&self, stake_pool_id: &str) -> StdResult<String>;
    /// Launches the stake snapshot for all pools.
    async fn launch_stake_snapshot_all_pools(&self) -> StdResult<String>;
    /// Launches the era info.
    async fn launch_era(&self) -> StdResult<String>;
    /// Launches the epoch info.
    async fn launch_epoch(&self) -> StdResult<String>;
    /// Launches the chain point.
    async fn launch_chain_point(&self) -> StdResult<String>;
    /// Launches the kes period.
    async fn launch_kes_period(&self) -> StdResult<(String, u64)>;
}

/// A runner able to request data from a Cardano node using the
/// [Cardano Cli](https://docs.cardano.org/getting-started/use-cli).
#[derive(Clone, Debug)]
pub struct CardanoCliRunner {
    cli_path: PathBuf,
    socket_path: PathBuf,
    network: CardanoNetwork,
}

impl CardanoCliRunner {
    /// CardanoCliRunner factory
    pub fn new(cli_path: PathBuf, socket_path: PathBuf, network: CardanoNetwork) -> Self {
        Self {
            cli_path,
            socket_path,
            network,
        }
    }

    fn random_out_file() -> StdResult<PathBuf> {
        let mut rng = rand_core::OsRng;
        let dir = std::env::temp_dir().join("cardano-cli-runner");
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        Ok(dir.join(format!("{}.out", rng.next_u64())))
    }

    fn command_for_utxo(&self, address: &str, out_file: PathBuf) -> Command {
        let mut command = self.get_command();
        command
            .arg(CARDANO_ERA)
            .arg("query")
            .arg("utxo")
            .arg("--address")
            .arg(address)
            .arg("--out-file")
            .arg(out_file);
        self.post_config_command(&mut command);

        command
    }

    fn command_for_stake_distribution(&self) -> Command {
        let mut command = self.get_command();
        command.arg(CARDANO_ERA).arg("query").arg("stake-distribution");
        self.post_config_command(&mut command);

        command
    }

    fn command_for_stake_snapshot(&self, stake_pool_id: &str) -> Command {
        let mut command = self.get_command();
        command
            .arg(CARDANO_ERA)
            .arg("query")
            .arg("stake-snapshot")
            .arg("--stake-pool-id")
            .arg(stake_pool_id);
        self.post_config_command(&mut command);

        command
    }

    fn command_for_stake_snapshot_all_pools(&self) -> Command {
        let mut command = self.get_command();
        command
            .arg(CARDANO_ERA)
            .arg("query")
            .arg("stake-snapshot")
            .arg("--all-stake-pools");
        self.post_config_command(&mut command);

        command
    }

    fn command_for_era(&self) -> Command {
        let mut command = self.get_command();
        command.arg(CARDANO_ERA).arg("query").arg("tip");
        self.post_config_command(&mut command);

        command
    }

    fn command_for_epoch(&self) -> Command {
        let mut command = self.get_command();
        command.arg(CARDANO_ERA).arg("query").arg("tip");
        self.post_config_command(&mut command);

        command
    }

    fn command_for_chain_point(&self) -> Command {
        let mut command = self.get_command();
        command.arg(CARDANO_ERA).arg("query").arg("tip");
        self.post_config_command(&mut command);

        command
    }

    fn command_for_kes_period(&self) -> Command {
        let mut command = self.get_command();
        command.arg(CARDANO_ERA).arg("query").arg("tip");
        self.post_config_command(&mut command);

        command
    }

    fn get_command(&self) -> Command {
        let mut command = Command::new(&self.cli_path);
        command.env(
            "CARDANO_NODE_SOCKET_PATH",
            self.socket_path.to_string_lossy().as_ref(),
        );

        command
    }

    fn post_config_command<'a>(&'a self, command: &'a mut Command) -> &'a mut Command {
        match self.network {
            CardanoNetwork::MainNet => command.arg("--mainnet"),
            CardanoNetwork::TestNet(magic) => {
                command.args(vec!["--testnet-magic", &magic.to_string()])
            }
        }
    }

    /// Get slots per kes period
    ///
    /// This implementation is aligned with current value for the KES period on the testnet and mainnet networks of Cardano.
    /// If this value changes in the future, the implementation should be updated accordingly.
    /// The value can be retrieved in the 'slotsPerKESPeriod' field of the 'shelly-genesis.json' configuration file.
    fn get_slots_per_kes_period(&self) -> u64 {
        match self.network {
            CardanoNetwork::MainNet => 129600,
            CardanoNetwork::TestNet(1) => 129600,
            CardanoNetwork::TestNet(2) => 129600,
            CardanoNetwork::TestNet(_) => 129600,
        }
    }
}

#[async_trait]
impl CliRunner for CardanoCliRunner {
    async fn launch_utxo(&self, address: &str) -> StdResult<String> {
        let out_file = Self::random_out_file()?;
        let output = self.command_for_utxo(address, out_file.clone()).output().await?;

        if output.status.success() {
            Ok(fs::read_to_string(out_file)?.trim().to_string())
        } else {
            let message = String::from_utf8_lossy(&output.stderr);

            Err(anyhow!(
                "Error launching command {:?}, error = '{}'",
                self.command_for_utxo(address, out_file),
                message
            ))
        }
    }

    async fn launch_stake_distribution(&self) -> StdResult<String> {
        let output = self.command_for_stake_distribution().output().await?;

        if output.status.success() {
            Ok(std::str::from_utf8(&output.stdout)?.trim().to_string())
        } else {
            let message = String::from_utf8_lossy(&output.stderr);

            Err(anyhow!(
                "Error launching command {:?}, error = '{}'",
                self.command_for_stake_distribution(),
                message
            ))
        }
    }

    async fn launch_stake_snapshot(&self, stake_pool_id: &str) -> StdResult<String> {
        let output = self.command_for_stake_snapshot(stake_pool_id).output().await?;

        if output.status.success() {
            Ok(std::str::from_utf8(&output.stdout)?.trim().to_string())
        } else {
            let message = String::from_utf8_lossy(&output.stderr);

            Err(anyhow!(
                "Error launching command {:?}, error = '{}'",
                self.command_for_stake_snapshot(stake_pool_id),
                message
            ))
        }
    }

    async fn launch_stake_snapshot_all_pools(&self) -> StdResult<String> {
        let output = self.command_for_stake_snapshot_all_pools().output().await?;

        if output.status.success() {
            Ok(std::str::from_utf8(&output.stdout)?.trim().to_string())
        } else {
            let message = String::from_utf8_lossy(&output.stderr);

            Err(anyhow!(
                "Error launching command {:?}, error = '{}'",
                self.command_for_stake_snapshot_all_pools(),
                message
            ))
        }
    }

    async fn launch_era(&self) -> StdResult<String> {
        let output = self.command_for_era().output().await?;

        if output.status.success() {
            Ok(std::str::from_utf8(&output.stdout)?.trim().to_string())
        } else {
            let message = String::from_utf8_lossy(&output.stderr);

            Err(anyhow!(
                "Error launching command {:?}, error = '{}'",
                self.command_for_era(),
                message
            ))
        }
    }

    async fn launch_epoch(&self) -> StdResult<String> {
        let output = self.command_for_epoch().output().await?;

        if output.status.success() {
            Ok(std::str::from_utf8(&output.stdout)?.trim().to_string())
        } else {
            let message = String::from_utf8_lossy(&output.stderr);

            Err(anyhow!(
                "Error launching command {:?}, error = '{}'",
                self.command_for_epoch(),
                message
            ))
        }
    }

    async fn launch_chain_point(&self) -> StdResult<String> {
        let output = self.command_for_chain_point().output().await?;

        if output.status.success() {
            Ok(std::str::from_utf8(&output.stdout)?.trim().to_string())
        } else {
            let message = String::from_utf8_lossy(&output.stderr);

            Err(anyhow!(
                "Error launching command {:?}, error = '{}'",
                self.command_for_chain_point(),
                message
            ))
        }
    }

    async fn launch_kes_period(&self) -> StdResult<(String, u64)> {
        let output = self.command_for_kes_period().output().await?;

        if output.status.success() {
            Ok((
                std::str::from_utf8(&output.stdout)?.trim().to_string(),
                self.get_slots_per_kes_period(),
            ))
        } else {
            let message = String::from_utf8_lossy(&output.stderr);

            Err(anyhow!(
                "Error launching command {:?}, error = '{}'",
                self.command_for_kes_period(),
                message
            ))
        }
    }
}

/// A [ChainObserver] pulling it's data using a [CardanoCliRunner].
pub struct CardanoCliChainObserver {
    cli_runner: Box<dyn CliRunner + Send + Sync>,
}

impl CardanoCliChainObserver {
    /// CardanoCliChainObserver factory
    pub fn new(cli_runner: Box<dyn CliRunner + Send + Sync>) -> Self {
        Self { cli_runner }
    }

    // This is the only way I found to tell the compiler the correct types
    // and lifetimes for the function `double`.
    fn parse_string<'a>(&'a self, string: &'a str) -> IResult<&'a str, f64> {
        nom::number::complete::double(string)
    }

    async fn get_current_stake_value(
        &self,
        stake_pool_id: &str,
    ) -> Result<u64, ChainObserverError> {
        let stake_pool_snapshot_output = self
            .cli_runner
            .launch_stake_snapshot(stake_pool_id)
            .await
            .map_err(ChainObserverError::General)?;
        let stake_pool_snapshot: Value = serde_json::from_str(&stake_pool_snapshot_output)
            .with_context(|| format!("output was = '{stake_pool_snapshot_output}'"))
            .map_err(ChainObserverError::InvalidContent)?;
        if let Value::Number(stake_pool_stake) = &stake_pool_snapshot["poolStakeMark"] {
            return stake_pool_stake.as_u64().ok_or_else(|| {
                ChainObserverError::InvalidContent(anyhow!(
                    "Error: could not parse stake pool value as u64 {stake_pool_stake:?}"
                ))
            });
        }
        Err(ChainObserverError::InvalidContent(anyhow!(
            "Error: could not parse stake pool snapshot {stake_pool_snapshot:?}"
        )))
    }

    // This is the legacy way of computing stake distribution, not optimized for mainnet, and usable for versions of the Cardano node up to '1.35.7'
    async fn get_current_stake_distribution_legacy(
        &self,
    ) -> Result<Option<StakeDistribution>, ChainObserverError> {
        let output = self
            .cli_runner
            .launch_stake_distribution()
            .await
            .map_err(ChainObserverError::General)?;
        let mut stake_distribution = StakeDistribution::new();

        for (num, line) in output.lines().enumerate() {
            let words: Vec<&str> = line.split_ascii_whitespace().collect();

            if num < 2 || words.len() != 2 {
                continue;
            }

            let stake_pool_id = words[0];
            let stake_fraction = words[1];

            if let Ok((_, _f)) = self.parse_string(stake_fraction) {
                // This block is a fix:
                // the stake retrieved was computed on the current epoch, when we need a value computed on the previous epoch
                // in 'let stake: u64 = (f * 1_000_000_000.0).round() as u64;'
                let stake: u64 = self.get_current_stake_value(stake_pool_id).await?;

                if stake > 0 {
                    let _ = stake_distribution.insert(stake_pool_id.to_string(), stake);
                }
            } else {
                return Err(ChainObserverError::InvalidContent(anyhow!(
                    "could not parse stake from '{}'",
                    words[1]
                )));
            }
        }

        Ok(Some(stake_distribution))
    }

    // This is the new way of computing stake distribution, optimized for mainnet, and usable for versions of the Cardano node from '8.0.0'
    async fn get_current_stake_distribution_optimized(
        &self,
    ) -> Result<Option<StakeDistribution>, ChainObserverError> {
        let output = self
            .cli_runner
            .launch_stake_snapshot_all_pools()
            .await
            .map_err(ChainObserverError::General)?;
        let mut stake_distribution = StakeDistribution::new();

        let data: HashMap<String, Value> =
            serde_json::from_str(&output).map_err(|e| ChainObserverError::General(e.into()))?;
        let pools_data = data
            .get("pools")
            .ok_or(ChainObserverError::InvalidContent(anyhow!(
                "Missing 'pools' field"
            )))?
            .as_object()
            .ok_or(ChainObserverError::InvalidContent(anyhow!(
                "Could not convert pool data to object"
            )))?;

        for (k, v) in pools_data.iter() {
            let pool_id_hex = k;
            let pool_id_bech32 = encode_bech32(
                "pool",
                &Vec::from_hex(pool_id_hex.as_bytes())
                    .map_err(|e| ChainObserverError::General(e.into()))?,
            )
            .map_err(ChainObserverError::General)?;
            let stakes = v
                .get("stakeMark")
                .ok_or(ChainObserverError::InvalidContent(anyhow!(
                    "Missing 'stakeMark' field for {pool_id_bech32}"
                )))?
                .as_u64()
                .ok_or(ChainObserverError::InvalidContent(anyhow!(
                    "Stake could not be converted to integer for {pool_id_bech32}"
                )))?;
            if stakes > 0 {
                stake_distribution.insert(pool_id_bech32, stakes);
            }
        }

        Ok(Some(stake_distribution))
    }
}

#[async_trait]
impl ChainObserver for CardanoCliChainObserver {
    async fn get_current_era(&self) -> Result<Option<String>, ChainObserverError> {
        let output = self
            .cli_runner
            .launch_era()
            .await
            .map_err(ChainObserverError::General)?;
        let v: Value = serde_json::from_str(&output)
            .with_context(|| format!("output was = '{output}'"))
            .map_err(ChainObserverError::InvalidContent)?;

        if let Value::String(era) = &v["era"] {
            Ok(Some(era.to_string()))
        } else {
            Ok(None)
        }
    }

    async fn get_current_epoch(&self) -> Result<Option<Epoch>, ChainObserverError> {
        let output = self
            .cli_runner
            .launch_epoch()
            .await
            .map_err(ChainObserverError::General)?;
        let v: Value = serde_json::from_str(&output)
            .with_context(|| format!("output was = '{output}'"))
            .map_err(ChainObserverError::InvalidContent)?;

        if let Value::Number(epoch) = &v["epoch"] {
            Ok(epoch.as_u64().map(Epoch))
        } else {
            Ok(None)
        }
    }

    async fn get_current_chain_point(&self) -> Result<Option<ChainPoint>, ChainObserverError> {
        let output = self
            .cli_runner
            .launch_chain_point()
            .await
            .map_err(ChainObserverError::General)?;
        let v: Value = serde_json::from_str(&output)
            .with_context(|| format!("output was = '{output}'"))
            .map_err(ChainObserverError::InvalidContent)?;

        if let Value::String(hash) = &v["hash"] {
            Ok(Some(ChainPoint {
                slot_number: SlotNumber(v["slot"].as_u64().unwrap_or_default()),
                block_number: BlockNumber(v["block"].as_u64().unwrap_or_default()),
                block_hash: hash.to_string(),
            }))
        } else {
            Ok(None)
        }
    }

    async fn get_current_datums(
        &self,
        address: &ChainAddress,
    ) -> Result<Vec<TxDatum>, ChainObserverError> {
        let output = self
            .cli_runner
            .launch_utxo(address)
            .await
            .map_err(ChainObserverError::General)?;

        let v: BTreeMap<String, Value> = serde_json::from_str(&output)
            .with_context(|| format!("output was = '{output}'"))
            .map_err(ChainObserverError::InvalidContent)?;

        Ok(v.values()
            .filter_map(|v| {
                v.get("inlineDatum")
                    .filter(|datum| !datum.is_null())
                    .map(|datum| TxDatum(datum.to_string()))
            })
            .collect())
    }

    // TODO: This function implements a fallback mechanism to compute the stake distribution: new/optimized computation when available, legacy computation otherwise
    async fn get_current_stake_distribution(
        &self,
    ) -> Result<Option<StakeDistribution>, ChainObserverError> {
        match self.get_current_stake_distribution_optimized().await {
            Ok(stake_distribution_maybe) => Ok(stake_distribution_maybe),
            Err(_) => self.get_current_stake_distribution_legacy().await,
        }
    }

    async fn get_current_kes_period(&self) -> Result<Option<KesPeriod>, ChainObserverError> {
        let dir = std::env::temp_dir().join("mithril_kes_period");
        fs::create_dir_all(&dir).map_err(|e| ChainObserverError::General(e.into()))?;
        let (output, slots_per_kes_period) = self
            .cli_runner
            .launch_kes_period()
            .await
            .map_err(ChainObserverError::General)?;
        if slots_per_kes_period == 0 {
            return Err(anyhow!("slots_per_kes_period must be greater than 0"))
                .with_context(|| "CardanoCliChainObserver failed to calculate kes period")?;
        }
        let first_left_curly_bracket_index = output.find('{').unwrap_or_default();
        let output_cleaned = output.split_at(first_left_curly_bracket_index).1;
        let v: Value = serde_json::from_str(output_cleaned)
            .with_context(|| format!("output was = '{output}'"))
            .map_err(ChainObserverError::InvalidContent)?;

        if let Value::Number(slot) = &v["slot"] {
            Ok(slot.as_u64().map(|slot| KesPeriod(slot / slots_per_kes_period)))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsStr;

    use crate::test::test_cli_runner::{TestCliRunner, test_expected};

    use super::*;

    macro_rules! assert_cli_command {
        ($command:expr, $expected_shell:expr, envs: $envs:expr) => {
            let cmd = $command;
            let std_cmd = cmd.as_std();
            let cmd_display = format!("{std_cmd:?}");
            assert!(
                cmd_display.contains($expected_shell),
                "Command shell does not contains expected content\n  full command shell: '{cmd_display}'\n  expect to contains: {}'",
                $expected_shell
            );
            let cmd_envs: Vec<(&OsStr, Option<&OsStr>)> = std_cmd.get_envs().collect();
            assert_eq!(cmd_envs, $envs);
        };
    }

    #[tokio::test]
    async fn test_get_current_era() {
        let observer = CardanoCliChainObserver::new(Box::<TestCliRunner>::default());
        let era = observer.get_current_era().await.unwrap().unwrap();

        assert_eq!(test_expected::launch_era::ERA.to_string(), era);
    }

    #[tokio::test]
    async fn test_get_current_epoch() {
        let observer = CardanoCliChainObserver::new(Box::<TestCliRunner>::default());
        let epoch = observer.get_current_epoch().await.unwrap().unwrap();

        assert_eq!(test_expected::launch_epoch::EPOCH, epoch);
    }

    #[tokio::test]
    async fn test_get_current_chain_point() {
        let observer = CardanoCliChainObserver::new(Box::<TestCliRunner>::default());
        let chain_point = observer.get_current_chain_point().await.unwrap().unwrap();

        assert_eq!(
            ChainPoint {
                slot_number: test_expected::launch_chain_point::SLOT_NUMBER,
                block_number: test_expected::launch_chain_point::BLOCK_NUMBER,
                block_hash: test_expected::launch_chain_point::BLOCK_HASH.to_string(),
            },
            chain_point
        );
    }

    #[tokio::test]
    async fn test_cli_testnet_runner() {
        let runner = CardanoCliRunner::new(
            PathBuf::from("cardano-cli"),
            PathBuf::from("/tmp/whatever.sock"),
            CardanoNetwork::TestNet(10),
        );

        assert_cli_command!(
            runner.command_for_epoch(),
            r#""cardano-cli" "latest" "query" "tip" "--testnet-magic" "10""#,
            envs: vec![(OsStr::new("CARDANO_NODE_SOCKET_PATH"), Some(OsStr::new("/tmp/whatever.sock")))]
        );
        assert_cli_command!(
            runner.command_for_stake_distribution(),
            r#""cardano-cli" "latest" "query" "stake-distribution" "--testnet-magic" "10""#,
            envs: vec![(OsStr::new("CARDANO_NODE_SOCKET_PATH"), Some(OsStr::new("/tmp/whatever.sock")))]
        );
    }

    #[tokio::test]
    async fn test_cli_mainnet_runner() {
        let runner = CardanoCliRunner::new(
            PathBuf::from("cardano-cli"),
            PathBuf::from("/tmp/whatever.sock"),
            CardanoNetwork::MainNet,
        );

        assert_cli_command!(
            runner.command_for_epoch(),
            r#""cardano-cli" "latest" "query" "tip" "--mainnet""#,
            envs: vec![(OsStr::new("CARDANO_NODE_SOCKET_PATH"), Some(OsStr::new("/tmp/whatever.sock")))]
        );
        assert_cli_command!(
            runner.command_for_stake_distribution(),
            r#""cardano-cli" "latest" "query" "stake-distribution" "--mainnet"#,
            envs: vec![(OsStr::new("CARDANO_NODE_SOCKET_PATH"), Some(OsStr::new("/tmp/whatever.sock")))]
        );
    }

    #[tokio::test]
    async fn test_get_current_datums() {
        let observer = CardanoCliChainObserver::new(Box::<TestCliRunner>::default());
        let address = "addrtest_123456".to_string();
        let datums = observer.get_current_datums(&address).await.unwrap();
        assert_eq!(
            vec![TxDatum(
                format!(
                    r#"{{"constructor":0,"fields":[{{"bytes":"{}"}}]}}"#,
                    test_expected::launch_utxo::BYTES
                )
                .to_string()
            )],
            datums
        );
    }

    #[tokio::test]
    async fn test_get_current_stake_value() {
        let observer = CardanoCliChainObserver::new(Box::<TestCliRunner>::default());
        let stake = observer
            .get_current_stake_value("pool1qqyjr9pcrv97gwrueunug829fs5znw6p2wxft3fvqkgu5f4qlrg")
            .await
            .expect("get current stake value should not fail");
        assert_eq!(
            test_expected::launch_stake_snapshot::DEFAULT_POOL_STAKE_MARK,
            stake
        );

        let stake = observer
            .get_current_stake_value(test_expected::launch_stake_snapshot::POOL_ID_SPECIFIC)
            .await
            .expect("get current stake value should not fail");
        assert_eq!(
            test_expected::launch_stake_snapshot::POOL_STAKE_MARK_FOR_POOL_ID_SPECIFIC,
            stake
        );
    }

    #[tokio::test]
    async fn test_get_current_stake_distribution_legacy() {
        let observer = CardanoCliChainObserver::new(Box::new(TestCliRunner::legacy()));
        let results = observer
            .get_current_stake_distribution_legacy()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(7, results.len());
        assert_eq!(
            3_000_000,
            *results
                .get("pool1qqyjr9pcrv97gwrueunug829fs5znw6p2wxft3fvqkgu5f4qlrg")
                .unwrap()
        );
        assert_eq!(
            3_000_000,
            *results
                .get("pool1qz2vzszautc2c8mljnqre2857dpmheq7kgt6vav0s38tvvhxm6w")
                .unwrap()
        );
        assert!(!results.contains_key("pool1qpqvz90w7qsex2al2ejjej0rfgrwsguch307w8fraw7a7adf6g8"));
    }

    #[tokio::test]
    async fn test_get_current_stake_distribution_new() {
        let observer = CardanoCliChainObserver::new(Box::<TestCliRunner>::default());
        let computed_stake_distribution = observer
            .get_current_stake_distribution_optimized()
            .await
            .unwrap()
            .unwrap();
        let mut expected_stake_distribution = StakeDistribution::new();
        expected_stake_distribution.insert(
            "pool1qqqqqdk4zhsjuxxd8jyvwncf5eucfskz0xjjj64fdmlgj735lr9".to_string(),
            test_expected::launch_stake_snapshot_all_pools::STAKE_MARK_POOL_1,
        );
        expected_stake_distribution.insert(
            "pool1qqqqpanw9zc0rzh0yp247nzf2s35uvnsm7aaesfl2nnejaev0uc".to_string(),
            test_expected::launch_stake_snapshot_all_pools::STAKE_MARK_POOL_2,
        );
        expected_stake_distribution.insert(
            "pool1qqqqzyqf8mlm70883zht60n4q6uqxg4a8x266sewv8ad2grkztl".to_string(),
            test_expected::launch_stake_snapshot_all_pools::STAKE_MARK_POOL_3,
        );
        assert_eq!(
            BTreeMap::from_iter(
                expected_stake_distribution
                    .into_iter()
                    .collect::<Vec<(_, _)>>()
                    .into_iter(),
            ),
            BTreeMap::from_iter(
                computed_stake_distribution
                    .into_iter()
                    .collect::<Vec<(_, _)>>()
                    .into_iter(),
            ),
        );
    }

    #[tokio::test]
    async fn test_get_current_stake_distribution() {
        let observer = CardanoCliChainObserver::new(Box::new(TestCliRunner::legacy()));
        let expected_stake_distribution = observer
            .get_current_stake_distribution_legacy()
            .await
            .unwrap()
            .unwrap();
        let computed_stake_distribution =
            observer.get_current_stake_distribution().await.unwrap().unwrap();

        assert_eq!(
            BTreeMap::from_iter(
                expected_stake_distribution
                    .clone()
                    .into_iter()
                    .collect::<Vec<(_, _)>>()
                    .into_iter(),
            ),
            BTreeMap::from_iter(
                computed_stake_distribution
                    .into_iter()
                    .collect::<Vec<(_, _)>>()
                    .into_iter(),
            ),
        );

        let observer = CardanoCliChainObserver::new(Box::<TestCliRunner>::default());
        let expected_stake_distribution = observer
            .get_current_stake_distribution_optimized()
            .await
            .unwrap()
            .unwrap();
        let computed_stake_distribution =
            observer.get_current_stake_distribution().await.unwrap().unwrap();

        assert_eq!(
            BTreeMap::from_iter(
                expected_stake_distribution
                    .into_iter()
                    .collect::<Vec<(_, _)>>()
                    .into_iter(),
            ),
            BTreeMap::from_iter(
                computed_stake_distribution
                    .into_iter()
                    .collect::<Vec<(_, _)>>()
                    .into_iter(),
            ),
        );
    }

    #[tokio::test]
    async fn test_get_current_kes_period() {
        let observer = CardanoCliChainObserver::new(Box::<TestCliRunner>::default());
        let kes_period = observer.get_current_kes_period().await.unwrap().unwrap();
        assert_eq!(
            (test_expected::launch_chain_point::SLOT_NUMBER.0
                / test_expected::launch_kes_period::SLOTS_PER_KES_PERIOD),
            kes_period
        );
    }
}
