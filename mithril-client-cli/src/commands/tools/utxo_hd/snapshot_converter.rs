use std::{
    env, fmt,
    fs::{create_dir, read_dir, remove_dir_all, rename},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, anyhow};
use chrono::Utc;
use clap::{Parser, ValueEnum};

use mithril_client::{
    MithrilError, MithrilResult,
    common::{CardanoNetwork, MagicId},
};

use crate::utils::{
    ArchiveUnpacker, CardanoDbUtils, GitHubReleaseRetriever, HttpDownloader, LedgerFormat,
    ProgressOutputType, ProgressPrinter, ReqwestGitHubApiClient, ReqwestHttpDownloader, copy_dir,
    is_version_equal_or_upper, print_simple_warning, remove_dir_contents,
};
use crate::{
    CommandContext,
    utils::{CARDANO_NODE_V10_6_2, CARDANO_NODE_V10_7_0, CARDANO_NODE_V11_1_0},
};

const GITHUB_ORGANIZATION: &str = "IntersectMBO";
const GITHUB_REPOSITORY: &str = "cardano-node";

const LATEST_DISTRIBUTION_TAG: &str = "latest";
const PRERELEASE_DISTRIBUTION_TAG: &str = "pre-release";

const WORK_DIR: &str = "tmp";
const CARDANO_DISTRIBUTION_DIR: &str = "cardano-node-distribution";
const SNAPSHOTS_DIR: &str = "snapshots";

const SNAPSHOT_CONVERTER_BIN_DIR: &str = "bin";
const SNAPSHOT_CONVERTER_BIN_NAME_UNIX: &str = "snapshot-converter";
const SNAPSHOT_CONVERTER_BIN_NAME_WINDOWS: &str = "snapshot-converter.exe";
const SNAPSHOT_CONVERTER_CONFIG_DIR: &str = "share";
const SNAPSHOT_CONVERTER_CONFIG_FILE: &str = "config.json";

const LEDGER_DIR: &str = "ledger";
const LSM_DATABASE_DIR: &str = "lsm";
const LSM_EXPORT_DIR: &str = "lsm_export";
const PROTOCOL_MAGIC_ID_FILE: &str = "protocolMagicId";

const CONVERSION_FALLBACK_LIMIT: usize = 2;

#[derive(Debug, Clone, ValueEnum, Eq, PartialEq)]
enum UTxOHDFlavor {
    #[clap(name = "Legacy")]
    Legacy,
    #[clap(name = "LMDB")]
    Lmdb,
    #[clap(name = "LSM")]
    Lsm,
}

impl fmt::Display for UTxOHDFlavor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Legacy => write!(f, "Legacy"),
            Self::Lmdb => write!(f, "LMDB"),
            Self::Lsm => write!(f, "LSM"),
        }
    }
}

impl From<&UTxOHDFlavor> for LedgerFormat {
    fn from(value: &UTxOHDFlavor) -> Self {
        match value {
            UTxOHDFlavor::Legacy => LedgerFormat::Legacy,
            UTxOHDFlavor::Lmdb => LedgerFormat::Lmdb,
            UTxOHDFlavor::Lsm => LedgerFormat::Lsm,
        }
    }
}

#[derive(Debug, Clone, ValueEnum, Eq, PartialEq)]
enum CardanoNetworkCliArg {
    Preview,
    Preprod,
    Mainnet,
    Devnet,
}

impl fmt::Display for CardanoNetworkCliArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preview => write!(f, "preview"),
            Self::Preprod => write!(f, "preprod"),
            Self::Mainnet => write!(f, "mainnet"),
            Self::Devnet => write!(f, "devnet"),
        }
    }
}

impl TryFrom<CardanoNetwork> for CardanoNetworkCliArg {
    type Error = MithrilError;

    fn try_from(network: CardanoNetwork) -> Result<Self, Self::Error> {
        match network {
            CardanoNetwork::MainNet => Ok(Self::Mainnet),
            CardanoNetwork::TestNet(magic_id) => match magic_id {
                CardanoNetwork::PREVIEW_MAGIC_ID => Ok(Self::Preview),
                CardanoNetwork::PREPROD_MAGIC_ID => Ok(Self::Preprod),
                CardanoNetwork::DEVNET_MAGIC_ID => Ok(Self::Devnet),
                _ => Err(anyhow!(
                    "Cardano network not supported for ledger state snapshot conversion: {network:?}",
                )),
            },
        }
    }
}

#[cfg_attr(test, mockall::automock)]
trait SnapshotConverter {
    fn convert(&self, input_path: &Path, output_path: &Path) -> MithrilResult<()>;
}
#[derive(Clone)]
struct SnapshotConverterConfig {
    pub converter_bin: PathBuf,
    pub config_path: PathBuf,
    pub utxo_hd_flavor: UTxOHDFlavor,
    pub hide_output: bool,
}

enum SnapshotConverterBin {
    From11_1(SnapshotConverterConfig),
    From10_7(SnapshotConverterConfig),
    UpTo10_6(SnapshotConverterConfig),
    UpTo10_5(SnapshotConverterConfig),
}

impl SnapshotConverterBin {
    fn converter_bin(&self) -> &Path {
        match self {
            SnapshotConverterBin::From11_1(cfg)
            | SnapshotConverterBin::From10_7(cfg)
            | SnapshotConverterBin::UpTo10_6(cfg)
            | SnapshotConverterBin::UpTo10_5(cfg) => &cfg.converter_bin,
        }
    }
}

impl SnapshotConverter for SnapshotConverterBin {
    fn convert(&self, input_path: &Path, output_path: &Path) -> MithrilResult<()> {
        let commands = match self {
            SnapshotConverterBin::From11_1(cfg) => {
                build_commands_from_11_1(input_path, output_path, cfg.clone())?
            }

            SnapshotConverterBin::From10_7(cfg) => {
                vec![build_command_from_10_7(input_path, output_path, cfg.clone())?]
            }

            SnapshotConverterBin::UpTo10_6(cfg) => {
                vec![build_command_from_10_6(input_path, output_path, cfg.clone())]
            }

            SnapshotConverterBin::UpTo10_5(cfg) => {
                vec![build_command_up_to_10_5(input_path, output_path, cfg.clone())]
            }
        };

        for mut command in commands {
            let status = command.status().with_context(|| {
                format!(
                    "Failed to execute snapshot-converter binary at {}",
                    self.converter_bin().display()
                )
            })?;

            if !status.success() {
                return Err(anyhow!(
                    "Failure while running snapshot-converter binary, exited with status code: {:?}",
                    status.code().map_or(String::from("unknown"), |c| c.to_string())
                ));
            }
        }

        Ok(())
    }
}

fn build_commands_from_11_1(
    input_path: &Path,
    output_path: &Path,
    cfg: SnapshotConverterConfig,
) -> MithrilResult<Vec<Command>> {
    let snapshots_dir = output_path.parent().unwrap_or(output_path);
    let is_lsm = cfg.utxo_hd_flavor == UTxOHDFlavor::Lsm;

    let mut convert_command = Command::new(&cfg.converter_bin);
    convert_command
        .arg("convert")
        .arg("--snapshot-in")
        .arg(input_path)
        .arg("--snapshot-out")
        .arg(output_path);

    if is_lsm {
        convert_command
            .arg("--lsm-export-to")
            .arg(snapshots_dir.join(LSM_EXPORT_DIR));
    }

    convert_command
        .arg("--config")
        .arg(&cfg.config_path)
        .stdout(command_stdout(cfg.hide_output));

    let mut commands = vec![convert_command];

    if is_lsm {
        let snapshot_name = output_path.file_name().with_context(|| {
            format!(
                "Missing filename in converted snapshot output path: {}",
                output_path.display()
            )
        })?;

        let mut import_command = Command::new(&cfg.converter_bin);
        import_command
            .arg("lsm")
            .arg("import")
            .arg("--lsm-database")
            .arg(snapshots_dir.join(LSM_DATABASE_DIR))
            .arg("--lsm-import-from")
            .arg(snapshots_dir.join(LSM_EXPORT_DIR))
            .arg("--snapshot")
            .arg(snapshot_name)
            .stdout(command_stdout(cfg.hide_output));

        commands.push(import_command);
    }

    Ok(commands)
}

fn command_stdout(hide_output: bool) -> Stdio {
    if hide_output {
        // Hide output when JSON output is enabled (as they are not JSON formatted)
        Stdio::null()
    } else {
        // redirect to stderr to keep stdout dedicated to the command result.
        std::io::stderr().into()
    }
}

fn build_command_from_10_7(
    input_path: &Path,
    output_path: &Path,
    cfg: SnapshotConverterConfig,
) -> MithrilResult<Command> {
    let mut command = Command::new(cfg.converter_bin);

    command.arg("--input-mem").arg(input_path);

    if cfg.utxo_hd_flavor == UTxOHDFlavor::Lsm {
        let output_database_path =
            output_path.parent().unwrap_or(output_path).join(LSM_DATABASE_DIR);
        command
            .arg("--output-lsm-snapshot")
            .arg(output_path)
            .arg("--output-lsm-database")
            .arg(output_database_path);
    } else {
        let flavor = cfg.utxo_hd_flavor.to_string().to_lowercase();
        command.arg(format!("--output-{flavor}")).arg(output_path);
    }

    command
        .arg("--config")
        .arg(cfg.config_path)
        .stdout(if cfg.hide_output {
            Stdio::null()
        } else {
            std::io::stderr().into()
        });

    Ok(command)
}

fn build_command_from_10_6(
    input_path: &Path,
    output_path: &Path,
    cfg: SnapshotConverterConfig,
) -> Command {
    let mut command = Command::new(cfg.converter_bin);

    command
        .arg("--mem-in")
        .arg(input_path)
        .arg(format!(
            "--{}-out",
            cfg.utxo_hd_flavor.to_string().to_lowercase()
        ))
        .arg(output_path)
        .arg("--config")
        .arg(cfg.config_path)
        .stdout(if cfg.hide_output {
            // Hide output when JSON output is enabled (as they are not JSON formatted)
            Stdio::null()
        } else {
            // redirect to stderr to keep stdout dedicated to the command result.
            std::io::stderr().into()
        });
    command
}

fn build_command_up_to_10_5(
    input_path: &Path,
    output_path: &Path,
    cfg: SnapshotConverterConfig,
) -> Command {
    let mut command = Command::new(cfg.converter_bin);

    command
        .arg("Mem")
        .arg(input_path)
        .arg(cfg.utxo_hd_flavor.to_string())
        .arg(output_path)
        .arg("cardano")
        .arg("--config")
        .arg(cfg.config_path.clone())
        .stdout(if cfg.hide_output {
            // Hide output when JSON output is enabled (as they are not JSON formatted)
            Stdio::null()
        } else {
            // redirect to stderr to keep stdout dedicated to the command result.
            std::io::stderr().into()
        });
    command
}

/// Clap command to convert a restored `InMemory` Mithril snapshot to another flavor.
#[derive(Parser, Debug, Clone)]
pub struct SnapshotConverterCommand {
    /// Path to the Cardano node database directory.
    #[clap(long)]
    db_directory: PathBuf,

    /// Cardano node version of the Mithril signed snapshot (`latest` and `pre-release` are also supported to download the latest or pre-release distribution).
    ///
    /// `latest` and `pre-release` are also supported to download the latest or pre-release distribution.
    #[clap(long)]
    cardano_node_version: String,

    /// (Optional) Path to the snapshot converter binary. If not provided, the binary will be downloaded from the GitHub releases of the Cardano node repository based on the provided `cardano_node_version`.
    ///
    /// requires `config_path` to be provided as well.
    #[clap(long, requires("config_path"))]
    binary_path: Option<PathBuf>,

    // (Optional) Path to the snapshot converter config file. Mandatory if `binary_path` is provided
    #[clap(long, requires("binary_path"))]
    config_path: Option<PathBuf>,

    /// Cardano network.
    #[clap(long)]
    #[deprecated(
        since = "0.12.12",
        note = "optional: automatically detected from the protocolMagicId file"
    )]
    cardano_network: Option<CardanoNetworkCliArg>,

    /// UTxO-HD flavor to convert the ledger snapshot to (`Legacy`, `LMDB` or `LSM`).
    #[clap(long)]
    utxo_hd_flavor: UTxOHDFlavor,

    /// Replaces the current ledger state in the `db_directory`.
    #[clap(long)]
    commit: bool,

    /// GitHub token for authenticated API calls.
    #[clap(long, env = "GITHUB_TOKEN")]
    github_token: Option<String>,
}

impl SnapshotConverterCommand {
    /// Main command execution
    pub async fn execute(&self, context: CommandContext) -> MithrilResult<()> {
        let progress_output_type = if context.is_json_output_enabled() {
            ProgressOutputType::JsonReporter
        } else {
            ProgressOutputType::Tty
        };

        if is_version_at_least_10_6_2_or_latest(&self.cardano_node_version)
            && self.utxo_hd_flavor == UTxOHDFlavor::Legacy
        {
            return Err(anyhow!(
                "UTxO HD Flavor Legacy is not supported on Cardano node 10.6.2 or upper"
            ));
        }

        let is_local_bin_mode = self.binary_path.is_some() && self.config_path.is_some();

        let number_of_steps = Self::calculate_number_of_steps(is_local_bin_mode, self.commit);

        let mut current_step = 0;

        let progress_printer = ProgressPrinter::new(progress_output_type, number_of_steps);

        let work_dir = self.db_directory.join(WORK_DIR);
        create_dir(&work_dir).with_context(|| {
            format!(
                "Failed to create snapshot converter work directory: {}",
                work_dir.display()
            )
        })?;

        let distribution_dir = work_dir.join(CARDANO_DISTRIBUTION_DIR);

        let result = {
            #[allow(deprecated)]
            let cardano_network = if let Some(network) = &self.cardano_network {
                network.clone()
            } else {
                Self::detect_cardano_network(&self.db_directory).with_context(|| {
                    format!(
                        "Could not detect Cardano network from the database directory: {}",
                        self.db_directory.display()
                    )
                })?
            };

            let (converter_bin, config_path) = if is_local_bin_mode {
                match (&self.binary_path, &self.config_path) {
                    (Some(bin), Some(cfg)) => (bin.clone(), cfg.clone()),
                    _ => {
                        return Err(anyhow!(
                            "Local binary mode requires both --binary-path and --config-path to be provided"
                        ));
                    }
                }
            } else {
                create_dir(&distribution_dir).with_context(|| {
                    format!(
                        "Failed to create distribution directory: {}",
                        distribution_dir.display()
                    )
                })?;
                current_step += 1;
                let archive_path = Self::download_cardano_node_distribution(
                    current_step,
                    &progress_printer,
                    ReqwestGitHubApiClient::new(self.github_token.clone())?,
                    ReqwestHttpDownloader::new()?,
                    &self.cardano_node_version,
                    &distribution_dir,
                )
                .await
                .with_context(|| "Failed to download Cardano node distribution")?;

                current_step += 1;
                progress_printer.report_step(
                    current_step,
                    &format!(
                        "Unpacking distribution from archive: {}",
                        archive_path.display()
                    ),
                )?;
                ArchiveUnpacker::default()
                    .unpack(&archive_path, &distribution_dir)
                    .with_context(|| {
                        format!(
                            "Failed to unpack distribution to directory: {}",
                            distribution_dir.display()
                        )
                    })?;
                progress_printer.print_message(&format!(
                    "Distribution unpacked successfully to: {}",
                    distribution_dir.display()
                ))?;

                let converter_bin =
                    Self::get_snapshot_converter_binary_path(&distribution_dir, env::consts::OS)?;
                let config_path =
                    Self::get_snapshot_converter_config_path(&distribution_dir, &cardano_network);

                (converter_bin, config_path)
            };

            current_step += 1;
            let converted_snapshot_path = Self::convert_ledger_state_snapshot(
                current_step,
                &progress_printer,
                &work_dir,
                converter_bin,
                config_path,
                self,
            )
            .with_context(|| {
                format!(
                    "Failed to convert ledger snapshot to flavor: {}",
                    self.utxo_hd_flavor
                )
            })?;

            if self.commit {
                current_step += 1;
                Self::commit_converted_snapshot(
                    current_step,
                    &progress_printer,
                    &self.db_directory,
                    &converted_snapshot_path,
                    &self.utxo_hd_flavor,
                )
                .with_context(
                    || "Failed to overwrite the ledger state with the converted snapshot.",
                )?;
            }

            Self::print_successful_result(
                &self.db_directory,
                &converted_snapshot_path,
                &cardano_network,
                &self.utxo_hd_flavor,
                &self.cardano_node_version,
                self.commit,
                context.is_json_output_enabled(),
            )?;

            Ok(())
        };

        if let Err(e) = Self::cleanup(&work_dir, &distribution_dir, self.commit, result.is_ok()) {
            progress_printer.print_message(&format!(
                "Failed to clean up temporary directory '{distribution_dir}' after execution: {e:?}",
                distribution_dir = distribution_dir.display(),
            ))?;
        }

        result
    }

    fn calculate_number_of_steps(is_local_bin_mode: bool, commit: bool) -> u16 {
        let minimal_steps = 1;
        let mut steps = minimal_steps;
        if !is_local_bin_mode {
            steps += 2
        };
        if commit {
            steps += 1
        };
        steps
    }

    async fn download_cardano_node_distribution(
        step_number: u16,
        progress_printer: &ProgressPrinter,
        github_api_client: impl GitHubReleaseRetriever,
        http_downloader: impl HttpDownloader,
        tag: &str,
        target_dir: &Path,
    ) -> MithrilResult<PathBuf> {
        progress_printer.report_step(
            step_number,
            &format!("Downloading Cardano node distribution for tag: '{tag}'..."),
        )?;
        let release = match tag {
            LATEST_DISTRIBUTION_TAG => github_api_client
                .get_latest_release(GITHUB_ORGANIZATION, GITHUB_REPOSITORY)
                .await
                .with_context(|| "Failed to get latest release")?,
            PRERELEASE_DISTRIBUTION_TAG => github_api_client
                .get_prerelease(GITHUB_ORGANIZATION, GITHUB_REPOSITORY)
                .await
                .with_context(|| "Failed to get pre-release")?,
            _ => github_api_client
                .get_release_by_tag(GITHUB_ORGANIZATION, GITHUB_REPOSITORY, tag)
                .await
                .with_context(|| format!("Failed to get release by tag: {tag}"))?,
        };
        let asset = release.get_asset_for_os(env::consts::OS)?.with_context(|| {
            format!(
                "Failed to find asset for current platform: {}",
                env::consts::OS
            )
        })?;
        let archive_path = http_downloader
            .download_file(asset.browser_download_url.parse()?, target_dir, &asset.name)
            .await?;

        progress_printer.print_message(&format!(
            "Distribution downloaded successfully. Archive location: {}",
            archive_path.display()
        ))?;

        Ok(archive_path)
    }

    fn convert_ledger_state_snapshot(
        step_number: u16,
        progress_printer: &ProgressPrinter,
        work_dir: &Path,
        converter_bin: PathBuf,
        config_path: PathBuf,
        command: &SnapshotConverterCommand,
    ) -> MithrilResult<PathBuf> {
        progress_printer.report_step(
            step_number,
            &format!(
                "Converting ledger state snapshot to '{}' flavor",
                command.utxo_hd_flavor
            ),
        )?;
        let snapshots =
            Self::find_most_recent_snapshots(&command.db_directory, CONVERSION_FALLBACK_LIMIT)?;
        let converter_bin_config = SnapshotConverterConfig {
            converter_bin,
            config_path,
            utxo_hd_flavor: command.utxo_hd_flavor.clone(),
            hide_output: matches!(
                progress_printer.output_type(),
                ProgressOutputType::JsonReporter | ProgressOutputType::Hidden
            ),
        };

        let converter_bin = get_snapshot_converter_bin_by_version(
            &command.cardano_node_version,
            converter_bin_config,
        );

        Self::try_convert(
            progress_printer,
            work_dir,
            &command.utxo_hd_flavor,
            &snapshots,
            Box::new(converter_bin),
        )
    }

    fn print_successful_result(
        db_dir: &Path,
        converted_snapshot_path: &Path,
        cardano_network: &CardanoNetworkCliArg,
        utxo_hd_flavor: &UTxOHDFlavor,
        cardano_node_version: &str,
        commit: bool,
        is_json_output_enabled: bool,
    ) -> MithrilResult<()> {
        let canonical_db_dir = &db_dir
            .canonicalize()
            .with_context(|| format!("Could not get canonical path of '{}'", db_dir.display()))?;
        let message =
            format!("Ledger state have been successfully converted to {utxo_hd_flavor} format");
        let timestamp = Utc::now().to_rfc3339();

        if commit {
            let docker_cmd = CardanoDbUtils::get_docker_run_command(
                canonical_db_dir,
                &cardano_network.to_string(),
                cardano_node_version,
                utxo_hd_flavor.into(),
            );

            if matches!(&utxo_hd_flavor, UTxOHDFlavor::Legacy) {
                print_simple_warning(
                    "Legacy ledger format is only compatible with cardano-node up to `10.3.1`.",
                    is_json_output_enabled,
                );
            }

            if is_json_output_enabled {
                println!(
                    "{}",
                    serde_json::json!({
                        "message": message,
                        "timestamp": timestamp,
                        "run_docker_cmd": docker_cmd,
                    })
                );
            } else {
                println!(
                    r###"{message}.

If you are using the Cardano Docker image, you can start the Cardano node with:

   {docker_cmd}
"###,
                );
            }
        } else if is_json_output_enabled {
            println!(
                "{}",
                serde_json::json!({
                    "message": message,
                    "timestamp": timestamp,
                    "converted_snapshot_path": converted_snapshot_path,
                })
            );
        } else {
            println!(
                r###"{message}.

Snapshot location: {}
"###,
                converted_snapshot_path.display()
            );
        }

        Ok(())
    }

    fn try_convert(
        progress_printer: &ProgressPrinter,
        work_dir: &Path,
        utxo_hd_flavor: &UTxOHDFlavor,
        snapshots: &[PathBuf],
        converter: Box<dyn SnapshotConverter>,
    ) -> MithrilResult<PathBuf> {
        let snapshots_dir = work_dir.join(SNAPSHOTS_DIR);

        for (i, snapshot) in snapshots.iter().enumerate() {
            let attempt = i + 1;
            let snapshot_path_display = snapshot.display();
            progress_printer.print_message(&format!(
                "Converting '{snapshot_path_display}' (attempt #{attempt})",
            ))?;

            let input_path = copy_dir(snapshot, &snapshots_dir)?;
            let output_path = Self::compute_converted_snapshot_output_path(
                &snapshots_dir,
                &input_path,
                utxo_hd_flavor,
            )?;

            match converter.convert(&input_path, &output_path) {
                Ok(()) => {
                    progress_printer.print_message(&format!(
                        "Successfully converted ledger state snapshot: '{snapshot_path_display}'",
                    ))?;
                    return Ok(output_path);
                }
                Err(e) => {
                    progress_printer.print_message(&format!(
                        "Failed to convert ledger state snapshot '{snapshot_path_display}': {e}",
                    ))?;
                    continue;
                }
            };
        }

        Err(anyhow!(
            "Failed to convert any of the provided ledger state snapshots to the desired flavor: {}",
            utxo_hd_flavor
        ))
    }

    fn get_snapshot_converter_binary_path(
        distribution_dir: &Path,
        target_os: &str,
    ) -> MithrilResult<PathBuf> {
        let base_path = distribution_dir.join(SNAPSHOT_CONVERTER_BIN_DIR);
        let binary_name = match target_os {
            "linux" | "macos" => SNAPSHOT_CONVERTER_BIN_NAME_UNIX,
            "windows" => SNAPSHOT_CONVERTER_BIN_NAME_WINDOWS,
            _ => return Err(anyhow!("Unsupported platform: {}", target_os)),
        };

        Ok(base_path.join(binary_name))
    }

    fn get_snapshot_converter_config_path(
        distribution_dir: &Path,
        network: &CardanoNetworkCliArg,
    ) -> PathBuf {
        distribution_dir
            .join(SNAPSHOT_CONVERTER_CONFIG_DIR)
            .join(network.to_string())
            .join(SNAPSHOT_CONVERTER_CONFIG_FILE)
    }

    /// Returns the list of valid ledger snapshot directories sorted in ascending order of slot number.
    ///
    /// Only directories with numeric names are considered valid snapshots.
    fn get_sorted_snapshot_dirs(ledger_dir: &Path) -> MithrilResult<Vec<(u64, PathBuf)>> {
        let entries = read_dir(ledger_dir).with_context(|| {
            format!(
                "Failed to read ledger state snapshots directory: {}",
                ledger_dir.display()
            )
        })?;

        let mut snapshots = entries
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                if !path.is_dir() {
                    return None;
                }
                SnapshotConverterCommand::extract_slot_number(&path)
                    .ok()
                    .map(|slot| (slot, path))
            })
            .collect::<Vec<_>>();

        snapshots.sort_by_key(|(slot, _)| *slot);

        Ok(snapshots)
    }

    fn find_most_recent_snapshots(db_dir: &Path, count: usize) -> MithrilResult<Vec<PathBuf>> {
        let ledger_dir = db_dir.join(LEDGER_DIR);
        let snapshots = Self::get_sorted_snapshot_dirs(&ledger_dir)?
            .into_iter()
            .rev()
            .take(count)
            .map(|(_, path)| path)
            .collect::<Vec<_>>();

        if snapshots.is_empty() {
            return Err(anyhow!(
                "No valid ledger state snapshots found in directory: {}",
                ledger_dir.display()
            ));
        }

        Ok(snapshots)
    }

    fn compute_converted_snapshot_output_path(
        snapshots_dir: &Path,
        input_snapshot: &Path,
        flavor: &UTxOHDFlavor,
    ) -> MithrilResult<PathBuf> {
        let slot_number = Self::extract_slot_number(input_snapshot).with_context(|| {
            format!(
                "Failed to extract slot number from: {}",
                input_snapshot.display()
            )
        })?;
        let converted_snapshot_path = snapshots_dir.join(format!(
            "{}_{}",
            slot_number,
            flavor.to_string().to_lowercase()
        ));

        Ok(converted_snapshot_path)
    }

    fn extract_slot_number(path: &Path) -> MithrilResult<u64> {
        let file_name = path
            .file_name()
            .with_context(|| format!("No filename in path: {}", path.display()))?;
        let file_name_str = file_name
            .to_str()
            .with_context(|| format!("Invalid UTF-8 in path filename: {:?}", file_name))?;

        file_name_str
            .parse::<u64>()
            .with_context(|| format!("Invalid slot number in path filename: {file_name_str}"))
    }

    /// Commits the converted snapshot by replacing the current ledger state snapshots in the database directory.
    fn commit_converted_snapshot(
        step_number: u16,
        progress_printer: &ProgressPrinter,
        db_dir: &Path,
        converted_snapshot_path: &Path,
        utxo_hd_flavor: &UTxOHDFlavor,
    ) -> MithrilResult<()> {
        let ledger_dir = db_dir.join(LEDGER_DIR);

        progress_printer.report_step(
            step_number,
            &format!(
                "Upgrading and replacing ledger state in {} with converted snapshot: {}",
                ledger_dir.display(),
                converted_snapshot_path.display()
            ),
        )?;

        let filename = converted_snapshot_path
            .file_name()
            .with_context(|| "Missing filename in converted snapshot path")?
            .to_string_lossy();
        let (slot_number, _) = filename
            .split_once('_')
            .with_context(|| format!("Invalid converted snapshot name format: {}", filename))?;

        let destination_name = if *utxo_hd_flavor == UTxOHDFlavor::Lsm {
            format!("{slot_number}_lsm")
        } else {
            slot_number.to_string()
        };

        remove_dir_contents(&ledger_dir).with_context(|| {
            format!(
                "Failed to remove contents of ledger directory: {}",
                ledger_dir.display()
            )
        })?;
        let destination = ledger_dir.join(destination_name);
        rename(converted_snapshot_path, &destination).with_context(|| {
            format!(
                "Failed to move converted snapshot to ledger directory: {}",
                destination.display()
            )
        })?;

        if *utxo_hd_flavor == UTxOHDFlavor::Lsm {
            let lsm_source = converted_snapshot_path
                .parent()
                .with_context(|| {
                    format!(
                        "Missing parent directory for converted snapshot: {}",
                        converted_snapshot_path.display()
                    )
                })?
                .join(LSM_DATABASE_DIR);
            let lsm_destination = db_dir.join(LSM_DATABASE_DIR);
            if lsm_destination.exists() {
                remove_dir_all(&lsm_destination).with_context(|| {
                    format!(
                        "Failed to remove existing LSM directory: {}",
                        lsm_destination.display()
                    )
                })?;
            }
            rename(&lsm_source, &lsm_destination).with_context(|| {
                format!(
                    "Failed to move LSM database to: {}",
                    lsm_destination.display()
                )
            })?;
        }

        Ok(())
    }

    fn cleanup(
        work_dir: &Path,
        distribution_dir: &Path,
        commit: bool,
        success: bool,
    ) -> MithrilResult<()> {
        if distribution_dir.exists() {
            remove_dir_all(distribution_dir)?;
        }
        match (success, commit) {
            (true, true) => {
                remove_dir_all(work_dir)?;
            }
            (true, false) => {}
            (false, _) => {
                remove_dir_all(work_dir)?;
            }
        }

        Ok(())
    }

    fn detect_cardano_network(db_dir: &Path) -> MithrilResult<CardanoNetworkCliArg> {
        let magic_id_path = db_dir.join(PROTOCOL_MAGIC_ID_FILE);
        let content = std::fs::read_to_string(&magic_id_path).with_context(|| {
            format!(
                "Failed to read protocolMagicId file: {}",
                magic_id_path.display()
            )
        })?;
        let id: MagicId = content
            .trim()
            .parse()
            .with_context(|| format!("Invalid protocolMagicId value: '{}'", content.trim()))?;
        let network = CardanoNetwork::from(id);

        CardanoNetworkCliArg::try_from(network)
    }
}

fn get_snapshot_converter_bin_by_version(
    cardano_node_version: &str,
    converter_bin_config: SnapshotConverterConfig,
) -> SnapshotConverterBin {
    if is_version_at_least_11_1_0_or_latest(cardano_node_version) {
        SnapshotConverterBin::From11_1(converter_bin_config)
    } else if is_version_at_least_10_7_0_or_latest(cardano_node_version) {
        SnapshotConverterBin::From10_7(converter_bin_config)
    } else if is_version_at_least_10_6_2_or_latest(cardano_node_version) {
        SnapshotConverterBin::UpTo10_6(converter_bin_config)
    } else {
        SnapshotConverterBin::UpTo10_5(converter_bin_config)
    }
}

fn is_version_at_least_11_1_0_or_latest(version: &str) -> bool {
    is_version_equal_or_upper(version, CARDANO_NODE_V11_1_0)
}

fn is_version_at_least_10_7_0_or_latest(version: &str) -> bool {
    is_version_equal_or_upper(version, CARDANO_NODE_V10_7_0)
}

fn is_version_at_least_10_6_2_or_latest(version: &str) -> bool {
    is_version_equal_or_upper(version, CARDANO_NODE_V10_6_2)
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use mithril_common::temp_dir_create;

    use super::*;

    mod execute {
        use std::path::PathBuf;

        use slog::{Logger, o};

        use crate::{
            CommandContext, ConfigParameters,
            commands::tools::{
                SnapshotConverterCommand, utxo_hd::snapshot_converter::UTxOHDFlavor,
            },
        };

        fn fake_command_context() -> CommandContext {
            CommandContext::new(
                ConfigParameters::default(),
                true,
                true,
                Logger::root(slog::Discard, o!()),
            )
        }

        fn dummy_snapshot_converter_command() -> SnapshotConverterCommand {
            #[allow(deprecated)]
            SnapshotConverterCommand {
                db_directory: PathBuf::new(),
                cardano_node_version: "1.0.0".to_string(),
                binary_path: None,
                config_path: None,
                commit: false,
                utxo_hd_flavor: UTxOHDFlavor::Legacy,
                github_token: None,
                cardano_network: None,
            }
        }

        #[tokio::test]
        async fn should_return_error_if_utxo_hd_flavor_is_legacy_and_cardano_node_version_10_6_2() {
            let command = SnapshotConverterCommand {
                cardano_node_version: "10.6.2".to_string(),
                utxo_hd_flavor: UTxOHDFlavor::Legacy,
                ..dummy_snapshot_converter_command()
            };

            let result = SnapshotConverterCommand::execute(&command, fake_command_context()).await;

            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err().to_string(),
                "UTxO HD Flavor Legacy is not supported on Cardano node 10.6.2 or upper"
            );
        }

        #[tokio::test]
        async fn should_return_error_if_utxo_hd_flavor_is_legacy_and_cardano_node_version_10_6_2_or_upper()
         {
            let command = SnapshotConverterCommand {
                cardano_node_version: "10.7.7".to_string(),
                utxo_hd_flavor: UTxOHDFlavor::Legacy,
                ..dummy_snapshot_converter_command()
            };

            let result = SnapshotConverterCommand::execute(&command, fake_command_context()).await;

            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err().to_string(),
                "UTxO HD Flavor Legacy is not supported on Cardano node 10.6.2 or upper"
            );
        }

        #[tokio::test]
        async fn should_return_error_if_utxo_hd_flavor_is_legacy_and_cardano_node_version_latest() {
            let command = SnapshotConverterCommand {
                cardano_node_version: "latest".to_string(),
                utxo_hd_flavor: UTxOHDFlavor::Legacy,
                ..dummy_snapshot_converter_command()
            };

            let result = SnapshotConverterCommand::execute(&command, fake_command_context()).await;

            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err().to_string(),
                "UTxO HD Flavor Legacy is not supported on Cardano node 10.6.2 or upper"
            );
        }
    }

    mod download_cardano_node_distribution {
        use mockall::predicate::eq;
        use reqwest::Url;

        use crate::utils::{GitHubRelease, MockGitHubReleaseRetriever, MockHttpDownloader};

        use super::*;

        #[tokio::test]
        async fn downloads_latest_release_distribution() {
            let temp_dir = temp_dir_create!();
            let release = GitHubRelease::dummy_with_all_supported_assets();
            let asset = release.get_asset_for_os(env::consts::OS).unwrap().unwrap();

            let cloned_release = release.clone();
            let mut github_api_client = MockGitHubReleaseRetriever::new();
            github_api_client
                .expect_get_latest_release()
                .with(eq(GITHUB_ORGANIZATION), eq(GITHUB_REPOSITORY))
                .returning(move |_, _| Ok(cloned_release.clone()));

            let mut http_downloader = MockHttpDownloader::new();
            http_downloader
                .expect_download_file()
                .with(
                    eq(Url::parse(&asset.browser_download_url).unwrap()),
                    eq(temp_dir.clone()),
                    eq(asset.name.clone()),
                )
                .returning(|_, _, _| Ok(PathBuf::new()));

            SnapshotConverterCommand::download_cardano_node_distribution(
                1,
                &ProgressPrinter::new(ProgressOutputType::Hidden, 1),
                github_api_client,
                http_downloader,
                LATEST_DISTRIBUTION_TAG,
                &temp_dir,
            )
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn downloads_prerelease_distribution() {
            let temp_dir = temp_dir_create!();
            let release = GitHubRelease::dummy_with_all_supported_assets();
            let asset = release.get_asset_for_os(env::consts::OS).unwrap().unwrap();

            let cloned_release = release.clone();
            let mut github_api_client = MockGitHubReleaseRetriever::new();
            github_api_client
                .expect_get_prerelease()
                .with(eq(GITHUB_ORGANIZATION), eq(GITHUB_REPOSITORY))
                .returning(move |_, _| Ok(cloned_release.clone()));

            let mut http_downloader = MockHttpDownloader::new();
            http_downloader
                .expect_download_file()
                .with(
                    eq(Url::parse(&asset.browser_download_url).unwrap()),
                    eq(temp_dir.clone()),
                    eq(asset.name.clone()),
                )
                .returning(|_, _, _| Ok(PathBuf::new()));

            SnapshotConverterCommand::download_cardano_node_distribution(
                1,
                &ProgressPrinter::new(ProgressOutputType::Hidden, 1),
                github_api_client,
                http_downloader,
                PRERELEASE_DISTRIBUTION_TAG,
                &temp_dir,
            )
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn downloads_tagged_release_distribution() {
            let cardano_node_version = "10.3.1";
            let temp_dir = temp_dir_create!();
            let release = GitHubRelease::dummy_with_all_supported_assets();
            let asset = release.get_asset_for_os(env::consts::OS).unwrap().unwrap();

            let cloned_release = release.clone();
            let mut github_api_client = MockGitHubReleaseRetriever::new();
            github_api_client
                .expect_get_release_by_tag()
                .with(
                    eq(GITHUB_ORGANIZATION),
                    eq(GITHUB_REPOSITORY),
                    eq(cardano_node_version),
                )
                .returning(move |_, _, _| Ok(cloned_release.clone()));

            let mut http_downloader = MockHttpDownloader::new();
            http_downloader
                .expect_download_file()
                .with(
                    eq(Url::parse(&asset.browser_download_url).unwrap()),
                    eq(temp_dir.clone()),
                    eq(asset.name.clone()),
                )
                .returning(|_, _, _| Ok(PathBuf::new()));

            SnapshotConverterCommand::download_cardano_node_distribution(
                1,
                &ProgressPrinter::new(ProgressOutputType::Hidden, 1),
                github_api_client,
                http_downloader,
                cardano_node_version,
                &temp_dir,
            )
            .await
            .unwrap();
        }
    }

    mod get_snapshot_converter_binary_path {
        use super::*;

        #[test]
        fn returns_correct_binary_path_for_linux() {
            let distribution_dir = PathBuf::from("/path/to/distribution");

            let binary_path = SnapshotConverterCommand::get_snapshot_converter_binary_path(
                &distribution_dir,
                "linux",
            )
            .unwrap();

            assert_eq!(
                binary_path,
                distribution_dir
                    .join(SNAPSHOT_CONVERTER_BIN_DIR)
                    .join(SNAPSHOT_CONVERTER_BIN_NAME_UNIX)
            );
        }

        #[test]
        fn returns_correct_binary_path_for_macos() {
            let distribution_dir = PathBuf::from("/path/to/distribution");

            let binary_path = SnapshotConverterCommand::get_snapshot_converter_binary_path(
                &distribution_dir,
                "macos",
            )
            .unwrap();

            assert_eq!(
                binary_path,
                distribution_dir
                    .join(SNAPSHOT_CONVERTER_BIN_DIR)
                    .join(SNAPSHOT_CONVERTER_BIN_NAME_UNIX)
            );
        }

        #[test]
        fn returns_correct_binary_path_for_windows() {
            let distribution_dir = PathBuf::from("/path/to/distribution");

            let binary_path = SnapshotConverterCommand::get_snapshot_converter_binary_path(
                &distribution_dir,
                "windows",
            )
            .unwrap();

            assert_eq!(
                binary_path,
                distribution_dir
                    .join(SNAPSHOT_CONVERTER_BIN_DIR)
                    .join(SNAPSHOT_CONVERTER_BIN_NAME_WINDOWS)
            );
        }
    }

    mod get_snapshot_converter_config_path {
        use super::*;

        #[test]
        fn returns_config_path_for_mainnet() {
            let distribution_dir = PathBuf::from("/path/to/distribution");
            let network = CardanoNetworkCliArg::Mainnet;

            let config_path = SnapshotConverterCommand::get_snapshot_converter_config_path(
                &distribution_dir,
                &network,
            );

            assert_eq!(
                config_path,
                distribution_dir
                    .join(SNAPSHOT_CONVERTER_CONFIG_DIR)
                    .join(network.to_string())
                    .join(SNAPSHOT_CONVERTER_CONFIG_FILE)
            );
        }

        #[test]
        fn returns_config_path_for_preprod() {
            let distribution_dir = PathBuf::from("/path/to/distribution");
            let network = CardanoNetworkCliArg::Preprod;

            let config_path = SnapshotConverterCommand::get_snapshot_converter_config_path(
                &distribution_dir,
                &network,
            );

            assert_eq!(
                config_path,
                distribution_dir
                    .join(SNAPSHOT_CONVERTER_CONFIG_DIR)
                    .join(network.to_string())
                    .join(SNAPSHOT_CONVERTER_CONFIG_FILE)
            );
        }

        #[test]
        fn returns_config_path_for_preview() {
            let distribution_dir = PathBuf::from("/path/to/distribution");
            let network = CardanoNetworkCliArg::Preview;

            let config_path = SnapshotConverterCommand::get_snapshot_converter_config_path(
                &distribution_dir,
                &network,
            );

            assert_eq!(
                config_path,
                distribution_dir
                    .join(SNAPSHOT_CONVERTER_CONFIG_DIR)
                    .join(network.to_string())
                    .join(SNAPSHOT_CONVERTER_CONFIG_FILE)
            );
        }
    }

    mod extract_slot_number {
        use super::*;

        #[test]
        fn parses_valid_numeric_path() {
            let path = PathBuf::from("/whatever").join("123456");

            let slot = SnapshotConverterCommand::extract_slot_number(&path).unwrap();

            assert_eq!(slot, 123456);
        }

        #[test]
        fn fails_with_non_numeric_filename() {
            let path = PathBuf::from("/whatever").join("notanumber");

            SnapshotConverterCommand::extract_slot_number(&path)
                .expect_err("Should fail with non-numeric filename");
        }

        #[test]
        fn fails_if_no_filename() {
            let path = PathBuf::from("/");

            SnapshotConverterCommand::extract_slot_number(&path)
                .expect_err("Should fail if path has no filename");
        }
    }

    mod compute_converted_snapshot_output_path {
        use super::*;

        #[test]
        fn compute_output_path_from_numeric_file_name() {
            let snapshots_dir = PathBuf::from("/snapshots");
            let input_snapshot = PathBuf::from("/whatever").join("123456");

            {
                let snapshot_path =
                    SnapshotConverterCommand::compute_converted_snapshot_output_path(
                        &snapshots_dir,
                        &input_snapshot,
                        &UTxOHDFlavor::Lmdb,
                    )
                    .unwrap();

                assert_eq!(snapshot_path, snapshots_dir.join("123456_lmdb"));
            }

            {
                let snapshot_path =
                    SnapshotConverterCommand::compute_converted_snapshot_output_path(
                        &snapshots_dir,
                        &input_snapshot,
                        &UTxOHDFlavor::Legacy,
                    )
                    .unwrap();

                assert_eq!(snapshot_path, snapshots_dir.join("123456_legacy"));
            }

            {
                let snapshot_path =
                    SnapshotConverterCommand::compute_converted_snapshot_output_path(
                        &snapshots_dir,
                        &input_snapshot,
                        &UTxOHDFlavor::Lsm,
                    )
                    .unwrap();

                assert_eq!(snapshot_path, snapshots_dir.join("123456_lsm"));
            }
        }

        #[test]
        fn fails_with_invalid_slot_number() {
            let snapshots_dir = PathBuf::from("/snapshots");
            let input_snapshot = PathBuf::from("/whatever/notanumber");

            SnapshotConverterCommand::compute_converted_snapshot_output_path(
                &snapshots_dir,
                &input_snapshot,
                &UTxOHDFlavor::Lmdb,
            )
            .expect_err("Should fail with invalid slot number");
        }
    }

    mod commit_converted_snapshot {
        use super::*;

        #[test]
        fn moves_converted_snapshot_to_ledger_directory() {
            let tmp_dir = temp_dir_create!();
            let ledger_dir = tmp_dir.join(LEDGER_DIR);
            create_dir(&ledger_dir).unwrap();
            let previous_snapshot = ledger_dir.join("123");
            File::create(&previous_snapshot).unwrap();

            let converted_snapshot = tmp_dir.join("456_lmdb");
            File::create(&converted_snapshot).unwrap();

            assert!(previous_snapshot.exists());
            SnapshotConverterCommand::commit_converted_snapshot(
                1,
                &ProgressPrinter::new(ProgressOutputType::Hidden, 1),
                &tmp_dir,
                &converted_snapshot,
                &UTxOHDFlavor::Lmdb,
            )
            .unwrap();

            assert!(!previous_snapshot.exists());
            assert!(ledger_dir.join("456").exists());
        }

        #[test]
        fn moves_lsm_converted_snapshot_to_ledger_directory_with_lsm_suffix() {
            let tmp_dir = temp_dir_create!();
            let snapshots_dir = tmp_dir.join("snapshots");
            create_dir(&snapshots_dir).unwrap();

            let converted_snapshot = snapshots_dir.join("456_lsm");
            create_dir(&converted_snapshot).unwrap();
            File::create(converted_snapshot.join("some_file")).unwrap();

            let lsm_source = snapshots_dir.join(LSM_DATABASE_DIR);
            create_dir(&lsm_source).unwrap();
            File::create(lsm_source.join("lsm_data")).unwrap();

            let db_dir = tmp_dir.join("db");
            create_dir(&db_dir).unwrap();
            let ledger_dir = db_dir.join(LEDGER_DIR);
            create_dir(&ledger_dir).unwrap();

            SnapshotConverterCommand::commit_converted_snapshot(
                1,
                &ProgressPrinter::new(ProgressOutputType::Hidden, 1),
                &db_dir,
                &converted_snapshot,
                &UTxOHDFlavor::Lsm,
            )
            .unwrap();

            assert!(ledger_dir.join("456_lsm").exists());
            assert!(ledger_dir.join("456_lsm").join("some_file").exists());
            assert!(db_dir.join(LSM_DATABASE_DIR).join("lsm_data").exists());
        }

        #[test]
        fn lsm_commit_replaces_existing_lsm_directory() {
            let tmp_dir = temp_dir_create!();
            let snapshots_dir = tmp_dir.join("snapshots");
            create_dir(&snapshots_dir).unwrap();

            let converted_snapshot = snapshots_dir.join("456_lsm");
            create_dir(&converted_snapshot).unwrap();

            let lsm_source = snapshots_dir.join(LSM_DATABASE_DIR);
            create_dir(&lsm_source).unwrap();
            File::create(lsm_source.join("new_data")).unwrap();

            let db_dir = tmp_dir.join("db");
            create_dir(&db_dir).unwrap();
            let ledger_dir = db_dir.join(LEDGER_DIR);
            create_dir(&ledger_dir).unwrap();
            let existing_lsm = db_dir.join(LSM_DATABASE_DIR);
            create_dir(&existing_lsm).unwrap();
            File::create(existing_lsm.join("old_data")).unwrap();

            SnapshotConverterCommand::commit_converted_snapshot(
                1,
                &ProgressPrinter::new(ProgressOutputType::Hidden, 1),
                &db_dir,
                &converted_snapshot,
                &UTxOHDFlavor::Lsm,
            )
            .unwrap();

            let lsm_destination = db_dir.join(LSM_DATABASE_DIR);
            assert!(!lsm_destination.join("old_data").exists());
            assert!(lsm_destination.join("new_data").exists());
        }

        #[test]
        fn fails_if_converted_snapshot_has_invalid_filename() {
            let tmp_dir = temp_dir_create!();
            let ledger_dir = tmp_dir.join(LEDGER_DIR);
            create_dir(&ledger_dir).unwrap();
            let previous_snapshot = ledger_dir.join("123");
            File::create(&previous_snapshot).unwrap();

            let converted_snapshot = tmp_dir.join("456");
            File::create(&converted_snapshot).unwrap();

            SnapshotConverterCommand::commit_converted_snapshot(
                1,
                &ProgressPrinter::new(ProgressOutputType::Hidden, 1),
                &tmp_dir,
                &converted_snapshot,
                &UTxOHDFlavor::Lmdb,
            )
            .expect_err("Should fail if converted snapshot has invalid filename");

            assert!(previous_snapshot.exists());
        }
    }

    mod cleanup {
        use super::*;

        #[test]
        fn removes_both_dirs_on_success_when_commit_is_true() {
            let tmp = temp_dir_create!();
            let work_dir = tmp.join("workdir_dir");
            let distribution_dir = tmp.join("distribution_dir");
            create_dir(&work_dir).unwrap();
            create_dir(&distribution_dir).unwrap();

            SnapshotConverterCommand::cleanup(&work_dir, &distribution_dir, true, true).unwrap();

            assert!(!distribution_dir.exists());
            assert!(!work_dir.exists());
        }

        #[test]
        fn removes_only_distribution_on_success_when_commit_is_false() {
            let tmp = temp_dir_create!();
            let work_dir = tmp.join("workdir_dir");
            let distribution_dir = tmp.join("distribution_dir");
            create_dir(&work_dir).unwrap();
            create_dir(&distribution_dir).unwrap();

            SnapshotConverterCommand::cleanup(&work_dir, &distribution_dir, false, true).unwrap();

            assert!(!distribution_dir.exists());
            assert!(work_dir.exists());
        }

        #[test]
        fn removes_both_dirs_on_success_when_commit_is_true_and_distribution_is_nested() {
            let tmp = temp_dir_create!();
            let work_dir = tmp.join("workdir_dir");
            let distribution_dir = work_dir.join("distribution_dir");
            create_dir(&work_dir).unwrap();
            create_dir(&distribution_dir).unwrap();

            SnapshotConverterCommand::cleanup(&work_dir, &distribution_dir, true, true).unwrap();

            assert!(!distribution_dir.exists());
            assert!(!work_dir.exists());
        }

        #[test]
        fn removes_only_distribution_on_success_when_commit_is_false_and_distribution_is_nested() {
            let tmp = temp_dir_create!();
            let work_dir = tmp.join("workdir_dir");
            let distribution_dir = work_dir.join("distribution_dir");
            create_dir(&work_dir).unwrap();
            create_dir(&distribution_dir).unwrap();

            SnapshotConverterCommand::cleanup(&work_dir, &distribution_dir, false, true).unwrap();

            assert!(!distribution_dir.exists());
            assert!(work_dir.exists());
        }

        #[test]
        fn removes_both_dirs_on_failure() {
            let tmp = temp_dir_create!();
            let work_dir = tmp.join("workdir_dir");
            let distribution_dir = tmp.join("distribution_dir");
            create_dir(&work_dir).unwrap();
            create_dir(&distribution_dir).unwrap();

            SnapshotConverterCommand::cleanup(&work_dir, &distribution_dir, false, false).unwrap();

            assert!(!distribution_dir.exists());
            assert!(!work_dir.exists());
        }
    }

    mod detect_cardano_network {
        use super::*;

        fn create_protocol_magic_id_file(db_dir: &Path, magic_id: MagicId) -> PathBuf {
            let file_path = db_dir.join(PROTOCOL_MAGIC_ID_FILE);
            std::fs::write(&file_path, magic_id.to_string()).unwrap();

            file_path
        }

        #[test]
        fn detects_mainnet() {
            let db_dir = temp_dir_create!();
            create_protocol_magic_id_file(&db_dir, CardanoNetwork::MAINNET_MAGIC_ID);

            let network = SnapshotConverterCommand::detect_cardano_network(&db_dir).unwrap();

            assert_eq!(network, CardanoNetworkCliArg::Mainnet);
        }

        #[test]
        fn detects_preprod() {
            let db_dir = temp_dir_create!();
            create_protocol_magic_id_file(&db_dir, CardanoNetwork::PREPROD_MAGIC_ID);

            let network = SnapshotConverterCommand::detect_cardano_network(&db_dir).unwrap();

            assert_eq!(network, CardanoNetworkCliArg::Preprod);
        }

        #[test]
        fn detects_preview() {
            let db_dir = temp_dir_create!();
            create_protocol_magic_id_file(&db_dir, CardanoNetwork::PREVIEW_MAGIC_ID);

            let network = SnapshotConverterCommand::detect_cardano_network(&db_dir).unwrap();

            assert_eq!(network, CardanoNetworkCliArg::Preview);
        }

        #[test]
        fn fails_on_invalid_network() {
            let db_dir = temp_dir_create!();
            let invalid_magic_id = 999999;
            create_protocol_magic_id_file(&db_dir, invalid_magic_id);

            SnapshotConverterCommand::detect_cardano_network(&db_dir)
                .expect_err("Should fail with invalid network magic ID");
        }

        #[test]
        fn fails_when_protocol_magic_id_file_is_empty() {
            let db_dir = temp_dir_create!();
            File::create(db_dir.join(PROTOCOL_MAGIC_ID_FILE)).unwrap();

            SnapshotConverterCommand::detect_cardano_network(&db_dir)
                .expect_err("Should fail when protocol magic ID file is empty");
        }

        #[test]
        fn fails_when_protocol_magic_id_file_is_missing() {
            let db_dir = temp_dir_create!();

            assert!(!db_dir.join(PROTOCOL_MAGIC_ID_FILE).exists());

            SnapshotConverterCommand::detect_cardano_network(&db_dir)
                .expect_err("Should fail when protocol magic ID file is missing");
        }
    }

    mod snapshots_indexing {
        use mithril_common::temp_dir_create;

        use super::*;

        #[test]
        fn returns_the_two_most_recent_snapshots() {
            let db_dir = temp_dir_create!();
            let ledger_dir = db_dir.join(LEDGER_DIR);
            create_dir(&ledger_dir).unwrap();

            create_dir(ledger_dir.join("1500")).unwrap();
            create_dir(ledger_dir.join("500")).unwrap();
            create_dir(ledger_dir.join("1000")).unwrap();

            let found = SnapshotConverterCommand::find_most_recent_snapshots(&db_dir, 2).unwrap();

            assert_eq!(
                found,
                vec![ledger_dir.join("1500"), ledger_dir.join("1000")]
            );
        }

        #[test]
        fn returns_list_with_one_entry_if_only_one_valid_snapshot() {
            let db_dir = temp_dir_create!();
            let ledger_dir = db_dir.join(LEDGER_DIR);
            create_dir(&ledger_dir).unwrap();

            create_dir(ledger_dir.join("500")).unwrap();

            let found = SnapshotConverterCommand::find_most_recent_snapshots(&db_dir, 2).unwrap();

            assert_eq!(found, vec![ledger_dir.join("500")]);
        }

        #[test]
        fn ignores_non_numeric_and_non_directory_entries() {
            let temp_dir = temp_dir_create!();
            let ledger_dir = temp_dir.join(LEDGER_DIR);
            create_dir(&ledger_dir).unwrap();

            create_dir(ledger_dir.join("1000")).unwrap();
            File::create(ledger_dir.join("500")).unwrap();
            create_dir(ledger_dir.join("invalid")).unwrap();

            let found = SnapshotConverterCommand::find_most_recent_snapshots(&temp_dir, 2).unwrap();

            assert_eq!(found, vec![ledger_dir.join("1000")]);
        }

        #[test]
        fn returns_all_available_snapshots_when_count_exceeds_available() {
            let db_dir = temp_dir_create!();
            let ledger_dir = db_dir.join(LEDGER_DIR);
            create_dir(&ledger_dir).unwrap();

            create_dir(ledger_dir.join("1000")).unwrap();
            create_dir(ledger_dir.join("1500")).unwrap();

            let found = SnapshotConverterCommand::find_most_recent_snapshots(&db_dir, 99).unwrap();

            assert_eq!(
                found,
                vec![ledger_dir.join("1500"), ledger_dir.join("1000")]
            );
        }

        #[test]
        fn returns_error_if_no_valid_snapshot_found() {
            let temp_dir = temp_dir_create!();
            let ledger_dir = temp_dir.join(LEDGER_DIR);
            create_dir(&ledger_dir).unwrap();

            File::create(ledger_dir.join("invalid")).unwrap();

            SnapshotConverterCommand::find_most_recent_snapshots(&temp_dir, 2)
                .expect_err("Should return error if no valid ledger snapshot directory found");
        }

        #[test]
        fn get_sorted_snapshot_dirs_returns_sorted_valid_directories() {
            let temp_dir = temp_dir_create!();
            let ledger_dir = temp_dir.join(LEDGER_DIR);
            create_dir(&ledger_dir).unwrap();

            create_dir(ledger_dir.join("1500")).unwrap();
            create_dir(ledger_dir.join("1000")).unwrap();
            create_dir(ledger_dir.join("2000")).unwrap();
            File::create(ledger_dir.join("500")).unwrap();
            create_dir(ledger_dir.join("notanumber")).unwrap();

            let snapshots =
                SnapshotConverterCommand::get_sorted_snapshot_dirs(&ledger_dir).unwrap();

            assert_eq!(
                snapshots,
                vec![
                    (1000, ledger_dir.join("1000")),
                    (1500, ledger_dir.join("1500")),
                    (2000, ledger_dir.join("2000")),
                ]
            );
        }
    }

    mod snapshot_conversion_fallback {
        use mockall::predicate::{self, always};

        use super::*;

        fn create_dummy_snapshots(dir: &Path, count: usize) -> Vec<PathBuf> {
            (1..=count)
                .map(|i| {
                    let snapshot_path = dir.join(format!("{i}"));
                    create_dir(&snapshot_path).unwrap();
                    snapshot_path
                })
                .collect()
        }

        fn contains_filename(expected: &Path) -> impl Fn(&Path) -> bool + use<> {
            let filename = expected.file_name().unwrap().to_string_lossy().to_string();

            move |p: &Path| p.to_string_lossy().contains(&filename)
        }

        #[test]
        fn conversion_succeed_and_is_called_once_if_first_conversion_succeeds() {
            let temp_dir = temp_dir_create!();
            let snapshots = create_dummy_snapshots(&temp_dir, 2);

            let mut converter = MockSnapshotConverter::new();
            converter
                .expect_convert()
                .with(
                    predicate::function(contains_filename(&snapshots[0])),
                    always(),
                )
                .return_once(|_, _| Ok(()))
                .once();

            SnapshotConverterCommand::try_convert(
                &ProgressPrinter::new(ProgressOutputType::Hidden, 1),
                Path::new(""),
                &UTxOHDFlavor::Lmdb,
                &snapshots,
                Box::new(converter),
            )
            .unwrap();
        }

        #[test]
        fn conversion_falls_back_if_first_conversion_fails() {
            let temp_dir = temp_dir_create!();
            let snapshots = create_dummy_snapshots(&temp_dir, 2);

            let mut converter = MockSnapshotConverter::new();
            converter
                .expect_convert()
                .with(
                    predicate::function(contains_filename(&snapshots[0])),
                    always(),
                )
                .return_once(|_, _| Err(anyhow!("Error during conversion")))
                .once();
            converter
                .expect_convert()
                .with(
                    predicate::function(contains_filename(&snapshots[1])),
                    always(),
                )
                .return_once(|_, _| Ok(()))
                .once();

            SnapshotConverterCommand::try_convert(
                &ProgressPrinter::new(ProgressOutputType::Hidden, 1),
                Path::new(""),
                &UTxOHDFlavor::Lmdb,
                &snapshots,
                Box::new(converter),
            )
            .expect("Should succeed even if the first conversion fails");
        }

        #[test]
        fn conversion_fails_if_all_attempts_fail() {
            let temp_dir = temp_dir_create!();
            let snapshots = create_dummy_snapshots(&temp_dir, 2);
            let mut converter = MockSnapshotConverter::new();
            converter
                .expect_convert()
                .returning(|_, _| Err(anyhow!("Conversion failed")))
                .times(2);

            SnapshotConverterCommand::try_convert(
                &ProgressPrinter::new(ProgressOutputType::Hidden, 1),
                Path::new(""),
                &UTxOHDFlavor::Lmdb,
                &snapshots,
                Box::new(converter),
            )
            .expect_err("Should fail if all conversion attempts fail");
        }
    }

    mod get_snapshot_converter_bin_by_version {
        use std::path::PathBuf;

        use crate::commands::tools::utxo_hd::snapshot_converter::{
            SnapshotConverterBin, SnapshotConverterConfig, UTxOHDFlavor,
            get_snapshot_converter_bin_by_version,
        };

        fn dummy_config() -> SnapshotConverterConfig {
            SnapshotConverterConfig {
                converter_bin: PathBuf::new(),
                config_path: PathBuf::new(),
                utxo_hd_flavor: UTxOHDFlavor::Lmdb,
                hide_output: true,
            }
        }

        #[test]
        fn should_return_from_11_1_with_cardano_version_11_1_0_or_upper() {
            let converter_bin = get_snapshot_converter_bin_by_version("11.1.0", dummy_config());
            assert!(
                matches!(converter_bin, SnapshotConverterBin::From11_1(_)),
                "returned type is not SnapshotConverterBin::From11_1"
            );

            let converter_bin = get_snapshot_converter_bin_by_version("11.2.0", dummy_config());
            assert!(
                matches!(converter_bin, SnapshotConverterBin::From11_1(_)),
                "returned type is not SnapshotConverterBin::From11_1"
            );
        }

        #[test]
        fn should_return_from_11_1_with_cardano_version_latest() {
            let converter_bin = get_snapshot_converter_bin_by_version("latest", dummy_config());
            assert!(
                matches!(converter_bin, SnapshotConverterBin::From11_1(_)),
                "returned type is not SnapshotConverterBin::From11_1"
            );
        }

        #[test]
        fn should_return_from_10_7_with_cardano_version_10_7_0_to_11_0_x() {
            let converter_bin = get_snapshot_converter_bin_by_version("10.7.1", dummy_config());
            assert!(
                matches!(converter_bin, SnapshotConverterBin::From10_7(_)),
                "returned type is not SnapshotConverterBin::From10_7"
            );

            let converter_bin = get_snapshot_converter_bin_by_version("11.0.9", dummy_config());
            assert!(
                matches!(converter_bin, SnapshotConverterBin::From10_7(_)),
                "returned type is not SnapshotConverterBin::From10_7"
            );
        }

        #[test]
        fn should_return_up_to_10_6_with_cardano_version_10_6_2_to_10_6_x() {
            let converter_bin = get_snapshot_converter_bin_by_version("10.6.2", dummy_config());
            assert!(
                matches!(converter_bin, SnapshotConverterBin::UpTo10_6(_)),
                "returned type is not SnapshotConverterBin::UpTo10_6"
            );

            let converter_bin = get_snapshot_converter_bin_by_version("10.6.9", dummy_config());
            assert!(
                matches!(converter_bin, SnapshotConverterBin::UpTo10_6(_)),
                "returned type is not SnapshotConverterBin::UpTo10_6"
            );
        }

        #[test]
        fn should_return_up_to_10_5_with_cardano_version_below_10_6_2() {
            let converter_bin = get_snapshot_converter_bin_by_version("10.6.1", dummy_config());
            assert!(
                matches!(converter_bin, SnapshotConverterBin::UpTo10_5(_)),
                "returned type is not SnapshotConverterBin::UpTo10_5"
            );

            let converter_bin = get_snapshot_converter_bin_by_version("10.5.0", dummy_config());
            assert!(
                matches!(converter_bin, SnapshotConverterBin::UpTo10_5(_)),
                "returned type is not SnapshotConverterBin::UpTo10_5"
            );
        }
    }

    mod build_commands_from_11_1 {
        use std::path::PathBuf;
        use std::process::Command;

        use crate::commands::tools::utxo_hd::snapshot_converter::{
            LSM_DATABASE_DIR, LSM_EXPORT_DIR, SnapshotConverterConfig, UTxOHDFlavor,
            build_commands_from_11_1,
        };

        fn dummy_config(utxo_hd_flavor: UTxOHDFlavor) -> SnapshotConverterConfig {
            SnapshotConverterConfig {
                converter_bin: PathBuf::from("/bin/snapshot-converter"),
                config_path: PathBuf::from("/share/config.json"),
                utxo_hd_flavor,
                hide_output: true,
            }
        }

        fn args_of(command: &Command) -> Vec<String> {
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect()
        }

        #[test]
        fn lmdb_builds_a_single_convert_command_without_lsm_flags() {
            let input = PathBuf::from("/work/snapshots/123456");
            let output = PathBuf::from("/work/snapshots/123456_lmdb");
            let config = dummy_config(UTxOHDFlavor::Lmdb);
            let config_path = config.config_path.clone();

            let commands = build_commands_from_11_1(&input, &output, config).unwrap();

            assert_eq!(commands.len(), 1);
            assert_eq!(
                args_of(&commands[0]),
                vec![
                    "convert".to_string(),
                    "--snapshot-in".to_string(),
                    input.to_string_lossy().into_owned(),
                    "--snapshot-out".to_string(),
                    output.to_string_lossy().into_owned(),
                    "--config".to_string(),
                    config_path.to_string_lossy().into_owned(),
                ]
            );
        }

        #[test]
        fn lsm_builds_a_convert_command_then_an_import_command() {
            let input = PathBuf::from("/work/snapshots/123456");
            let output = PathBuf::from("/work/snapshots/123456_lsm");
            let snapshots_dir = output.parent().unwrap();
            let config = dummy_config(UTxOHDFlavor::Lsm);
            let config_path = config.config_path.clone();

            let commands = build_commands_from_11_1(&input, &output, config).unwrap();

            assert_eq!(commands.len(), 2);
            assert_eq!(
                args_of(&commands[0]),
                vec![
                    "convert".to_string(),
                    "--snapshot-in".to_string(),
                    input.to_string_lossy().into_owned(),
                    "--snapshot-out".to_string(),
                    output.to_string_lossy().into_owned(),
                    "--lsm-export-to".to_string(),
                    snapshots_dir.join(LSM_EXPORT_DIR).to_string_lossy().into_owned(),
                    "--config".to_string(),
                    config_path.to_string_lossy().into_owned(),
                ]
            );
            assert_eq!(
                args_of(&commands[1]),
                vec![
                    "lsm".to_string(),
                    "import".to_string(),
                    "--lsm-database".to_string(),
                    snapshots_dir.join(LSM_DATABASE_DIR).to_string_lossy().into_owned(),
                    "--lsm-import-from".to_string(),
                    snapshots_dir.join(LSM_EXPORT_DIR).to_string_lossy().into_owned(),
                    "--snapshot".to_string(),
                    "123456_lsm".to_string(),
                ]
            );
        }

        #[test]
        fn every_command_runs_the_converter_binary() {
            let input = PathBuf::from("/work/snapshots/123456");
            let output = PathBuf::from("/work/snapshots/123456_lsm");
            let config = dummy_config(UTxOHDFlavor::Lsm);
            let converter_bin = config.converter_bin.clone();

            let commands = build_commands_from_11_1(&input, &output, config).unwrap();

            for command in &commands {
                assert_eq!(command.get_program(), converter_bin.as_os_str());
            }
        }
    }

    mod calculate_number_of_steps {
        use super::*;

        #[test]
        fn returns_1_when_local_bin_mode_is_true_and_commit_is_false() {
            let steps = SnapshotConverterCommand::calculate_number_of_steps(true, false);
            assert_eq!(steps, 1);
        }

        #[test]
        fn returns_2_when_local_bin_mode_is_true_and_commit_is_true() {
            let steps = SnapshotConverterCommand::calculate_number_of_steps(true, true);
            assert_eq!(steps, 2);
        }

        #[test]
        fn returns_4_when_local_bin_mode_is_false_and_commit_is_true() {
            let steps = SnapshotConverterCommand::calculate_number_of_steps(false, true);
            assert_eq!(steps, 4);
        }

        #[test]
        fn returns_3_when_local_bin_mode_is_false_and_commit_is_false() {
            let steps = SnapshotConverterCommand::calculate_number_of_steps(false, false);
            assert_eq!(steps, 3);
        }
    }

    mod command_arguments_validation {
        use clap::Parser;

        use crate::commands::tools::SnapshotConverterCommand;

        #[test]
        fn should_fail_if_binary_path_is_provided_without_config_path() {
            let result = SnapshotConverterCommand::try_parse_from([
                "snapshot-converter",
                "--db-directory",
                "/path/to/db",
                "--cardano-node-version",
                "10.7.0",
                "--utxo-hd-flavor",
                "LMDB",
                "--binary-path",
                "/path/to/binary",
            ]);

            assert!(result.is_err());
            let error_message = result.unwrap_err().to_string();
            assert!(error_message.contains(
                "the following required arguments were not provided:\n  --config-path <CONFIG_PATH>"
            ));
        }

        #[test]
        fn should_fail_if_config_path_is_provided_without_binary_path() {
            let result = SnapshotConverterCommand::try_parse_from([
                "snapshot-converter",
                "--db-directory",
                "/path/to/db",
                "--cardano-node-version",
                "10.7.0",
                "--utxo-hd-flavor",
                "LMDB",
                "--config-path",
                "/path/to/config",
            ]);

            assert!(result.is_err());
            let error_message = result.unwrap_err().to_string();
            assert!(error_message.contains(
                "the following required arguments were not provided:\n  --binary-path <BINARY_PATH>"
            ));
        }

        #[test]
        fn should_succeed_if_both_config_and_binary_paths_are_provided() {
            let result = SnapshotConverterCommand::try_parse_from([
                "snapshot-converter",
                "--db-directory",
                "/path/to/db",
                "--cardano-node-version",
                "10.7.0",
                "--utxo-hd-flavor",
                "LMDB",
                "--binary-path",
                "/path/to/binary",
                "--config-path",
                "/path/to/config",
            ]);

            assert!(result.is_ok());
        }

        #[test]
        fn should_succeed_if_none_of_config_and_binary_paths_are_provided() {
            let result = SnapshotConverterCommand::try_parse_from([
                "snapshot-converter",
                "--db-directory",
                "/path/to/db",
                "--cardano-node-version",
                "10.7.0",
                "--utxo-hd-flavor",
                "LMDB",
            ]);

            assert!(result.is_ok());
        }
    }
}
