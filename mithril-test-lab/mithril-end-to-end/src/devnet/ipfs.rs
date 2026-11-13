use std::ops::{Deref, DerefMut};
use std::path::{Display, Path, PathBuf};
use std::process::{ExitStatus, Stdio};

use anyhow::{Context, anyhow};
use reqwest::Url;
use slog_scope::{info, warn};
use tokio::process::Command;

use mithril_common::StdResult;

use crate::RetryableDevnetError;
use crate::utils::{ChildLoggerExt, file_utils};

const IPFS_DEVNET_SCRIPT_NAME: &str = "ipfs-devnet.sh";

#[derive(Debug, Copy, Clone, Default)]
pub enum IpfsDevnetMode {
    /// Spawn an IPFS devnet (default, only alive during the tests).
    #[default]
    Spawn,
    /// Attach to an existing IPFS devnet.
    Detached,
}

#[derive(Debug, Clone)]
pub struct IpfsDevnet {
    topology: Vec<KuboNode>,
    mode: IpfsDevnetMode,
    command_builder: IpfsCommandBuilder,
}

#[derive(Debug, Clone)]
pub struct KuboNode {
    pub rpc_url: Url,
    pub working_dir: PathBuf,
    pub rpc_basic_auth: Option<KuboRpcBasicAuth>,
    swarm_index: u8,
    command_builder: IpfsCommandBuilder,
}

#[derive(Debug, Clone)]
pub struct IpfsDevnetBootstrapArgs {
    pub devnet_scripts_dir: PathBuf,
    pub number_of_nodes: u8,
    pub swarm_target_dir: PathBuf,
    pub kubo_version: Option<semver::Version>,
    pub mode: IpfsDevnetMode,
    pub rpc_authenticated_nodes: u8,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IpnsKey {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone)]
struct IpfsCommandBuilder {
    devnet_script_path: PathBuf,
    swarm_dir: PathBuf,
}

impl IpfsCommandBuilder {
    fn new(devnet_script_path: &Path, swarm_dir: &Path) -> Self {
        Self {
            devnet_script_path: devnet_script_path.to_owned(),
            swarm_dir: swarm_dir.to_owned(),
        }
    }

    fn display_script_path(&self) -> Display<'_> {
        self.devnet_script_path.display()
    }

    fn build(&self, sub_command: &str, additional_args: &[&str]) -> IpfsCommand {
        let mut context = format!("{IPFS_DEVNET_SCRIPT_NAME} {sub_command}");

        if !additional_args.is_empty() {
            context.push(' ');
            context.push_str(&additional_args.join(" "));
        }

        let mut command = Command::new(self.devnet_script_path.clone());
        command
            .arg(sub_command)
            .args(additional_args)
            .env("SWARM_DIR", self.swarm_dir.as_os_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        IpfsCommand { command, context }
    }

    fn build_query_command(&self, node_swarm_index: u8, query_args: &[&str]) -> IpfsCommand {
        let node_swarm_index_str = node_swarm_index.to_string();
        // First `--` forwards arguments to the generated `$SWARM_DIR/query.sh` command
        // Second `--` ends `query.sh` options, ensuring that all remaining arguments are forwarded to the executed `ipfs` command.
        let additional_args =
            [vec!["--", "-n", &node_swarm_index_str, "--"], query_args.to_vec()].concat();

        self.build("query", &additional_args)
    }
}

struct IpfsCommand {
    command: Command,
    context: String,
}

impl IpfsCommand {
    /// Execute the IPFS command and return the exit status.
    ///
    /// Stdout and stderr are forwarded to the slog scope logger.
    async fn execute(mut self) -> StdResult<ExitStatus> {
        let exit_status = self
            .command
            .spawn()
            .with_context(|| format!("Failed to spawn '{}'", self.context))?
            .wait_forwarding_output_to_slog_scope(&self.context)
            .await
            .with_context(|| format!("Execution of '{}' failed", self.context))?;

        Ok(exit_status)
    }

    /// Execute the IPFS command and return the output.
    ///
    /// If the command fails, an error is returned.
    async fn execute_with_output(mut self) -> StdResult<std::process::Output> {
        let output = self
            .command
            .output()
            .await
            .with_context(|| format!("Failed to spawn '{}'", self.context))?;

        if output.status.success() {
            Ok(output)
        } else {
            Err(anyhow!(
                "Execution of '{}' failed with status {}: {}",
                self.context,
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }
}

impl Deref for IpfsCommand {
    type Target = Command;

    fn deref(&self) -> &Self::Target {
        &self.command
    }
}

impl DerefMut for IpfsCommand {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.command
    }
}

impl IpfsDevnet {
    fn build_topology(
        number_of_nodes: u8,
        swarm_dir: &Path,
        command_builder: &IpfsCommandBuilder,
    ) -> StdResult<Vec<KuboNode>> {
        (1..=number_of_nodes)
            .map(|n| {
                let working_dir = swarm_dir.join(format!("kubo-node-{n}"));
                Ok(KuboNode {
                    rpc_url: Url::parse(&format!("http://127.0.0.1:{}", 5000_u16 + n as u16))
                        .unwrap(),
                    rpc_basic_auth: KuboRpcBasicAuth::read_from_node_dir(&working_dir)?,
                    working_dir,
                    swarm_index: n,
                    command_builder: command_builder.clone(),
                })
            })
            .collect()
    }

    pub async fn bootstrap(bootstrap_args: &IpfsDevnetBootstrapArgs) -> StdResult<IpfsDevnet> {
        match bootstrap_args.mode {
            IpfsDevnetMode::Spawn => Self::bootstrap_new_network(bootstrap_args).await,
            IpfsDevnetMode::Detached => Self::bootstrap_attached(bootstrap_args),
        }
    }

    fn bootstrap_attached(bootstrap_args: &IpfsDevnetBootstrapArgs) -> StdResult<IpfsDevnet> {
        let devnet_script_path = file_utils::get_process_path(
            IPFS_DEVNET_SCRIPT_NAME,
            &bootstrap_args.devnet_scripts_dir,
        )?;
        let swarm_dir = bootstrap_args.swarm_target_dir.to_owned();
        let swarm_dir_entries: Vec<_> = swarm_dir
            .read_dir()
            .with_context(|| format!("Failed to read swarm directory: '{}'", swarm_dir.display()))?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .collect();

        for i in 1..=bootstrap_args.number_of_nodes {
            let expected_node = format!("kubo-node-{i}");
            if !swarm_dir_entries
                .iter()
                .any(|e| e.file_name().to_string_lossy() == expected_node)
            {
                anyhow::bail!(
                    "Expected node '{}' missing in attached swarm directory ('{}'), please re-initialize the devnet with at least {} nodes",
                    expected_node,
                    swarm_dir.display(),
                    bootstrap_args.number_of_nodes
                );
            }
        }

        let command_builder = IpfsCommandBuilder::new(&devnet_script_path, &swarm_dir);
        Ok(IpfsDevnet {
            topology: Self::build_topology(
                bootstrap_args.number_of_nodes,
                &bootstrap_args.swarm_target_dir,
                &command_builder,
            )?,
            mode: bootstrap_args.mode,
            command_builder,
        })
    }

    async fn bootstrap_new_network(
        bootstrap_args: &IpfsDevnetBootstrapArgs,
    ) -> StdResult<IpfsDevnet> {
        let devnet_script_path = file_utils::get_process_path(
            IPFS_DEVNET_SCRIPT_NAME,
            &bootstrap_args.devnet_scripts_dir,
        )?;
        let command_builder =
            IpfsCommandBuilder::new(&devnet_script_path, &bootstrap_args.swarm_target_dir);

        let mut bootstrap_command = command_builder.build(
            "init",
            &[
                "--overwrite",
                "--number",
                &bootstrap_args.number_of_nodes.to_string(),
                "--rpc-auth-nodes",
                &bootstrap_args.rpc_authenticated_nodes.to_string(),
            ],
        );

        if let Some(kubo_version) = &bootstrap_args.kubo_version {
            bootstrap_command.env("KUBO_VERSION", kubo_version.to_string());
        }

        bootstrap_command.current_dir(&bootstrap_args.devnet_scripts_dir);

        info!("Bootstrapping the IPFS Devnet"; "script" => command_builder.display_script_path(), "cmd" => "init");

        match bootstrap_command.execute().await?.code() {
            Some(0) => Ok(IpfsDevnet {
                topology: Self::build_topology(
                    bootstrap_args.number_of_nodes,
                    &bootstrap_args.swarm_target_dir,
                    &command_builder,
                )?,
                mode: bootstrap_args.mode,
                command_builder,
            }),
            Some(code) => Err(anyhow!(RetryableDevnetError(format!(
                "IPFS Bootstrap devnet exited with status code: {code}"
            )))),
            None => Err(anyhow!("IPFS Bootstrap devnet terminated by signal")),
        }
    }

    pub fn topology(&self) -> &[KuboNode] {
        &self.topology
    }

    pub async fn start(&self) -> StdResult<()> {
        // Note: running the start command on an already running devnet does nothing, so running it
        // against a "Detached" devnet poses no risk (if stopped, it will start, if running, it will do nothing).
        let run_command = self.command_builder.build("start", &[]);

        info!("Starting the IPFS devnet"; "script" => &self.command_builder.display_script_path(), "cmd" => "start");

        match run_command.execute().await?.code() {
            Some(0) => Ok(()),
            Some(code) => Err(anyhow!(RetryableDevnetError(format!(
                "Run IPFS devnet exited with status code: {code}"
            )))),
            None => Err(anyhow!("Run IPFS devnet terminated by signal")),
        }
    }

    pub async fn stop(&self) -> StdResult<()> {
        if matches!(self.mode, IpfsDevnetMode::Detached) {
            info!("IPFS devnet is in detached mode, leaving it running");
            return Ok(());
        }

        let run_command = self.command_builder.build("stop", &[]);

        info!("Stopping the IPFS devnet"; "script" => &self.command_builder.display_script_path(), "cmd" => "stop");

        match run_command.execute().await?.code() {
            Some(0) => Ok(()),
            Some(code) => Err(anyhow!("Stop IPFS devnet exited with status code: {code}")),
            None => Err(anyhow!("Stop IPFS devnet terminated by signal")),
        }
    }
}

impl KuboNode {
    /// List IPNS keys of the Kubo node keystore
    pub async fn list_ipns_keys(&self) -> StdResult<Vec<IpnsKey>> {
        // Output lines example:
        // k51qzi5uqu5dhmp0n2e4olicqyqure0kk8qq87y8s2o8qyyeah2hugrmo9boq7 self
        // k51qzi5uqu5dldmb73ienkcee5fm46ldactwcuu0wzqizcwgas9en94spxr16j mithril-snapshot
        let output = self
            .command_builder
            .build_query_command(self.swarm_index, &["key", "list", "-l"])
            .execute_with_output()
            .await?;

        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.trim().split_once(char::is_whitespace))
            .map(|(id, name)| IpnsKey {
                id: id.to_string(),
                name: name.to_string(),
            })
            .collect())
    }

    /// Get the id of the IPNS key with the given name
    ///
    /// Note: The key name is local to the IPFS node and can't be used to resolve IPNS names, only the key id can.
    pub async fn get_ipns_key_id(&self, key_name: &str) -> StdResult<Option<String>> {
        let keys = self.list_ipns_keys().await?;
        Ok(keys.into_iter().find(|key| key.name == key_name).map(|key| key.id))
    }

    pub async fn create_ipns_keypair(&self, key_name: &str) -> StdResult<()> {
        if self.get_ipns_key_id(key_name).await?.is_some() {
            warn!("Create IPNS keypair - key with name '{key_name}' already exists, reusing it");
            return Ok(());
        }

        let query_command = self.command_builder.build_query_command(
            self.swarm_index,
            &["key", "gen", "--type=ed25519", key_name],
        );

        info!("Creating IPNS keypair"; "script" => &self.command_builder.display_script_path(), "cmd" => "query -- key gen");

        match query_command.execute().await?.code() {
            Some(0) => Ok(()),
            Some(code) => Err(anyhow!(RetryableDevnetError(format!(
                "Create IPNS keypair exited with status code: {code}"
            )))),
            None => Err(anyhow!("Create IPNS keypair terminated by signal")),
        }
    }

    /// Resolve an **IPNS** name to an IPFS path.
    pub async fn ipns_name_resolve(&self, ipns_name: &str) -> StdResult<String> {
        // Example output:
        // /ipfs/QmfYpbWwaAmrTfapNZHYDkutDxckvqA5hzjrbfYDwymaKw
        let output = self
            .command_builder
            .build_query_command(
                self.swarm_index,
                &["name", "resolve", "--nocache", ipns_name],
            )
            .execute_with_output()
            .await?;

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Resolve an **IPFS** path (useful to retrieve the CID of a file if you only know the path and its folder CID).
    pub async fn ipfs_resolve(&self, ipfs_path: &str) -> StdResult<String> {
        // Example output:
        // /ipfs/bafkreibeffv3u3yqulwvgxqjcfsigocas35t5rjykzk5nmyev2x2fzwe3y
        let output = self
            .command_builder
            .build_query_command(self.swarm_index, &["resolve", ipfs_path])
            .execute_with_output()
            .await?;

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Resolve the given IPNS name and check that the resolved directory contains the given file,
    /// returning the resolved directory path.
    pub async fn resolve_file_in_ipns_dir(
        &self,
        ipns_name: &str,
        ipfs_file_name: &str,
    ) -> StdResult<String> {
        // Note: we could use `ipfs resolve` directly with the ipns key id, but this would make the
        // query prone to cache issues since this request does not allow ignoring the cache (contrary
        // to `ipfs name resolve` which has a `--nocache` option).
        let ipfs_dir_path = self.ipns_name_resolve(ipns_name).await?;
        self.ipfs_resolve(&format!("{ipfs_dir_path}/{ipfs_file_name}"))
            .await?;

        Ok(ipfs_dir_path)
    }
}

#[derive(Debug, Clone)]
pub struct KuboRpcBasicAuth {
    pub username: String,
    pub password: String,
}

impl KuboRpcBasicAuth {
    /// Read the `basic:<username>:<password>` secret written by the devnet in a node directory, if any
    fn read_from_node_dir(node_dir: &Path) -> StdResult<Option<Self>> {
        let secret_path = node_dir.join("rpc-auth-secret");
        if !secret_path.exists() {
            return Ok(None);
        }
        let secret = std::fs::read_to_string(&secret_path)
            .with_context(|| format!("Failed to read '{}'", secret_path.display()))?;
        let (username, password) = secret
            .trim()
            .strip_prefix("basic:")
            .and_then(|credentials| credentials.split_once(':'))
            .with_context(|| format!("Invalid RPC auth secret in '{}'", secret_path.display()))?;

        Ok(Some(Self {
            username: username.to_string(),
            password: password.to_string(),
        }))
    }
}
