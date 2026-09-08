use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, anyhow};
use reqwest::Url;
use slog_scope::info;
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

#[derive(Debug, Clone, Default)]
pub struct IpfsDevnet {
    devnet_script_path: PathBuf,
    swarm_dir: PathBuf,
    topology: Vec<KuboNode>,
    mode: IpfsDevnetMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KuboNode {
    pub rpc_url: Url,
    pub working_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct IpfsDevnetBootstrapArgs {
    pub devnet_scripts_dir: PathBuf,
    pub number_of_nodes: u8,
    pub swarm_target_dir: PathBuf,
    pub kubo_version: Option<semver::Version>,
    pub mode: IpfsDevnetMode,
}

impl IpfsDevnet {
    fn build_command<C: AsRef<OsStr>>(&self, sub_command: C) -> StdResult<Command> {
        let mut command = Command::new(self.devnet_script_path.clone());
        command
            .arg(sub_command)
            .env("SWARM_DIR", self.swarm_dir.as_os_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        Ok(command)
    }

    fn build_topology(number_of_nodes: u8, swarm_dir: &Path) -> Vec<KuboNode> {
        (1..=number_of_nodes)
            .map(|n| KuboNode {
                rpc_url: Url::parse(&format!("http://127.0.0.1:{}", 5000_u16 + n as u16)).unwrap(),
                working_dir: swarm_dir.join(format!("kubo-node-{n}")),
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

        Ok(IpfsDevnet {
            devnet_script_path,
            swarm_dir: bootstrap_args.swarm_target_dir.to_owned(),
            topology: Self::build_topology(
                bootstrap_args.number_of_nodes,
                &bootstrap_args.swarm_target_dir,
            ),
            mode: bootstrap_args.mode,
        })
    }

    async fn bootstrap_new_network(
        bootstrap_args: &IpfsDevnetBootstrapArgs,
    ) -> StdResult<IpfsDevnet> {
        let devnet_script_path = file_utils::get_process_path(
            IPFS_DEVNET_SCRIPT_NAME,
            &bootstrap_args.devnet_scripts_dir,
        )?;

        let mut bootstrap_command = Command::new(&devnet_script_path);
        bootstrap_command
            .arg("init")
            .arg("--overwrite")
            .arg("--number")
            .arg(bootstrap_args.number_of_nodes.to_string())
            .arg("--swarm-dir")
            .arg(bootstrap_args.swarm_target_dir.as_os_str());

        if let Some(kubo_version) = &bootstrap_args.kubo_version {
            bootstrap_command.env("KUBO_VERSION", kubo_version.to_string());
        }

        bootstrap_command
            .current_dir(&bootstrap_args.devnet_scripts_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        info!("Bootstrapping the IPFS Devnet"; "script" => &devnet_script_path.display(), "cmd" => "init");

        let exit_status = bootstrap_command
            .spawn()
            .with_context(|| format!("{IPFS_DEVNET_SCRIPT_NAME} failed to start"))?
            .wait_forwarding_output_to_slog_scope(IPFS_DEVNET_SCRIPT_NAME)
            .await
            .with_context(|| format!("{IPFS_DEVNET_SCRIPT_NAME} failed to run"))?;
        match exit_status.code() {
            Some(0) => Ok(IpfsDevnet {
                devnet_script_path,
                swarm_dir: bootstrap_args.swarm_target_dir.to_owned(),
                topology: Self::build_topology(
                    bootstrap_args.number_of_nodes,
                    &bootstrap_args.swarm_target_dir,
                ),
                mode: bootstrap_args.mode,
            }),
            Some(code) => Err(anyhow!(RetryableDevnetError(format!(
                "IPFS Bootstrap devnet exited with status code: {code}"
            )))),
            None => Err(anyhow!("IPFS Bootstrap devnet terminated by signal")),
        }
    }

    pub fn swarm_dir(&self) -> PathBuf {
        self.swarm_dir.clone()
    }

    pub fn topology(&self) -> &[KuboNode] {
        &self.topology
    }

    pub async fn start(&self) -> StdResult<()> {
        // Note: running the start command on an already running devnet does nothing, so running it
        // against a "Detached" devnet poses no risk (if stopped, it will start, if running, it will do nothing).
        let mut run_command = self.build_command("start")?;

        info!("Starting the IPFS devnet"; "script" => &self.devnet_script_path.display(), "cmd" => "start");

        let status = run_command
            .spawn()
            .with_context(|| "Failed to start the IPFS devnet")?
            .wait_forwarding_output_to_slog_scope(&format!("{IPFS_DEVNET_SCRIPT_NAME} start"))
            .await
            .with_context(|| "Error while starting the IPFS devnet")?;
        match status.code() {
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

        let mut run_command = self.build_command("stop")?;

        info!("Stopping the IPFS devnet"; "script" => &self.devnet_script_path.display(), "cmd" => "stop");

        let exit_status = run_command
            .spawn()
            .with_context(|| "Failed to stop the IPFS devnet")?
            .wait_forwarding_output_to_slog_scope(&format!("{IPFS_DEVNET_SCRIPT_NAME} stop"))
            .await
            .with_context(|| "Error while stopping the IPFS devnet")?;
        match exit_status.code() {
            Some(0) => Ok(()),
            Some(code) => Err(anyhow!("Stop IPFS devnet exited with status code: {code}")),
            None => Err(anyhow!("Stop IPFS devnet terminated by signal")),
        }
    }
}
