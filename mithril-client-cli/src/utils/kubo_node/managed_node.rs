use std::ffi::OsString;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use reqwest::{Client, Url};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::time::Instant;

use mithril_client::MithrilResult;

use crate::utils::{ReqwestGitHubApiClient, ReqwestHttpDownloader};

use super::{KuboBinaryProvider, KuboDistribution, KuboNodeConfig};

/// Maximum duration to wait for the RPC API of the daemon to answer after its start
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

/// Interval between two checks of the RPC API of the daemon during its start
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Maximum duration of a call to the RPC API of the daemon
const RPC_CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum duration to wait for the daemon to exit after a shutdown request, before killing it
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum duration to wait for the daemon to exit after being killed, before removing its
/// repository (on Windows, the files of a process can not be removed until it has exited)
const KILL_TIMEOUT: Duration = Duration::from_secs(5);

/// File of the repository where Kubo writes the multiaddr of its RPC API once listening
const API_FILE: &str = "api";

/// File of the repository where the output of the daemon is written
const DAEMON_LOG_FILE: &str = "daemon.log";

/// Prefixes of the environment variables read by Kubo, that are not inherited from the
/// environment of the client so that they can not alter the managed node (e.g. `GOLOG_LOG_LEVEL`
/// filling the disk with debug logs, or `LIBP2P_FORCE_PNET` preventing the daemon to start)
const KUBO_ENV_VAR_PREFIXES: [&str; 3] = ["IPFS_", "GOLOG_", "LIBP2P_"];

/// A Kubo node run by the client for the duration of a download, with its repository in a
/// dedicated directory.
///
/// The repository is removed once the node is stopped, or dropped (in which case the daemon is
/// killed).
pub struct ManagedKuboNode {
    // Dropped before the repository directory, as fields are dropped in declaration order
    daemon: KuboProcess,
    rpc_url: Url,
    http_client: Client,
    repository_dir: RepositoryDir,
}

impl ManagedKuboNode {
    /// Default parent directory of the repositories of the managed nodes, in the system temporary
    /// directory
    pub fn default_parent_dir() -> PathBuf {
        std::env::temp_dir().join("mithril-client")
    }

    /// Get the Kubo binary of the current platform, downloaded on first use and cached in the user
    /// cache directory, then [start][Self::start] a node with its repository in `parent_dir`,
    /// created if missing.
    pub async fn download_and_start(
        parent_dir: &Path,
        github_token: Option<String>,
    ) -> MithrilResult<Self> {
        let binary = KuboBinaryProvider::new(
            KuboBinaryProvider::default_install_dir()?,
            KuboDistribution::for_platform(std::env::consts::OS, std::env::consts::ARCH)?,
            Arc::new(ReqwestGitHubApiClient::new(github_token)?),
            Arc::new(ReqwestHttpDownloader::new()?),
        )
        .provide()
        .await
        .with_context(|| "Failed to get the Kubo binary")?;
        fs::create_dir_all(parent_dir).with_context(|| {
            format!(
                "Failed to create the Kubo repositories directory '{}'",
                parent_dir.display()
            )
        })?;

        Self::start(&binary, parent_dir).await
    }

    /// Initialize a Kubo repository in a new directory of `parent_dir`, configure it (see
    /// [KuboNodeConfig]) and start its daemon, waiting until its RPC API answers.
    ///
    /// On failure, or if cancelled, the started processes are killed and the repository is
    /// removed.
    pub async fn start(binary: &Path, parent_dir: &Path) -> MithrilResult<Self> {
        let repository_dir = RepositoryDir::create(parent_dir)?;
        run_ipfs(binary, repository_dir.path(), &KuboNodeConfig::init_args()).await?;
        for setting in KuboNodeConfig::settings() {
            run_ipfs(binary, repository_dir.path(), &setting.config_args()).await?;
        }

        let daemon_log_path = repository_dir.path().join(DAEMON_LOG_FILE);
        let daemon_log = File::create(&daemon_log_path)
            .with_context(|| format!("Failed to create '{}'", daemon_log_path.display()))?;
        let mut daemon = KuboProcess::spawn(
            ipfs_command(binary, repository_dir.path())
                .args(KuboNodeConfig::daemon_args())
                .stdout(daemon_log.try_clone()?)
                .stderr(daemon_log),
        )
        .with_context(|| format!("Failed to start the Kubo daemon '{}'", binary.display()))?;

        let http_client = Client::builder()
            // The RPC API is on the loopback interface, a system proxy must not be used
            .no_proxy()
            .timeout(RPC_CALL_TIMEOUT)
            .build()
            .with_context(|| "Failed to build the Kubo RPC HTTP client")?;
        match wait_until_ready(&mut daemon.0, &http_client, repository_dir.path()).await {
            Ok(rpc_url) => Ok(Self {
                daemon,
                rpc_url,
                http_client,
                repository_dir,
            }),
            Err(error) => {
                // Killed before reading its output so that it is complete
                drop(daemon);
                Err(error).with_context(|| {
                    format!(
                        "Kubo daemon failed to start, its output:\n{}",
                        fs::read_to_string(&daemon_log_path).unwrap_or_default()
                    )
                })
            }
        }
    }

    /// URL of the RPC API of the node
    pub fn rpc_url(&self) -> &Url {
        &self.rpc_url
    }

    /// Stop the daemon of the node, then remove its repository.
    ///
    /// The daemon is asked to shut down through its RPC API, and killed if it does not exit in time.
    pub async fn stop(mut self) -> MithrilResult<()> {
        // The daemon may close the connection before answering, the result is checked through its exit
        let _ = call_rpc(&self.http_client, &self.rpc_url, "shutdown").await;
        if tokio::time::timeout(SHUTDOWN_TIMEOUT, self.daemon.0.wait())
            .await
            .is_err()
        {
            self.daemon
                .0
                .kill()
                .await
                .with_context(|| "Failed to kill the Kubo daemon")?;
        }

        self.repository_dir.remove()
    }
}

/// Directory of a Kubo repository, removed when dropped
#[derive(Debug)]
struct RepositoryDir(PathBuf);

impl RepositoryDir {
    /// Create a new directory for a Kubo repository in `parent_dir`.
    ///
    /// Its name is made unique by the process id (concurrent clients) and the time (a reused
    /// process id). Creating it fails if it already exists, so that a repository is never shared.
    fn create(parent_dir: &Path) -> MithrilResult<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = parent_dir.join(format!("kubo-{}-{timestamp}", std::process::id()));
        fs::create_dir(&path).with_context(|| {
            format!(
                "Failed to create the Kubo repository directory '{}'",
                path.display()
            )
        })?;

        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn remove(&self) -> MithrilResult<()> {
        fs::remove_dir_all(&self.0).with_context(|| {
            format!(
                "Failed to remove the Kubo repository directory '{}'",
                self.0.display()
            )
        })
    }
}

impl Drop for RepositoryDir {
    fn drop(&mut self) {
        // Already removed if the node was stopped
        let _ = self.remove();
    }
}

/// A Kubo process, killed when dropped
struct KuboProcess(Child);

impl KuboProcess {
    fn spawn(command: &mut Command) -> std::io::Result<Self> {
        command.spawn().map(Self)
    }
}

impl Drop for KuboProcess {
    /// Kill the process, and wait (blocking, bounded by [KILL_TIMEOUT]) for its exit, so that
    /// its files can be removed (on Windows, the files of a process can not be removed until it has
    /// exited)
    fn drop(&mut self) {
        let _ = self.0.start_kill();
        let deadline = std::time::Instant::now() + KILL_TIMEOUT;
        while matches!(self.0.try_wait(), Ok(None)) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Environment variables of the client that must not be inherited by the Kubo commands
fn kubo_env_vars_to_remove(env_vars: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    env_vars
        .into_iter()
        .filter(|env_var| {
            env_var.to_str().is_some_and(|env_var| {
                KUBO_ENV_VAR_PREFIXES.iter().any(|prefix| env_var.starts_with(prefix))
            })
        })
        .collect()
}

/// An `ipfs` command on the repository, isolated from the Kubo environment variables of the
/// client
fn ipfs_command(binary: &Path, repository_dir: &Path) -> Command {
    let mut command = Command::new(binary);
    for env_var in kubo_env_vars_to_remove(std::env::vars_os().map(|(key, _)| key)) {
        command.env_remove(env_var);
    }
    command.env("IPFS_PATH", repository_dir).stdin(Stdio::null());

    command
}

/// Run an `ipfs` command on the repository, failing if it does not succeed
async fn run_ipfs<S: AsRef<str>>(
    binary: &Path,
    repository_dir: &Path,
    args: &[S],
) -> MithrilResult<()> {
    let command_line = format!(
        "{} {}",
        binary.display(),
        args.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(" ")
    );
    let mut process = KuboProcess::spawn(
        ipfs_command(binary, repository_dir)
            .args(args.iter().map(AsRef::as_ref))
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    )
    .with_context(|| format!("Failed to run '{command_line}'"))?;
    let mut stderr_pipe = process.0.stderr.take().with_context(|| "stderr is piped")?;
    let mut stderr = String::new();
    let (status, _) = tokio::join!(process.0.wait(), stderr_pipe.read_to_string(&mut stderr));
    let status = status.with_context(|| format!("Failed to run '{command_line}'"))?;

    if !status.success() {
        bail!(
            "Command '{command_line}' failed with {status}: {}",
            stderr.trim()
        );
    }

    Ok(())
}

/// Wait until the daemon has written its RPC address in the `api` file and its RPC API answers
async fn wait_until_ready(
    daemon: &mut Child,
    http_client: &Client,
    repository_dir: &Path,
) -> MithrilResult<Url> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(status) = daemon.try_wait()? {
            bail!("Kubo daemon exited during its start with {status}");
        }

        let last_error = match probe_rpc(http_client, repository_dir).await {
            Ok(rpc_url) => return Ok(rpc_url),
            Err(error) => error,
        };

        if Instant::now() >= deadline {
            return Err(last_error).with_context(|| {
                format!("Kubo daemon RPC API did not answer within {STARTUP_TIMEOUT:?}")
            });
        }
        tokio::time::sleep(STARTUP_POLL_INTERVAL).await;
    }
}

/// Read the RPC address of the daemon from its `api` file, and check that its RPC API answers
async fn probe_rpc(http_client: &Client, repository_dir: &Path) -> MithrilResult<Url> {
    let api_file = repository_dir.join(API_FILE);
    let api_address = fs::read_to_string(&api_file)
        .with_context(|| format!("Failed to read the Kubo API file '{}'", api_file.display()))?;
    let rpc_url = rpc_url_from_api_address(&api_address)?;
    call_rpc(http_client, &rpc_url, "version").await?;

    Ok(rpc_url)
}

/// Call a command of the Kubo RPC API, failing on an error response status
async fn call_rpc(http_client: &Client, rpc_url: &Url, command: &str) -> MithrilResult<()> {
    http_client
        .post(rpc_url.join(&format!("api/v0/{command}"))?)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

/// Build the RPC URL from the multiaddr written by Kubo in the `api` file of its repository,
/// e.g. `/ip4/127.0.0.1/tcp/5001`
fn rpc_url_from_api_address(api_address: &str) -> MithrilResult<Url> {
    match api_address.trim().split('/').collect::<Vec<_>>().as_slice() {
        ["", "ip4", host, "tcp", port] => Ok(Url::parse(&format!("http://{host}:{port}"))?),
        _ => Err(anyhow!(
            "Unsupported Kubo RPC API address '{api_address}', expected '/ip4/<host>/tcp/<port>'"
        )),
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::temp_dir_create;

    use super::*;

    fn dir_entries_count(dir: &Path) -> usize {
        fs::read_dir(dir).unwrap().count()
    }

    mod rpc_url_from_api_address {
        use super::*;

        #[test]
        fn is_built_from_the_ip4_tcp_address_of_the_api_file() {
            let rpc_url = rpc_url_from_api_address("/ip4/127.0.0.1/tcp/36803\n").unwrap();

            assert_eq!("http://127.0.0.1:36803/", rpc_url.as_str());
        }

        #[test]
        fn fails_on_an_address_that_is_not_ip4_tcp() {
            for api_address in ["/ip6/::1/tcp/5001", "/ip4/127.0.0.1/udp/5001", "", "garbage"] {
                rpc_url_from_api_address(api_address)
                    .expect_err(&format!("Should fail for api address '{api_address}'"));
            }
        }
    }

    mod repository_dir {
        use super::*;

        #[test]
        fn creates_a_directory_named_after_the_process_id_in_the_parent_directory() {
            let parent_dir = temp_dir_create!();

            let repository_dir = RepositoryDir::create(&parent_dir).unwrap();

            assert!(repository_dir.path().is_dir());
            assert_eq!(Some(parent_dir.as_path()), repository_dir.path().parent());
            let dir_name = repository_dir.path().file_name().unwrap().to_string_lossy();
            assert!(
                dir_name.starts_with(&format!("kubo-{}-", std::process::id())),
                "Unexpected repository directory name: {dir_name}"
            );
        }

        #[test]
        fn fails_when_the_parent_directory_does_not_exist() {
            let parent_dir = temp_dir_create!().join("missing");

            RepositoryDir::create(&parent_dir)
                .expect_err("Should fail when the parent directory does not exist");
        }

        #[test]
        fn is_removed_when_dropped() {
            let parent_dir = temp_dir_create!();

            let repository_dir = RepositoryDir::create(&parent_dir).unwrap();
            drop(repository_dir);

            assert_eq!(0, dir_entries_count(&parent_dir));
        }
    }

    mod kubo_env_vars_to_remove {
        use super::*;

        #[test]
        fn removes_the_variables_read_by_kubo_and_keeps_the_others() {
            let env_vars = [
                "IPFS_PATH",
                "IPFS_TELEMETRY",
                "GOLOG_LOG_LEVEL",
                "LIBP2P_FORCE_PNET",
                "PATH",
                "HOME",
                "HTTP_PROXY",
                "MY_IPFS_VAR",
            ]
            .map(OsString::from);

            assert_eq!(
                vec!["IPFS_PATH", "IPFS_TELEMETRY", "GOLOG_LOG_LEVEL", "LIBP2P_FORCE_PNET"],
                kubo_env_vars_to_remove(env_vars)
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn start_fails_and_removes_its_repository_when_a_setup_command_fails() {
        let parent_dir = temp_dir_create!();

        let error = ManagedKuboNode::start(Path::new("false"), &parent_dir)
            .await
            .err()
            .expect("Start should fail when a setup command fails");

        assert!(
            format!("{error:?}").contains("init --profile server"),
            "Error should name the failing command: {error:?}"
        );
        assert_eq!(0, dir_entries_count(&parent_dir));
    }

    /// Start cancelled while a fake `ipfs` binary hangs on a command (as when the client is
    /// interrupted by a shutdown signal)
    #[cfg(unix)]
    mod start_cancelled {
        use std::os::unix::fs::PermissionsExt;

        use super::*;

        /// Fake `ipfs` binary succeeding on all commands but `hanging_command`, on which it writes
        /// its pid to `pid_file` then hangs
        fn fake_ipfs_hanging_on(script_dir: &Path, hanging_command: &str) -> (PathBuf, PathBuf) {
            let binary = script_dir.join("ipfs");
            let pid_file = script_dir.join("pid");
            fs::write(
                &binary,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = \"{hanging_command}\" ]; then echo $$ > \"{}\"; exec sleep 30; fi\n",
                    pid_file.display()
                ),
            )
            .unwrap();
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();

            (binary, pid_file)
        }

        fn is_process_alive(pid: &str) -> bool {
            std::process::Command::new("kill")
                .args(["-0", pid])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        }

        /// Start a node in `test_dir/parent` with the fake binary, cancelling the start once the
        /// hanging command runs, returns the parent directory and the pid of the hanging command
        async fn start_then_cancel_while_hanging_on(
            hanging_command: &str,
            test_dir: &Path,
        ) -> (PathBuf, String) {
            let parent_dir = test_dir.join("parent");
            fs::create_dir(&parent_dir).unwrap();
            let (binary, pid_file) = fake_ipfs_hanging_on(test_dir, hanging_command);

            let wait_for_pid = async {
                loop {
                    if let Ok(pid) = fs::read_to_string(&pid_file)
                        && !pid.trim().is_empty()
                    {
                        return pid.trim().to_string();
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            tokio::select! {
                result = ManagedKuboNode::start(&binary, &parent_dir) => {
                    panic!("Start should hang on '{hanging_command}', got: {:?}", result.err())
                }
                pid = tokio::time::timeout(Duration::from_secs(10), wait_for_pid) => {
                    (parent_dir, pid.expect("The hanging command should have been run"))
                }
            }
        }

        #[tokio::test]
        async fn removes_its_repository_and_kills_a_running_setup_command() {
            let (parent_dir, pid) =
                start_then_cancel_while_hanging_on("init", &temp_dir_create!()).await;

            assert!(
                !is_process_alive(&pid),
                "The setup command should be killed"
            );
            assert_eq!(0, dir_entries_count(&parent_dir));
        }

        #[tokio::test]
        async fn removes_its_repository_and_kills_the_daemon() {
            let (parent_dir, pid) =
                start_then_cancel_while_hanging_on("daemon", &temp_dir_create!()).await;

            assert!(!is_process_alive(&pid), "The daemon should be killed");
            assert_eq!(0, dir_entries_count(&parent_dir));
        }
    }

    #[test]
    fn default_parent_dir_is_a_subdirectory_of_the_system_temp_dir() {
        assert_eq!(
            std::env::temp_dir().join("mithril-client"),
            ManagedKuboNode::default_parent_dir()
        );
    }

    /// Tests against the real Kubo binary, downloaded in the user cache directory.
    ///
    /// Run them with `cargo test -p mithril-client-cli managed_node -- --ignored`.
    mod with_the_real_kubo_binary {
        use super::*;

        async fn rpc_version_is_reachable(rpc_url: &Url) -> bool {
            Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .post(rpc_url.join("api/v0/version").unwrap())
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
        }

        #[tokio::test]
        #[ignore = "downloads and runs the real Kubo binary"]
        async fn starts_a_reachable_node_then_shuts_it_down_and_removes_its_repository() {
            let parent_dir = temp_dir_create!().join("missing_parent_dir");

            let node = ManagedKuboNode::download_and_start(&parent_dir, None).await.unwrap();
            let rpc_url = node.rpc_url().clone();

            assert!(rpc_version_is_reachable(&rpc_url).await);
            assert_eq!(1, dir_entries_count(&parent_dir));

            let stop_start = Instant::now();
            node.stop().await.unwrap();

            assert!(
                stop_start.elapsed() < SHUTDOWN_TIMEOUT,
                "The daemon should shut down on request instead of being killed after the timeout"
            );
            assert!(!rpc_version_is_reachable(&rpc_url).await);
            assert_eq!(0, dir_entries_count(&parent_dir));
        }

        #[tokio::test]
        #[ignore = "downloads and runs the real Kubo binary"]
        async fn kills_the_daemon_and_removes_its_repository_when_dropped_without_being_stopped() {
            let parent_dir = temp_dir_create!();

            let node = ManagedKuboNode::download_and_start(&parent_dir, None).await.unwrap();
            let rpc_url = node.rpc_url().clone();
            drop(node);

            assert!(!rpc_version_is_reachable(&rpc_url).await);
            assert_eq!(0, dir_entries_count(&parent_dir));
        }
    }
}
