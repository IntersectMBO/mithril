use std::ffi::OsString;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use reqwest::{Client, Response, Url};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::time::Instant;

use mithril_client::MithrilResult;

use crate::utils::{ReqwestGitHubApiClient, ReqwestHttpDownloader};

use super::{KuboArchive, KuboArchiveProvider, KuboDistribution, KuboNodeConfig};

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

/// JSON configuration file of the repository
const CONFIG_FILE: &str = "config";

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
    rpc_api_secret: String,
    http_client: Client,
    repository_dir: RepositoryDir,
}

impl ManagedKuboNode {
    /// Default parent directory of the repositories of the managed nodes: the system temporary
    /// directory
    pub fn default_parent_dir() -> PathBuf {
        std::env::temp_dir()
    }

    /// Get the Kubo release archive of the current platform, downloaded on first use and cached in the user
    /// cache directory, then [start][Self::start] a node with its repository in `parent_dir`,
    /// which must exist.
    pub async fn download_and_start(
        parent_dir: &Path,
        github_token: Option<String>,
    ) -> MithrilResult<Self> {
        if !parent_dir.is_dir() {
            bail!(
                "The Kubo repositories directory '{}' does not exist",
                parent_dir.display()
            );
        }
        let archive = KuboArchiveProvider::new(
            KuboArchiveProvider::default_install_dir()?,
            KuboDistribution::for_platform(std::env::consts::OS, std::env::consts::ARCH)?,
            Arc::new(ReqwestGitHubApiClient::new(github_token)?),
            Arc::new(ReqwestHttpDownloader::new()?),
        )
        .provide()
        .await
        .with_context(|| "Failed to get the Kubo release archive")?;

        Self::start(&archive, parent_dir).await
    }

    /// Unpack the Kubo binary of the `archive` in a new directory of `parent_dir`, then initialize
    /// a Kubo repository in it with the unpacked binary, configure it (see [KuboNodeConfig]) and
    /// start its daemon, waiting until its RPC API answers.
    ///
    /// On failure, or if cancelled, the started processes are killed and the repository is
    /// removed.
    pub async fn start(archive: &KuboArchive, parent_dir: &Path) -> MithrilResult<Self> {
        let repository_dir = RepositoryDir::create(parent_dir)?;
        let binary = &archive.unpack_binary(repository_dir.path())?;
        run_ipfs(binary, repository_dir.path(), &KuboNodeConfig::init_args()).await?;
        let rpc_api_secret = generate_rpc_api_secret();
        KuboNodeConfig::apply_settings_to_file(
            &repository_dir.path().join(CONFIG_FILE),
            &rpc_api_secret,
        )?;

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
        match wait_until_ready(
            &mut daemon.0,
            &http_client,
            repository_dir.path(),
            &rpc_api_secret,
        )
        .await
        {
            Ok(rpc_url) => Ok(Self {
                daemon,
                rpc_url,
                rpc_api_secret,
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

    /// Bearer token required by the RPC API of the node
    pub fn rpc_auth_token(&self) -> &str {
        &self.rpc_api_secret
    }

    /// Stop the daemon of the node, then remove its repository.
    ///
    /// The daemon is asked to shut down through its RPC API, and killed if it does not exit in time.
    pub async fn stop(mut self) -> MithrilResult<()> {
        // The daemon may close the connection before answering, the result is checked through its exit
        let _ = call_rpc(
            &self.http_client,
            &self.rpc_url,
            &self.rpc_api_secret,
            "shutdown",
        )
        .await;
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
    /// process id). Creating it fails if it already exists, so that a repository is never shared,
    /// and on Unix it is only accessible to the current user, so that another user of a shared
    /// parent directory (e.g. `/tmp`) can not tamper with the Kubo binary run from it.
    fn create(parent_dir: &Path) -> MithrilResult<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = parent_dir.join(format!(
            "mithril-client-kubo-{}-{timestamp}",
            std::process::id()
        ));
        let mut dir_builder = fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut dir_builder, 0o700);
        dir_builder.create(&path).with_context(|| {
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
    /// Remove the directory, printing an error if it can not be removed, as it is then left behind
    fn drop(&mut self) {
        // Already removed if the node was stopped
        if self.0.exists()
            && let Err(error) = self.remove()
        {
            eprintln!("{error:?}");
        }
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
    ///
    /// An error is printed if the process has not exited in time, as it may then be left running.
    fn drop(&mut self) {
        let _ = self.0.start_kill();
        let deadline = std::time::Instant::now() + KILL_TIMEOUT;
        while matches!(self.0.try_wait(), Ok(None)) {
            if std::time::Instant::now() >= deadline {
                eprintln!(
                    "Kubo process '{}' did not exit within {KILL_TIMEOUT:?} after being killed",
                    self.0.id().map(|pid| format!(" {pid}")).unwrap_or_default()
                );
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Environment variables of the client that must not be inherited by the Kubo commands
fn kubo_env_vars_to_remove(env_vars: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    env_vars
        .into_iter()
        .filter(|env_var| {
            let name = env_var.to_string_lossy().to_ascii_uppercase();
            KUBO_ENV_VAR_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
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

/// Generate a random secret for the RPC API of a node: 32 bytes from a cryptographically secure
/// generator, hex encoded
fn generate_rpc_api_secret() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

/// Wait until the daemon has written its RPC address in the `api` file and its RPC API answers
async fn wait_until_ready(
    daemon: &mut Child,
    http_client: &Client,
    repository_dir: &Path,
    rpc_api_secret: &str,
) -> MithrilResult<Url> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(status) = daemon.try_wait()? {
            bail!("Kubo daemon exited during its start with {status}");
        }

        let last_error = match probe_rpc(http_client, repository_dir, rpc_api_secret).await {
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
async fn probe_rpc(
    http_client: &Client,
    repository_dir: &Path,
    rpc_api_secret: &str,
) -> MithrilResult<Url> {
    let api_file = repository_dir.join(API_FILE);
    let api_address = fs::read_to_string(&api_file)
        .with_context(|| format!("Failed to read the Kubo API file '{}'", api_file.display()))?;
    let rpc_url = rpc_url_from_api_address(&api_address)?;
    call_rpc(http_client, &rpc_url, rpc_api_secret, "version").await?;

    Ok(rpc_url)
}

/// Call a command of the Kubo RPC API, authenticated with the `rpc_api_secret` as a Bearer token,
/// failing on an error response status
async fn call_rpc(
    http_client: &Client,
    rpc_url: &Url,
    rpc_api_secret: &str,
    command: &str,
) -> MithrilResult<()> {
    http_client
        .post(rpc_url.join(&format!("api/v0/{command}"))?)
        .bearer_auth(rpc_api_secret)
        .send()
        .await
        .and_then(Response::error_for_status)
        .with_context(|| format!("Kubo RPC API call '{command}' failed"))?;

    Ok(())
}

/// Build the RPC URL from the multiaddr written by Kubo in the `api` file of its repository,
/// e.g. `/ip4/127.0.0.1/tcp/5001`
fn rpc_url_from_api_address(api_address: &str) -> MithrilResult<Url> {
    let rpc_url = match api_address.trim().split('/').collect::<Vec<_>>().as_slice() {
        ["", "ip4", host, "tcp", port] => Url::parse(&format!("http://{host}:{port}"))?,
        _ => bail!(
            "Unsupported Kubo RPC API address '{api_address}', expected '/ip4/<host>/tcp/<port>'"
        ),
    };
    Ok(rpc_url)
}

#[cfg(test)]
mod tests {
    use mithril_common::temp_dir_create;

    use super::*;

    fn dir_entries_count(dir: &Path) -> usize {
        fs::read_dir(dir).unwrap().count()
    }

    /// Kubo like tar.gz archive, in `dir`, holding an executable `kubo/ipfs` shell script with the
    /// given body
    #[cfg(unix)]
    fn fake_kubo_archive(dir: &Path, script_body: &str) -> KuboArchive {
        KuboArchive::fake(dir, format!("#!/bin/sh\n{script_body}\n").as_bytes())
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
                dir_name.starts_with(&format!("mithril-client-kubo-{}-", std::process::id())),
                "Unexpected repository directory name: {dir_name}"
            );
        }

        #[cfg(unix)]
        #[test]
        fn is_only_accessible_to_the_current_user() {
            use std::os::unix::fs::PermissionsExt;

            let repository_dir = RepositoryDir::create(&temp_dir_create!()).unwrap();

            let mode = fs::metadata(repository_dir.path()).unwrap().permissions().mode();
            assert_eq!(0o700, mode & 0o777, "Unexpected mode: {mode:o}");
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

    #[test]
    fn generated_rpc_api_secrets_are_random_32_bytes_hex_encoded() {
        let secret = generate_rpc_api_secret();

        assert_eq!(64, secret.len());
        assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(secret, generate_rpc_api_secret());
    }

    mod call_rpc {
        use httpmock::MockServer;

        use super::*;

        const SECRET: &str = "my-secret";

        #[tokio::test]
        async fn sends_the_secret_as_a_bearer_token() {
            let server = MockServer::start();
            let mock = server.mock(|when, then| {
                when.method("POST")
                    .path("/api/v0/version")
                    .header("authorization", "Bearer my-secret");
                then.status(200);
            });

            call_rpc(
                &Client::new(),
                &Url::parse(&server.base_url()).unwrap(),
                SECRET,
                "version",
            )
            .await
            .unwrap();

            mock.assert();
        }

        #[tokio::test]
        async fn error_on_an_error_status_does_not_hold_the_secret() {
            let server = MockServer::start();
            server.mock(|_, then| {
                then.status(403);
            });

            let error = call_rpc(
                &Client::new(),
                &Url::parse(&server.base_url()).unwrap(),
                SECRET,
                "version",
            )
            .await
            .expect_err("Should fail on an error status");

            assert!(!format!("{error:?}").contains(SECRET), "{error:?}");
        }

        #[tokio::test]
        async fn error_on_an_unreachable_api_does_not_hold_the_secret() {
            let closed_port = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();

            let error = call_rpc(
                &Client::new(),
                &Url::parse(&format!("http://127.0.0.1:{closed_port}")).unwrap(),
                SECRET,
                "version",
            )
            .await
            .expect_err("Should fail when the RPC API is unreachable");

            assert!(!format!("{error:?}").contains(SECRET), "{error:?}");
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

        #[test]
        fn removes_the_variables_read_by_kubo_whatever_their_case() {
            let env_vars =
                ["ipfs_path", "Golog_Log_Level", "libp2p_force_pnet"].map(OsString::from);

            assert_eq!(
                vec!["ipfs_path", "Golog_Log_Level", "libp2p_force_pnet"],
                kubo_env_vars_to_remove(env_vars)
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn start_runs_the_binary_unpacked_in_its_repository() {
        let test_dir = temp_dir_create!();
        let parent_dir = test_dir.join("parent");
        fs::create_dir(&parent_dir).unwrap();
        let run_binary_file = test_dir.join("run_binary");
        let archive = fake_kubo_archive(
            &test_dir,
            &format!("echo \"$0\" > \"{}\"\nexit 1", run_binary_file.display()),
        );

        ManagedKuboNode::start(&archive, &parent_dir)
            .await
            .err()
            .expect("Start should fail when a setup command fails");

        let run_binary = PathBuf::from(fs::read_to_string(&run_binary_file).unwrap().trim());
        let repository_dir = run_binary.parent().and_then(Path::parent).unwrap();
        assert_eq!(Some(parent_dir.as_path()), repository_dir.parent());
        assert!(run_binary.ends_with("kubo/ipfs"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn start_fails_and_removes_its_repository_when_a_setup_command_fails() {
        let test_dir = temp_dir_create!();
        let parent_dir = test_dir.join("parent");
        fs::create_dir(&parent_dir).unwrap();
        let archive = fake_kubo_archive(&test_dir, "exit 1");

        let error = ManagedKuboNode::start(&archive, &parent_dir)
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
        use super::*;

        /// Archive of a fake `ipfs` binary succeeding on all commands but `hanging_command`, on
        /// which it writes its pid to `pid_file` then hangs
        fn fake_kubo_archive_hanging_on(
            dir: &Path,
            hanging_command: &str,
        ) -> (KuboArchive, PathBuf) {
            let pid_file = dir.join("pid");
            let archive = fake_kubo_archive(
                dir,
                &format!(
                    "if [ \"$1\" = \"{hanging_command}\" ]; then echo $$ > \"{}\"; exec sleep 30; fi\n\
                     if [ \"$1\" = \"init\" ]; then echo '{{}}' > \"$IPFS_PATH/config\"; fi",
                    pid_file.display()
                ),
            );

            (archive, pid_file)
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
            let (archive, pid_file) = fake_kubo_archive_hanging_on(test_dir, hanging_command);

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
                result = ManagedKuboNode::start(&archive, &parent_dir) => {
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
    fn default_parent_dir_is_the_system_temp_dir() {
        assert_eq!(std::env::temp_dir(), ManagedKuboNode::default_parent_dir());
    }

    #[tokio::test]
    async fn download_and_start_fails_when_the_parent_dir_does_not_exist() {
        let parent_dir = temp_dir_create!().join("missing");
        assert!(!parent_dir.exists());

        let error = ManagedKuboNode::download_and_start(&parent_dir, None)
            .await
            .err()
            .expect("Should fail when the parent directory does not exist");

        assert!(
            format!("{error:?}").contains("does not exist"),
            "Unexpected error: {error:?}"
        );
    }

    /// Tests against the real Kubo binary, downloaded in the user cache directory.
    ///
    /// Run them with `cargo test -p mithril-client-cli managed_node -- --ignored`.
    mod with_the_real_kubo_binary {
        use super::*;

        async fn rpc_version_is_reachable(rpc_url: &Url, rpc_auth_token: Option<&str>) -> bool {
            let mut request = Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .post(rpc_url.join("api/v0/version").unwrap());
            if let Some(rpc_auth_token) = rpc_auth_token {
                request = request.bearer_auth(rpc_auth_token);
            }
            request
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
        }

        #[tokio::test]
        #[ignore = "downloads and runs the real Kubo binary"]
        async fn starts_a_reachable_node_then_shuts_it_down_and_removes_its_repository() {
            let parent_dir = temp_dir_create!();

            let node = ManagedKuboNode::download_and_start(&parent_dir, None).await.unwrap();
            let rpc_url = node.rpc_url().clone();
            let rpc_auth_token = node.rpc_auth_token().to_string();

            assert!(rpc_version_is_reachable(&rpc_url, Some(&rpc_auth_token)).await);
            assert!(
                !rpc_version_is_reachable(&rpc_url, None).await,
                "The RPC API should require the auth token"
            );
            assert_eq!(1, dir_entries_count(&parent_dir));

            let stop_start = Instant::now();
            node.stop().await.unwrap();

            assert!(
                stop_start.elapsed() < SHUTDOWN_TIMEOUT,
                "The daemon should shut down on request instead of being killed after the timeout"
            );
            assert!(!rpc_version_is_reachable(&rpc_url, Some(&rpc_auth_token)).await);
            assert_eq!(0, dir_entries_count(&parent_dir));
        }

        #[tokio::test]
        #[ignore = "downloads and runs the real Kubo binary"]
        async fn kills_the_daemon_and_removes_its_repository_when_dropped_without_being_stopped() {
            let parent_dir = temp_dir_create!();

            let node = ManagedKuboNode::download_and_start(&parent_dir, None).await.unwrap();
            let rpc_url = node.rpc_url().clone();
            let rpc_auth_token = node.rpc_auth_token().to_string();
            drop(node);

            assert!(!rpc_version_is_reachable(&rpc_url, Some(&rpc_auth_token)).await);
            assert_eq!(0, dir_entries_count(&parent_dir));
        }
    }
}
