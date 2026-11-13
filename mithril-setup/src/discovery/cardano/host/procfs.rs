//! Lists the `cardano-node` processes by reading the Linux `/proc` filesystem

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use async_trait::async_trait;
use tokio::fs;

use crate::discovery::cardano::{NodeProcess, ProcessOwner, ProcessProbe};

/// Lists the `cardano-node` processes from `/proc`, resolving their user from `/etc/passwd`
pub struct ProcfsProcessProbe {
    proc_root: PathBuf,
    passwd_file: PathBuf,
}

impl ProcfsProcessProbe {
    /// Create a probe reading the given proc filesystem and passwd file
    pub fn new(proc_root: PathBuf, passwd_file: PathBuf) -> Self {
        Self {
            proc_root,
            passwd_file,
        }
    }
}

impl Default for ProcfsProcessProbe {
    fn default() -> Self {
        Self::new(PathBuf::from("/proc"), PathBuf::from("/etc/passwd"))
    }
}

#[async_trait]
impl ProcessProbe for ProcfsProcessProbe {
    async fn cardano_node_processes(&self) -> anyhow::Result<Vec<NodeProcess>> {
        let users = self.read_users().await;
        let mut entries = fs::read_dir(&self.proc_root).await.with_context(|| {
            format!(
                "Could not read the proc filesystem at '{}'",
                self.proc_root.display()
            )
        })?;

        let mut processes = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse().ok()) else {
                continue;
            };
            // A process may exit while being read, it is then skipped
            if let Some(process) = read_node_process(pid, &entry.path(), &users).await {
                processes.push(process);
            }
        }
        processes.sort_by_key(|process| process.pid);

        Ok(processes)
    }
}

impl ProcfsProcessProbe {
    /// Read the user names by uid, an unreadable passwd file leaves all the users unknown
    async fn read_users(&self) -> HashMap<u32, String> {
        fs::read_to_string(&self.passwd_file)
            .await
            .map(|content| parse_passwd(&content))
            .unwrap_or_default()
    }
}

const CARDANO_NODE: &str = "cardano-node";

/// Suffix added by the kernel to the executable link when the binary was replaced on disk
const DELETED_SUFFIX: &str = " (deleted)";

async fn read_node_process(
    pid: u32,
    dir: &Path,
    users: &HashMap<u32, String>,
) -> Option<NodeProcess> {
    let cmdline = fs::read(dir.join("cmdline")).await.ok()?;
    let mut cmdline = parse_cmdline(&cmdline).into_iter();
    let program = PathBuf::from(cmdline.next()?);
    // The links of the processes of other users can't be read without privileges
    let executable = fs::read_link(dir.join("exe")).await.ok().map(strip_deleted_suffix);

    if !is_cardano_node(&program) && !executable.as_deref().is_some_and(is_cardano_node) {
        return None;
    }
    // A relative program name can't be resolved: the working directory of the process is
    // not readable either when its executable link is not
    let executable = executable.or_else(|| program.is_absolute().then_some(program));

    let owner = fs::read_to_string(dir.join("status"))
        .await
        .ok()
        .and_then(|status| parse_owner(&status));

    Some(NodeProcess {
        pid,
        executable,
        args: cmdline.collect(),
        working_dir: fs::read_link(dir.join("cwd")).await.ok(),
        user: owner.and_then(|owner| users.get(&owner.uid).cloned()),
        owner,
    })
}

fn is_cardano_node(executable: &Path) -> bool {
    executable.file_name().is_some_and(|name| name == CARDANO_NODE)
}

fn strip_deleted_suffix(executable: PathBuf) -> PathBuf {
    match executable.to_str().and_then(|path| path.strip_suffix(DELETED_SUFFIX)) {
        Some(path) => PathBuf::from(path),
        None => executable,
    }
}

/// Split a `/proc/<pid>/cmdline` content, whose arguments are NUL terminated
fn parse_cmdline(content: &[u8]) -> Vec<String> {
    content
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

/// Extract the real uid and gid from a `/proc/<pid>/status` content,
/// ie: `Uid:\t1001\t1001\t1001\t1001` and `Gid:\t1001\t1001\t1001\t1001`
fn parse_owner(status: &str) -> Option<ProcessOwner> {
    let real_id = |prefix: &str| -> Option<u32> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(prefix))?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    };

    Some(ProcessOwner {
        uid: real_id("Uid:")?,
        gid: real_id("Gid:")?,
    })
}

/// Map the uids to the user names of a passwd file, ie: `cardano:x:1001:1001::/home/cardano:/bin/bash`
fn parse_passwd(content: &str) -> HashMap<u32, String> {
    content
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let uid = fields.nth(1)?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use crate::discovery::cardano::host::test_tools::{test_dir, write_file};

    use super::*;

    struct FakeProc {
        root: PathBuf,
    }

    impl FakeProc {
        fn new(test_name: &str) -> Self {
            let root = test_dir(test_name);
            write_file(
                &root.join("passwd"),
                "root:x:0:0:root:/root:/bin/bash\ncardano:x:1001:1001::/home/cardano:/bin/bash\n",
            );
            Self { root }
        }

        fn proc_root(&self) -> PathBuf {
            self.root.join("proc")
        }

        /// Add a process whose primary group has the same identifier as its user
        fn add_process(&self, pid: u32, cmdline: &[&str], uid: u32) -> PathBuf {
            let dir = self.proc_root().join(pid.to_string());
            write_file(&dir.join("cmdline"), cmdline_bytes(cmdline));
            write_file(
                &dir.join("status"),
                format!(
                    "Name:\tcardano-node\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
                ),
            );
            dir
        }

        fn probe(&self) -> ProcfsProcessProbe {
            ProcfsProcessProbe::new(self.proc_root(), self.root.join("passwd"))
        }
    }

    fn cmdline_bytes(cmdline: &[&str]) -> Vec<u8> {
        cmdline.iter().flat_map(|arg| arg.bytes().chain([0])).collect()
    }

    fn link(dir: &Path, name: &str, target: &str) {
        symlink(target, dir.join(name)).unwrap();
    }

    #[tokio::test]
    async fn lists_the_cardano_node_processes_with_their_details() {
        let proc = FakeProc::new("procfs_lists_the_cardano_node_processes");
        let dir = proc.add_process(
            1234,
            &["/usr/local/bin/cardano-node", "run", "--port", "3001"],
            1001,
        );
        link(&dir, "exe", "/usr/local/bin/cardano-node");
        link(&dir, "cwd", "/home/cardano");

        let processes = proc.probe().cardano_node_processes().await.unwrap();

        assert_eq!(
            vec![NodeProcess {
                pid: 1234,
                executable: Some(PathBuf::from("/usr/local/bin/cardano-node")),
                args: vec!["run".to_string(), "--port".to_string(), "3001".to_string()],
                working_dir: Some(PathBuf::from("/home/cardano")),
                user: Some("cardano".to_string()),
                owner: Some(ProcessOwner {
                    uid: 1001,
                    gid: 1001
                }),
            }],
            processes
        );
    }

    #[tokio::test]
    async fn ignores_the_processes_that_are_not_cardano_nodes() {
        let proc = FakeProc::new("procfs_ignores_other_processes");
        let dir = proc.add_process(10, &["/usr/bin/bash", "cardano-node.sh"], 0);
        link(&dir, "exe", "/usr/bin/bash");
        let dir = proc.add_process(11, &["/usr/bin/cardano-node-exporter"], 0);
        link(&dir, "exe", "/usr/bin/cardano-node-exporter");
        // Kernel threads have an empty command line
        proc.add_process(2, &[], 0);
        // Not a process directory
        write_file(&proc.proc_root().join("meminfo"), "");

        let processes = proc.probe().cardano_node_processes().await.unwrap();

        assert_eq!(Vec::<NodeProcess>::new(), processes);
    }

    #[tokio::test]
    async fn lists_the_processes_ordered_by_pid() {
        let proc = FakeProc::new("procfs_lists_ordered_by_pid");
        for pid in [300, 20, 1000] {
            let dir = proc.add_process(pid, &["cardano-node", "run"], 0);
            link(&dir, "exe", "/usr/local/bin/cardano-node");
        }

        let processes = proc.probe().cardano_node_processes().await.unwrap();

        let pids: Vec<u32> = processes.iter().map(|process| process.pid).collect();
        assert_eq!(vec![20, 300, 1000], pids);
    }

    #[tokio::test]
    async fn falls_back_to_the_program_name_when_the_executable_link_is_not_readable() {
        // Without privileges, the links of processes of other users can't be read
        let proc = FakeProc::new("procfs_falls_back_to_the_program_name");
        proc.add_process(1234, &["/opt/cardano/bin/cardano-node", "run"], 1001);

        let processes = proc.probe().cardano_node_processes().await.unwrap();

        assert_eq!(
            vec![NodeProcess {
                pid: 1234,
                executable: Some(PathBuf::from("/opt/cardano/bin/cardano-node")),
                args: vec!["run".to_string()],
                working_dir: None,
                user: Some("cardano".to_string()),
                owner: Some(ProcessOwner {
                    uid: 1001,
                    gid: 1001
                }),
            }],
            processes
        );
    }

    #[tokio::test]
    async fn leaves_the_executable_unknown_when_only_a_relative_program_name_is_readable() {
        // The program name is relative to the working directory of the node, which can't be read
        // either, so it can't be resolved
        let proc = FakeProc::new("procfs_leaves_the_executable_unknown");
        proc.add_process(1234, &["cardano-node", "run"], 1001);
        proc.add_process(1235, &["./bin/cardano-node", "run"], 1001);

        let processes = proc.probe().cardano_node_processes().await.unwrap();

        let detected: Vec<(u32, Option<PathBuf>)> = processes
            .into_iter()
            .map(|process| (process.pid, process.executable))
            .collect();
        assert_eq!(vec![(1234, None), (1235, None)], detected);
    }

    #[tokio::test]
    async fn detects_a_node_whose_executable_was_replaced_on_disk() {
        let proc = FakeProc::new("procfs_detects_a_replaced_executable");
        let dir = proc.add_process(1234, &["./node", "run"], 0);
        link(&dir, "exe", "/usr/local/bin/cardano-node (deleted)");

        let processes = proc.probe().cardano_node_processes().await.unwrap();

        let detected: Vec<(u32, Option<PathBuf>)> = processes
            .into_iter()
            .map(|process| (process.pid, process.executable))
            .collect();
        assert_eq!(
            vec![(1234, Some(PathBuf::from("/usr/local/bin/cardano-node")))],
            detected
        );
    }

    #[tokio::test]
    async fn leaves_the_user_unknown_when_absent_from_the_passwd_file() {
        let proc = FakeProc::new("procfs_leaves_the_user_unknown");
        proc.add_process(1234, &["cardano-node", "run"], 4242);

        let processes = proc.probe().cardano_node_processes().await.unwrap();

        assert_eq!(None, processes[0].user);
    }

    #[tokio::test]
    async fn reads_the_real_user_and_group_of_the_process() {
        let proc = FakeProc::new("procfs_reads_the_real_user_and_group");
        let dir = proc.add_process(1234, &["cardano-node", "run"], 0);
        // Real, effective, saved set and filesystem identifiers: only the real ones are kept
        write_file(
            &dir.join("status"),
            "Name:\tcardano-node\nUid:\t1001\t0\t0\t0\nGid:\t2002\t0\t0\t0\n",
        );

        let processes = proc.probe().cardano_node_processes().await.unwrap();

        assert_eq!(
            Some(ProcessOwner {
                uid: 1001,
                gid: 2002
            }),
            processes[0].owner
        );
    }

    #[tokio::test]
    async fn leaves_the_owner_unknown_when_the_status_is_not_readable() {
        let proc = FakeProc::new("procfs_leaves_the_owner_unknown");
        let dir = proc.add_process(1234, &["cardano-node", "run"], 1001);
        std::fs::remove_file(dir.join("status")).unwrap();

        let processes = proc.probe().cardano_node_processes().await.unwrap();

        assert_eq!(None, processes[0].owner);
        assert_eq!(None, processes[0].user);
    }

    #[tokio::test]
    async fn fails_when_the_proc_filesystem_can_not_be_read() {
        let probe = ProcfsProcessProbe::new(
            PathBuf::from("/this/proc/does/not/exist"),
            PathBuf::from("/etc/passwd"),
        );

        let result = probe.cardano_node_processes().await;

        assert!(result.is_err(), "Expected Err, got {result:?}");
    }
}
