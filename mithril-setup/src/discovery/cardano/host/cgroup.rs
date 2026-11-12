//! Finds the systemd unit of a process from its Linux control group

use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::Context;
use async_trait::async_trait;
use tokio::fs;

use crate::discovery::cardano::ServiceProbe;

/// Finds the systemd unit running a process from `/proc/<pid>/cgroup`
///
/// systemd places each service in its own control group named after the unit,
/// ie: `0::/system.slice/cardano-node.service`.
pub struct CgroupServiceProbe {
    proc_root: PathBuf,
}

impl CgroupServiceProbe {
    /// Create a probe reading the given proc filesystem
    pub fn new(proc_root: PathBuf) -> Self {
        Self { proc_root }
    }
}

impl Default for CgroupServiceProbe {
    fn default() -> Self {
        Self::new(PathBuf::from("/proc"))
    }
}

#[async_trait]
impl ServiceProbe for CgroupServiceProbe {
    async fn systemd_unit_of(&self, pid: u32) -> anyhow::Result<Option<String>> {
        let cgroup_file = self.proc_root.join(pid.to_string()).join("cgroup");
        match fs::read_to_string(&cgroup_file).await {
            Ok(content) => Ok(parse_systemd_unit(&content)),
            // The process exited since it was listed
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => {
                Err(error).with_context(|| format!("Could not read '{}'", cgroup_file.display()))
            }
        }
    }
}

/// Find the innermost systemd service in a `/proc/<pid>/cgroup` content
///
/// Each line is `hierarchy-ID:controllers:path`, the service being the last `.service`
/// component of the path (the user services are nested in the `user@<uid>.service` unit).
fn parse_systemd_unit(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let path = line.splitn(3, ':').nth(2)?;
        path.rsplit('/')
            .find(|component| component.ends_with(".service"))
            .map(str::to_string)
    })
}

#[cfg(test)]
mod tests {
    use crate::discovery::cardano::host::test_tools::{test_dir, write_file};

    use super::*;

    async fn unit_from_cgroup(test_name: &str, cgroup: &str) -> Option<String> {
        let proc_root = test_dir(test_name);
        write_file(&proc_root.join("42").join("cgroup"), cgroup);

        CgroupServiceProbe::new(proc_root).systemd_unit_of(42).await.unwrap()
    }

    #[tokio::test]
    async fn finds_the_unit_of_a_system_service() {
        let unit = unit_from_cgroup(
            "cgroup_finds_a_system_service",
            "0::/system.slice/cardano-node.service\n",
        )
        .await;

        assert_eq!(Some("cardano-node.service".to_string()), unit);
    }

    #[tokio::test]
    async fn finds_the_unit_of_a_user_service() {
        let unit = unit_from_cgroup(
            "cgroup_finds_a_user_service",
            "0::/user.slice/user-1001.slice/user@1001.service/app.slice/cnode.service\n",
        )
        .await;

        assert_eq!(Some("cnode.service".to_string()), unit);
    }

    #[tokio::test]
    async fn finds_the_unit_with_cgroup_v1() {
        let unit = unit_from_cgroup(
            "cgroup_finds_with_cgroup_v1",
            "12:cpuset:/\n11:memory:/system.slice/cnode.service\n1:name=systemd:/system.slice/cnode.service\n",
        )
        .await;

        assert_eq!(Some("cnode.service".to_string()), unit);
    }

    #[tokio::test]
    async fn finds_no_unit_for_a_process_started_from_a_terminal() {
        let unit = unit_from_cgroup(
            "cgroup_finds_no_unit_for_a_terminal_process",
            "0::/user.slice/user-1001.slice/session-3.scope\n",
        )
        .await;

        assert_eq!(None, unit);
    }

    #[tokio::test]
    async fn finds_no_unit_for_a_process_in_a_container() {
        let unit = unit_from_cgroup("cgroup_finds_no_unit_in_a_container", "0::/\n").await;

        assert_eq!(None, unit);
    }

    #[tokio::test]
    async fn finds_no_unit_for_a_process_that_exited() {
        let probe = CgroupServiceProbe::new(test_dir("cgroup_finds_no_unit_for_an_exited_process"));

        let unit = probe.systemd_unit_of(42).await.unwrap();

        assert_eq!(None, unit);
    }
}
