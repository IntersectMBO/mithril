use anyhow::{Context, anyhow};
use slog_scope::info;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::process::{Child, Command};

use mithril_common::StdResult;

use crate::utils::{LogGroup, file_utils};

#[derive(Debug, Clone)]
pub struct MithrilCommand {
    name: String,
    process_path: PathBuf,
    log_path: PathBuf,
    output_path: Option<PathBuf>,
    work_dir: PathBuf,
    env_vars: HashMap<String, String>,
    default_args: Vec<String>,
}

impl MithrilCommand {
    pub fn new(
        name: &str,
        work_dir: &Path,
        bin_dir: &Path,
        env_vars: HashMap<&str, &str>,
        default_args: &[&str],
    ) -> StdResult<MithrilCommand> {
        let process_path = file_utils::get_process_path(name, bin_dir)?;
        let log_path = work_dir.join(format!("{name}.log"));

        // ugly but it's far easier for callers to manipulate string literals
        let mut env_vars: HashMap<String, String> =
            env_vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let default_args = default_args.iter().map(|s| s.to_string()).collect();

        env_vars.insert("RUST_BACKTRACE".to_string(), "full".to_string());
        env_vars.insert("RUST_LIB_BACKTRACE".to_string(), "0".to_string());

        Ok(MithrilCommand {
            name: name.to_string(),
            process_path,
            log_path,
            output_path: None,
            work_dir: work_dir.to_path_buf(),
            env_vars,
            default_args,
        })
    }

    /// Set the name of the file where the stderr (and stdout if an output_filename is not set) of
    /// the command will be redirected.
    ///
    /// It will be suffixed with '.log'
    pub fn set_log_name(&mut self, name: &str) {
        self.log_path = self.work_dir.join(format!("{name}.log"));
    }

    /// Set the name of the file where the stdout of the command will be redirected.
    /// Return the path to the output file.
    ///
    /// It will be suffixed with '.out'
    ///
    /// If not set the stdout will be redirected to the log file instead.
    pub fn set_output_filename(&mut self, name: &str) -> PathBuf {
        let path = self.work_dir.join(format!("{name}.out"));
        self.output_path = Some(path.clone());
        path
    }

    pub fn set_env_var(&mut self, name: &str, value: &str) {
        self.env_vars.insert(name.to_string(), value.to_string());
    }

    pub fn unset_env_var(&mut self, name: &str) {
        self.env_vars.remove(name);
    }

    pub fn start(&mut self, args: &[String]) -> StdResult<Child> {
        let args = [&self.default_args, args].concat();

        let log_file_stderr = std::fs::File::options()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .with_context(|| {
                format!(
                    "failed to use file `{}` for logging",
                    self.log_path.display(),
                )
            })?;

        let log_file_stdout = match &self.output_path {
            None => log_file_stderr.try_clone().with_context(|| {
                format!(
                    "failed to use file `{}` for logging",
                    self.log_path.display(),
                )
            })?,
            Some(path) => std::fs::File::options()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| {
                    format!("failed to use file `{}` for command stdout", path.display(),)
                })?,
        };

        let mut command = Command::new(&self.process_path);
        command
            .current_dir(&self.work_dir)
            .stdout(log_file_stdout)
            .stderr(log_file_stderr)
            .envs(&self.env_vars)
            .args(&args)
            .kill_on_drop(true);

        info!("Starting {}", self.name; "work_dir" => &self.work_dir.display(), "env" => #?&self.env_vars, "args" => #?&args);

        command
            .spawn()
            .with_context(|| format!("{} failed to start", self.name))
    }

    /// Tail the command log
    ///
    /// You can override the title with the name parameter.
    pub(crate) async fn tail_logs(&self, name: Option<&str>, number_of_line: u64) -> StdResult<()> {
        if !self.log_path.exists() {
            return Err(anyhow!(
                "No log for {}, did you run the command at least once ? expected path: {}",
                self.name,
                self.log_path.display()
            ));
        }

        let _log_group_guard = LogGroup::new(
            name.unwrap_or(&self.name),
            &format!("LAST {number_of_line} LINES"),
        );

        println!(
            "{}",
            file_utils::tail(&self.log_path, number_of_line).await?
        );

        Ok(())
    }

    /// Grep error in log
    ///
    /// You can override the title with the name parameter.
    pub(crate) async fn last_error_in_logs(
        &self,
        name: Option<&str>,
        number_of_error: u64,
    ) -> StdResult<()> {
        if !self.log_path.exists() {
            return Err(anyhow!(
                "No log for {}, did you run the command at least once ? expected path: {}",
                self.name,
                self.log_path.display()
            ));
        }

        let _log_group_guard = LogGroup::new(
            name.unwrap_or(&self.name),
            &format!("LAST {number_of_error} ERROR(S)"),
        );

        println!(
            "{}",
            file_utils::last_errors(&self.log_path, number_of_error)
                .await
                .unwrap_or("Failed to get last error in logs".to_string())
        );

        Ok(())
    }
}
