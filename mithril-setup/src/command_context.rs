use anyhow::anyhow;
use slog::Logger;

/// Context for the command execution
pub struct CommandContext {
    unstable_enabled: bool,
    json: bool,
    logger: Logger,
}

impl CommandContext {
    /// Create a new command context
    pub fn new(unstable_enabled: bool, json: bool, logger: Logger) -> Self {
        Self {
            unstable_enabled,
            json,
            logger,
        }
    }

    /// Check if unstable commands are enabled
    pub fn is_unstable_enabled(&self) -> bool {
        self.unstable_enabled
    }

    /// Check if JSON output is enabled
    pub fn is_json_output_enabled(&self) -> bool {
        self.json
    }

    /// Ensure that unstable commands are enabled
    pub fn require_unstable(
        &self,
        sub_command: &str,
        command_example: Option<&str>,
    ) -> anyhow::Result<()> {
        if self.is_unstable_enabled() {
            Ok(())
        } else {
            let example = command_example.map(|e| format!(" {e}")).unwrap_or_default();
            Err(anyhow!(
                "The \"{sub_command}\" subcommand is only accepted using the --unstable flag.\n\n\
                ie: \"mithril-setup --unstable {sub_command}{example}\""
            ))
        }
    }

    /// Get the shared logger
    pub fn logger(&self) -> &Logger {
        &self.logger
    }
}

#[cfg(test)]
mod tests {
    use slog::o;

    use super::*;

    #[test]
    fn require_unstable_return_ok_if_unstable_enabled() {
        let unstable_enabled = true;
        let context =
            CommandContext::new(unstable_enabled, true, Logger::root(slog::Discard, o!()));

        let result = context.require_unstable("test", None);
        assert!(result.is_ok(), "Expected Ok, got {result:?}");
    }

    #[test]
    fn require_unstable_return_err_if_unstable_disabled() {
        let unstable_enabled = false;
        let context =
            CommandContext::new(unstable_enabled, true, Logger::root(slog::Discard, o!()));

        let result = context.require_unstable("test", None);
        assert!(result.is_err(), "Expected Err, got {result:?}");
    }
}
