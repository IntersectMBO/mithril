use clap::{
    builder::{StyledStr, Styles},
    error::{ContextKind, ContextValue},
};

use crate::ClapError;

/// Stores the removed command name and the new command name to use.
#[derive(Clone)]
pub struct RemovedCommand {
    command: String,
    new_command: String,
    additional_message: Option<String>,
    alias: Option<String>,
}

impl RemovedCommand {
    /// Create information about a removed command
    pub fn new<S1: Into<String>, S2: Into<String>>(command: S1, new_command: S2) -> Self {
        Self {
            command: command.into(),
            new_command: new_command.into(),
            additional_message: None,
            alias: None,
        }
    }

    /// Append a message to the removal error, e.g. `with option '--option'`
    pub fn with_additional_message<S: Into<String>>(mut self, additional_message: S) -> Self {
        self.additional_message = Some(additional_message.into());
        self
    }

    /// Also match the removed command when invoked through this alias
    pub fn with_alias<S: Into<String>>(mut self, alias: S) -> Self {
        self.alias = Some(alias.into());
        self
    }
}

/// Tool to handle known removed Clap commands.
pub struct CommandRemoval;

impl CommandRemoval {
    fn find_removed_command(
        error: &ClapError,
        removed_commands: Vec<RemovedCommand>,
    ) -> Option<RemovedCommand> {
        if let Some(context_value) = error.get(ContextKind::InvalidSubcommand) {
            let command_name = context_value.to_string();
            removed_commands.into_iter().find(|rc| {
                command_name == rc.command || rc.alias.as_ref().is_some_and(|a| &command_name == a)
            })
        } else {
            None
        }
    }

    /// Modify the result to add information on removed commands.
    pub fn handle_removed_commands<A>(
        matches_result: Result<A, ClapError>,
        styles: Styles,
        removed_commands: Vec<RemovedCommand>,
    ) -> Result<A, ClapError> {
        matches_result.map_err(|mut e: ClapError| {
            if let Some(removed_command) = Self::find_removed_command(&e, removed_commands)
            {
                let additional_message = removed_command
                    .additional_message
                    .map(|m| format!(" {m}"))
                    .unwrap_or_default();
                let message = format!(
                    "'{}{}{}' command has been removed, use '{}{}{}' command instead{additional_message}",
                    styles.get_error().render(),
                    removed_command.command,
                    styles.get_error().render_reset(),
                    styles.get_valid().render(),
                    removed_command.new_command,
                    styles.get_valid().render_reset(),
                );
                e.insert(
                    ContextKind::Suggested,
                    ContextValue::StyledStrs(vec![StyledStr::from(&message)]),
                );
            }
            e
        })
    }
}

#[cfg(test)]
mod tests {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    use clap::{CommandFactory, Parser, Subcommand};

    use super::*;

    #[derive(Parser, Debug, Clone)]
    pub struct MyCommand {
        #[clap(subcommand)]
        command: MySubCommands,
    }

    #[derive(Subcommand, Debug, Clone)]
    enum MySubCommands {}

    fn build_error(invalid_subcommand_name: &str) -> ClapError {
        let mut e = ClapError::new(ErrorKind::InvalidSubcommand).with_cmd(&MyCommand::command());
        e.insert(
            ContextKind::InvalidSubcommand,
            ContextValue::String(invalid_subcommand_name.to_string()),
        );
        e
    }

    #[test]
    fn invalid_sub_command_message_for_a_non_removed_command_is_not_modified() {
        let error = build_error("invalid_command");
        let default_error_message = error.to_string();

        let result = CommandRemoval::handle_removed_commands(
            Err(error) as Result<MyCommand, ClapError>,
            Styles::plain(),
            vec![RemovedCommand::new("old_command", "new_command")],
        );
        assert!(result.is_err());

        let message = result.err().unwrap().to_string();
        assert_eq!(default_error_message, message);
    }

    #[test]
    fn replace_error_message_on_removed_commands_and_show_the_new_command_without_additional_message()
     {
        let error = build_error("old_command");

        let result = CommandRemoval::handle_removed_commands(
            Err(error) as Result<MyCommand, ClapError>,
            Styles::plain(),
            vec![RemovedCommand::new("old_command", "new_command")],
        );
        assert!(result.is_err());

        let message = result.err().unwrap().to_string();
        assert!(
            message.contains(
                "'old_command' command has been removed, use 'new_command' command instead"
            ),
            "Unexpected error message:\n{message}"
        );
    }

    #[test]
    fn replace_error_message_on_removed_commands_and_show_the_new_command_when_using_alias() {
        let error = build_error("old_alias");

        let result = CommandRemoval::handle_removed_commands(
            Err(error) as Result<MyCommand, ClapError>,
            Styles::plain(),
            vec![RemovedCommand::new("old_command", "new_command").with_alias("old_alias")],
        );
        assert!(result.is_err());

        let message = result.err().unwrap().to_string();
        assert!(
            message.contains(
                "'old_command' command has been removed, use 'new_command' command instead"
            ),
            "Unexpected in error message:\n{message}"
        );
    }

    #[test]
    fn replace_error_message_on_removed_commands_and_show_the_new_command_with_additional_message()
    {
        let error = build_error("old_command");

        let result = CommandRemoval::handle_removed_commands(
            Err(error) as Result<MyCommand, ClapError>,
            Styles::plain(),
            vec![
                RemovedCommand::new("old_command", "new_command")
                    .with_additional_message("'additional message'"),
            ],
        );
        assert!(result.is_err());

        let message = result.err().unwrap().to_string();
        assert!(
            message.contains("'old_command' command has been removed, use 'new_command' command instead 'additional message'"),
            "Unexpected in error message:\n{message}"
        );
    }
}
