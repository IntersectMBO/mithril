//! Pure model of the result screen, showing the success or the failure of the setup

use crate::runner::ResultOutcome;

/// Introduction of the command to run
pub const COMMAND_INTRO: &str = "Run this command to finish the setup:";

/// Indentation of the command, so it stands out from the texts around it
pub const COMMAND_INDENT: &str = "  ";

/// Result of the setup shown to the user
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupResult {
    /// The setup succeeded, the user runs a command to finish it
    Success {
        /// What the setup produced
        message: &'static str,

        /// Command the user runs to finish the setup
        command: &'static str,
    },

    /// The setup failed
    Failure {
        /// What the setup could not produce
        message: &'static str,

        /// Reason of the failure
        reason: String,
    },
}

impl SetupResult {
    /// Text printed in the terminal once the screen is exited, the screen being cleared
    ///
    /// Nothing for a failure: the command prints its reason when it ends with the failure.
    pub fn text_printed_on_exit(&self) -> Option<String> {
        match self {
            Self::Success { message, command } => Some(format!(
                "{message}\n{COMMAND_INTRO}\n{COMMAND_INDENT}{command}"
            )),
            Self::Failure { .. } => None,
        }
    }
}

/// Actions the user can perform on the result screen
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Focus the `Back` button
    Left,

    /// Focus the `Exit` button
    Right,

    /// Go back to the review of the saved values
    Back,

    /// Close the result screen, ending the setup
    Exit,
}

/// Buttons of the result screen
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    /// Go back to the review of the saved values
    Back,

    /// Close the result screen
    Exit,
}

/// Model of the result screen
pub struct ResultModel {
    setup_result: SetupResult,
    focused: Button,
}

impl ResultModel {
    /// Create a model showing the setup result, with the `Exit` button focused on a success and
    /// the `Back` button on a failure (going back to fix a value is the likely next step)
    pub fn new(setup_result: SetupResult) -> Self {
        let focused = match setup_result {
            SetupResult::Success { .. } => Button::Exit,
            SetupResult::Failure { .. } => Button::Back,
        };

        Self {
            setup_result,
            focused,
        }
    }

    /// Result of the setup shown
    pub fn setup_result(&self) -> &SetupResult {
        &self.setup_result
    }

    /// Button having the focus
    pub fn focused(&self) -> Button {
        self.focused
    }

    /// Apply the action, returns the outcome when the screen is closed
    pub fn update(&mut self, action: Action) -> Option<ResultOutcome> {
        match action {
            Action::Left => self.focused = Button::Back,
            Action::Right => self.focused = Button::Exit,
            Action::Back => return Some(ResultOutcome::Back),
            Action::Exit => return Some(ResultOutcome::Exit),
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_result() -> SetupResult {
        SetupResult::Success {
            message: "Script generated",
            command: "./setup.sh",
        }
    }

    fn setup_failure() -> SetupResult {
        SetupResult::Failure {
            message: "Script not generated",
            reason: "disk full".to_string(),
        }
    }

    #[test]
    fn only_a_success_is_printed_on_exit() {
        assert_eq!(
            Some(format!("Script generated\n{COMMAND_INTRO}\n  ./setup.sh")),
            setup_result().text_printed_on_exit()
        );
        assert_eq!(None, setup_failure().text_printed_on_exit());
    }

    #[test]
    fn exit_is_focused_at_start_on_a_success_and_back_on_a_failure() {
        assert_eq!(Button::Exit, ResultModel::new(setup_result()).focused());
        assert_eq!(Button::Back, ResultModel::new(setup_failure()).focused());
    }

    #[test]
    fn left_and_right_switch_between_buttons() {
        let mut model = ResultModel::new(setup_result());

        assert_eq!(None, model.update(Action::Left));
        assert_eq!(Button::Back, model.focused());

        assert_eq!(None, model.update(Action::Left));
        assert_eq!(Button::Back, model.focused());

        assert_eq!(None, model.update(Action::Right));
        assert_eq!(Button::Exit, model.focused());
    }

    #[test]
    fn back_and_exit_close_the_screen_with_their_outcome() {
        let mut model = ResultModel::new(setup_result());

        assert_eq!(Some(ResultOutcome::Back), model.update(Action::Back));
        assert_eq!(Some(ResultOutcome::Exit), model.update(Action::Exit));
    }
}
