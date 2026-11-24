//! Pure model of the result screen

use crate::runner::ResultOutcome;

/// Introduction of the command to run
pub const COMMAND_INTRO: &str = "Run this command to finish the setup:";

/// Indentation of the command, so it stands out from the texts around it
pub const COMMAND_INDENT: &str = "  ";

/// Result of the setup shown to the user
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupResult {
    /// What the setup produced
    pub message: &'static str,

    /// Command the user runs to finish the setup
    pub command: &'static str,
}

impl SetupResult {
    /// Text of the result, printed in the terminal once the screen is closed
    pub fn plain_text(&self) -> String {
        format!(
            "{}\n{COMMAND_INTRO}\n{COMMAND_INDENT}{}",
            self.message, self.command
        )
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
    /// Create a model showing the setup result, with the `Exit` button focused
    pub fn new(setup_result: SetupResult) -> Self {
        Self {
            setup_result,
            focused: Button::Exit,
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
        SetupResult {
            message: "Script generated",
            command: "./setup.sh",
        }
    }

    #[test]
    fn plain_text_has_the_message_then_the_indented_command() {
        assert_eq!(
            format!("Script generated\n{COMMAND_INTRO}\n  ./setup.sh"),
            setup_result().plain_text()
        );
    }

    #[test]
    fn exit_is_focused_at_start() {
        assert_eq!(Button::Exit, ResultModel::new(setup_result()).focused());
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
