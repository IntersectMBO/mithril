//! Pure mapping of the keyboard events to the review table actions

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::review::model::{Action, Mode};

/// Map a key event to the action it triggers in the given mode, if any
pub fn to_action(key: KeyEvent, mode: &Mode) -> Option<Action> {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match (key.code, mode) {
            (KeyCode::Char('c'), _) => Some(Action::Abort),
            (KeyCode::Char('s'), Mode::Navigating) => Some(Action::Confirm),
            _ => None,
        };
    }

    match (key.code, mode) {
        (KeyCode::Up, Mode::Navigating) => Some(Action::Up),
        (KeyCode::Down, Mode::Navigating) => Some(Action::Down),
        (KeyCode::Enter, Mode::Navigating) => Some(Action::Edit),
        (KeyCode::Esc, Mode::Navigating) => Some(Action::Abort),
        (KeyCode::Char(character), Mode::Editing { .. }) => Some(Action::Input(character)),
        (KeyCode::Backspace, Mode::Editing { .. }) => Some(Action::Backspace),
        (KeyCode::Enter, Mode::Editing { .. }) => Some(Action::Save),
        (KeyCode::Esc, Mode::Editing { .. }) => Some(Action::Cancel),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(character: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(character), KeyModifiers::CONTROL)
    }

    fn editing() -> Mode {
        Mode::Editing {
            buffer: String::new(),
            cursor: 0,
        }
    }

    #[test]
    fn navigating_keys() {
        let mode = Mode::Navigating;

        assert_eq!(Some(Action::Up), to_action(key(KeyCode::Up), &mode));
        assert_eq!(Some(Action::Down), to_action(key(KeyCode::Down), &mode));
        assert_eq!(Some(Action::Edit), to_action(key(KeyCode::Enter), &mode));
        assert_eq!(Some(Action::Abort), to_action(key(KeyCode::Esc), &mode));
        assert_eq!(Some(Action::Confirm), to_action(ctrl('s'), &mode));
        assert_eq!(Some(Action::Abort), to_action(ctrl('c'), &mode));
    }

    #[test]
    fn editing_keys() {
        let mode = editing();

        assert_eq!(
            Some(Action::Input('a')),
            to_action(key(KeyCode::Char('a')), &mode)
        );
        assert_eq!(
            Some(Action::Backspace),
            to_action(key(KeyCode::Backspace), &mode)
        );
        assert_eq!(Some(Action::Save), to_action(key(KeyCode::Enter), &mode));
        assert_eq!(Some(Action::Cancel), to_action(key(KeyCode::Esc), &mode));
        assert_eq!(Some(Action::Abort), to_action(ctrl('c'), &mode));
    }

    #[test]
    fn shifted_characters_are_input_while_editing() {
        let shifted = KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT);

        assert_eq!(Some(Action::Input('A')), to_action(shifted, &editing()));
    }

    #[test]
    fn ctrl_s_is_not_input_while_editing() {
        assert_eq!(None, to_action(ctrl('s'), &editing()));
    }

    #[test]
    fn characters_are_ignored_while_navigating() {
        assert_eq!(None, to_action(key(KeyCode::Char('a')), &Mode::Navigating));
    }

    #[test]
    fn arrows_are_ignored_while_editing() {
        assert_eq!(None, to_action(key(KeyCode::Up), &editing()));
        assert_eq!(None, to_action(key(KeyCode::Down), &editing()));
    }
}
