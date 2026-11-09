//! Pure mapping of the keyboard events to the review table actions

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::review::model::{Action, Mode};

/// Map a key event to the action it triggers in the given mode, if any
pub fn to_action(key: KeyEvent, mode: &Mode) -> Option<Action> {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match (key.code, mode) {
            (KeyCode::Char('c'), _) => Some(Action::Abort),
            (KeyCode::Char('s'), Mode::Navigating) => Some(Action::Confirm),
            (KeyCode::Backspace, Mode::Editing { .. }) => Some(Action::DeleteWordBackward),
            (KeyCode::Delete, Mode::Editing { .. }) => Some(Action::DeleteWordForward),
            (KeyCode::Left, Mode::Editing { .. }) => Some(Action::MoveWordBackward),
            (KeyCode::Right, Mode::Editing { .. }) => Some(Action::MoveWordForward),
            _ => None,
        };
    }

    match (key.code, mode) {
        (KeyCode::Up, Mode::Navigating) => Some(Action::Up),
        (KeyCode::Down, Mode::Navigating) => Some(Action::Down),
        (KeyCode::Enter, Mode::Navigating) => Some(Action::Edit),
        (KeyCode::Esc, Mode::Navigating) => Some(Action::Abort),
        (KeyCode::Char(character), Mode::Editing { .. }) => Some(Action::Input(character)),
        (KeyCode::Backspace, Mode::Editing { .. }) if key.modifiers.contains(KeyModifiers::ALT) => {
            Some(Action::DeleteWordBackward)
        }
        (KeyCode::Backspace, Mode::Editing { .. }) => Some(Action::Backspace),
        (KeyCode::Delete, Mode::Editing { .. }) if key.modifiers.contains(KeyModifiers::ALT) => {
            Some(Action::DeleteWordForward)
        }
        (KeyCode::Delete, Mode::Editing { .. }) => Some(Action::Delete),
        (KeyCode::Left, Mode::Editing { .. }) if key.modifiers.contains(KeyModifiers::ALT) => {
            Some(Action::MoveWordBackward)
        }
        (KeyCode::Left, Mode::Editing { .. }) => Some(Action::Left),
        (KeyCode::Right, Mode::Editing { .. }) if key.modifiers.contains(KeyModifiers::ALT) => {
            Some(Action::MoveWordForward)
        }
        (KeyCode::Right, Mode::Editing { .. }) => Some(Action::Right),
        (KeyCode::Home, Mode::Editing { .. }) => Some(Action::Home),
        (KeyCode::End, Mode::Editing { .. }) => Some(Action::End),
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
    fn cursor_keys_while_editing() {
        let mode = editing();

        assert_eq!(Some(Action::Left), to_action(key(KeyCode::Left), &mode));
        assert_eq!(Some(Action::Right), to_action(key(KeyCode::Right), &mode));
        assert_eq!(Some(Action::Home), to_action(key(KeyCode::Home), &mode));
        assert_eq!(Some(Action::End), to_action(key(KeyCode::End), &mode));
        assert_eq!(Some(Action::Delete), to_action(key(KeyCode::Delete), &mode));
    }

    #[test]
    fn cursor_keys_are_ignored_while_navigating() {
        for code in [
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::Home,
            KeyCode::End,
            KeyCode::Delete,
        ] {
            assert_eq!(None, to_action(key(code), &Mode::Navigating), "{code:?}");
        }
    }

    #[test]
    fn shifted_characters_are_input_while_editing() {
        let shifted = KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT);

        assert_eq!(Some(Action::Input('A')), to_action(shifted, &editing()));
    }

    #[test]
    fn word_deletion_keys_while_editing() {
        let mode = editing();

        assert_eq!(
            Some(Action::DeleteWordBackward),
            to_action(
                KeyEvent::new(KeyCode::Backspace, KeyModifiers::CONTROL),
                &mode
            )
        );
        assert_eq!(
            Some(Action::DeleteWordBackward),
            to_action(KeyEvent::new(KeyCode::Backspace, KeyModifiers::ALT), &mode)
        );
        assert_eq!(
            Some(Action::DeleteWordForward),
            to_action(KeyEvent::new(KeyCode::Delete, KeyModifiers::CONTROL), &mode)
        );
        assert_eq!(
            Some(Action::DeleteWordForward),
            to_action(KeyEvent::new(KeyCode::Delete, KeyModifiers::ALT), &mode)
        );
    }

    #[test]
    fn word_deletion_keys_are_ignored_while_navigating() {
        for key in [
            KeyEvent::new(KeyCode::Backspace, KeyModifiers::CONTROL),
            KeyEvent::new(KeyCode::Backspace, KeyModifiers::ALT),
            KeyEvent::new(KeyCode::Delete, KeyModifiers::CONTROL),
            KeyEvent::new(KeyCode::Delete, KeyModifiers::ALT),
        ] {
            assert_eq!(None, to_action(key, &Mode::Navigating), "{key:?}");
        }
    }

    #[test]
    fn word_move_keys_while_editing() {
        let mode = editing();

        for modifier in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
            assert_eq!(
                Some(Action::MoveWordBackward),
                to_action(KeyEvent::new(KeyCode::Left, modifier), &mode),
                "{modifier:?}"
            );
            assert_eq!(
                Some(Action::MoveWordForward),
                to_action(KeyEvent::new(KeyCode::Right, modifier), &mode),
                "{modifier:?}"
            );
        }
    }

    #[test]
    fn word_move_keys_are_ignored_while_navigating() {
        for modifier in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
            for code in [KeyCode::Left, KeyCode::Right] {
                let key = KeyEvent::new(code, modifier);
                assert_eq!(None, to_action(key, &Mode::Navigating), "{key:?}");
            }
        }
    }

    #[test]
    fn ctrl_h_and_ctrl_w_are_not_mapped_while_editing() {
        assert_eq!(None, to_action(ctrl('h'), &editing()));
        assert_eq!(None, to_action(ctrl('w'), &editing()));
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
