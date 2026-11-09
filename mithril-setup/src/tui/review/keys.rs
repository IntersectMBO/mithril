//! Pure mapping of the keyboard events to the review table actions

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::review::model::{Action, Mode};

/// Map a key event to the action it triggers in the given mode, if any
///
/// Modifiers are matched exactly: a binding is not triggered when other modifiers are held.
pub fn to_action(key: KeyEvent, mode: &Mode) -> Option<Action> {
    use KeyCode::*;
    const NONE: KeyModifiers = KeyModifiers::NONE;
    const SHIFT: KeyModifiers = KeyModifiers::SHIFT;
    const CTRL: KeyModifiers = KeyModifiers::CONTROL;
    const ALT: KeyModifiers = KeyModifiers::ALT;

    match (mode, key.modifiers, key.code) {
        (_, CTRL, Char('c')) => Some(Action::Abort),

        (Mode::Navigating, NONE, Up) => Some(Action::Up),
        (Mode::Navigating, NONE, Down) => Some(Action::Down),
        (Mode::Navigating, NONE, Enter) => Some(Action::Edit),
        (Mode::Navigating, NONE, Esc) => Some(Action::Abort),
        (Mode::Navigating, CTRL, Char('s')) => Some(Action::Confirm),

        (Mode::Editing { .. }, NONE | SHIFT, Char(character)) => Some(Action::Input(character)),
        (Mode::Editing { .. }, NONE, Backspace) => Some(Action::Backspace),
        (Mode::Editing { .. }, NONE, Delete) => Some(Action::Delete),
        (Mode::Editing { .. }, NONE, Left) => Some(Action::Left),
        (Mode::Editing { .. }, NONE, Right) => Some(Action::Right),
        (Mode::Editing { .. }, NONE, Home) => Some(Action::Home),
        (Mode::Editing { .. }, NONE, End) => Some(Action::End),
        (Mode::Editing { .. }, NONE, Enter) => Some(Action::Save),
        (Mode::Editing { .. }, NONE, Esc) => Some(Action::Cancel),
        (Mode::Editing { .. }, CTRL | ALT, Backspace) => Some(Action::DeleteWordBackward),
        (Mode::Editing { .. }, CTRL | ALT, Delete) => Some(Action::DeleteWordForward),
        (Mode::Editing { .. }, CTRL | ALT, Left) => Some(Action::MoveWordBackward),
        (Mode::Editing { .. }, CTRL | ALT, Right) => Some(Action::MoveWordForward),

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
    fn extra_modifiers_do_not_trigger_a_binding() {
        let ctrl_shift = KeyModifiers::CONTROL | KeyModifiers::SHIFT;

        assert_eq!(
            None,
            to_action(KeyEvent::new(KeyCode::Left, ctrl_shift), &editing())
        );
        assert_eq!(
            None,
            to_action(
                KeyEvent::new(KeyCode::Char('a'), KeyModifiers::ALT),
                &editing()
            )
        );
        assert_eq!(
            None,
            to_action(
                KeyEvent::new(KeyCode::Up, KeyModifiers::SHIFT),
                &Mode::Navigating
            )
        );
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
