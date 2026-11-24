//! Pure mapping of the keyboard events to the result screen actions

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::setup_result::model::{Action, Button};

/// Map a key event to the action it triggers with the given focused button, if any
pub fn to_action(key: KeyEvent, focused: Button) -> Option<Action> {
    match (focused, key.modifiers, key.code) {
        (_, KeyModifiers::NONE, KeyCode::Left) => Some(Action::Left),
        (_, KeyModifiers::NONE, KeyCode::Right) => Some(Action::Right),
        (Button::Back, KeyModifiers::NONE, KeyCode::Enter) => Some(Action::Back),
        (Button::Exit, KeyModifiers::NONE, KeyCode::Enter) => Some(Action::Exit),
        (_, KeyModifiers::NONE, KeyCode::Esc) => Some(Action::Exit),
        (_, KeyModifiers::CONTROL, KeyCode::Char('c')) => Some(Action::Exit),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn left_and_right_choose_a_button() {
        for focused in [Button::Back, Button::Exit] {
            assert_eq!(Some(Action::Left), to_action(key(KeyCode::Left), focused));
            assert_eq!(Some(Action::Right), to_action(key(KeyCode::Right), focused));
        }
    }

    #[test]
    fn enter_presses_the_focused_button() {
        assert_eq!(
            Some(Action::Back),
            to_action(key(KeyCode::Enter), Button::Back)
        );
        assert_eq!(
            Some(Action::Exit),
            to_action(key(KeyCode::Enter), Button::Exit)
        );
    }

    #[test]
    fn esc_and_ctrl_c_exit_whatever_the_focused_button() {
        for focused in [Button::Back, Button::Exit] {
            for key in [
                KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            ] {
                assert_eq!(Some(Action::Exit), to_action(key, focused), "{key:?}");
            }
        }
    }

    #[test]
    fn other_keys_are_ignored() {
        for key in [
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT),
        ] {
            assert_eq!(None, to_action(key, Button::Exit), "{key:?}");
        }
    }
}
