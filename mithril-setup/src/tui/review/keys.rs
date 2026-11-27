//! Pure mapping of the keyboard, paste and mouse events to the review table actions

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};

use crate::tui::review::model::{Action, Button, Mode};

/// Map a key event to the action it triggers in the given mode, if any
///
/// Modifiers are matched exactly: a binding is not triggered when other modifiers are held.
pub fn to_action(key: KeyEvent, mode: &Mode) -> Option<Action> {
    use KeyCode::*;
    const NONE: KeyModifiers = KeyModifiers::NONE;
    const SHIFT: KeyModifiers = KeyModifiers::SHIFT;
    const CTRL: KeyModifiers = KeyModifiers::CONTROL;
    const ALT: KeyModifiers = KeyModifiers::ALT;
    // On Windows, AltGr is reported as Ctrl+Alt
    const ALTGR: KeyModifiers = KeyModifiers::CONTROL.union(KeyModifiers::ALT);

    match (mode, key.modifiers, key.code) {
        (_, CTRL, Char('c')) => Some(Action::Abort),

        (Mode::Navigating | Mode::OnButton(_), NONE, Up) => Some(Action::Up),
        (Mode::Navigating | Mode::OnButton(_), NONE, Esc) => Some(Action::FocusAbort),
        (Mode::Navigating | Mode::OnButton(_), CTRL, Char('s')) => Some(Action::FocusContinue),

        (Mode::Navigating, NONE, Down) => Some(Action::Down),
        (Mode::Navigating, NONE, Enter) => Some(Action::Edit),

        (Mode::OnButton(_), NONE, Left) => Some(Action::Left),
        (Mode::OnButton(_), NONE, Right) => Some(Action::Right),
        (Mode::OnButton(Button::Abort), NONE, Enter) => Some(Action::Abort),
        (Mode::OnButton(Button::Continue), NONE, Enter) => Some(Action::Confirm),

        (Mode::ErrorsPopup { .. }, NONE, Up) => Some(Action::Up),
        (Mode::ErrorsPopup { .. }, NONE, Down) => Some(Action::Down),
        (Mode::ErrorsPopup { .. }, NONE, Enter) => Some(Action::GoToField),
        (Mode::ErrorsPopup { .. }, NONE, Esc) => Some(Action::ClosePopup),

        (Mode::Editing { .. }, NONE | SHIFT | ALTGR, Char(character)) => {
            Some(Action::Input(character))
        }
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

/// Map a pasted text to the action it triggers in the given mode, if any
///
/// Only a value being edited accepts a paste.
pub fn paste_to_action(text: String, mode: &Mode) -> Option<Action> {
    match mode {
        Mode::Editing { .. } => Some(Action::Paste(text)),
        Mode::Navigating | Mode::OnButton(_) | Mode::ErrorsPopup { .. } => None,
    }
}

/// Map a mouse event to the action it triggers in the given mode, if any
///
/// The wheel moves like the `↑`/`↓` keys, one row per wheel step, other mouse events are ignored.
pub fn mouse_to_action(mouse: MouseEvent, mode: &Mode) -> Option<Action> {
    match (mode, mouse.kind) {
        (
            Mode::Navigating | Mode::OnButton(_) | Mode::ErrorsPopup { .. },
            MouseEventKind::ScrollUp,
        ) => Some(Action::Up),
        (Mode::Navigating | Mode::ErrorsPopup { .. }, MouseEventKind::ScrollDown) => {
            Some(Action::Down)
        }

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
        assert_eq!(
            Some(Action::FocusAbort),
            to_action(key(KeyCode::Esc), &mode)
        );
        assert_eq!(Some(Action::FocusContinue), to_action(ctrl('s'), &mode));
        assert_eq!(Some(Action::Abort), to_action(ctrl('c'), &mode));
    }

    #[test]
    fn button_keys() {
        let abort = Mode::OnButton(Button::Abort);
        let mode_continue = Mode::OnButton(Button::Continue);

        assert_eq!(Some(Action::Up), to_action(key(KeyCode::Up), &abort));
        assert_eq!(Some(Action::Left), to_action(key(KeyCode::Left), &abort));
        assert_eq!(Some(Action::Right), to_action(key(KeyCode::Right), &abort));
        assert_eq!(
            Some(Action::FocusAbort),
            to_action(key(KeyCode::Esc), &abort)
        );
        assert_eq!(Some(Action::FocusContinue), to_action(ctrl('s'), &abort));
        assert_eq!(Some(Action::Abort), to_action(key(KeyCode::Enter), &abort));
        assert_eq!(
            Some(Action::Confirm),
            to_action(key(KeyCode::Enter), &mode_continue)
        );
        assert_eq!(None, to_action(key(KeyCode::Down), &mode_continue));
        assert_eq!(None, to_action(key(KeyCode::Char('a')), &mode_continue));
    }

    #[test]
    fn errors_popup_keys() {
        let mode = Mode::ErrorsPopup { selected: 0 };

        assert_eq!(Some(Action::Up), to_action(key(KeyCode::Up), &mode));
        assert_eq!(Some(Action::Down), to_action(key(KeyCode::Down), &mode));
        assert_eq!(
            Some(Action::GoToField),
            to_action(key(KeyCode::Enter), &mode)
        );
        assert_eq!(
            Some(Action::ClosePopup),
            to_action(key(KeyCode::Esc), &mode)
        );
        assert_eq!(Some(Action::Abort), to_action(ctrl('c'), &mode));
    }

    #[test]
    fn other_keys_are_ignored_in_the_errors_popup() {
        let mode = Mode::ErrorsPopup { selected: 0 };

        for key in [
            key(KeyCode::Left),
            key(KeyCode::Right),
            key(KeyCode::Char('a')),
            ctrl('s'),
        ] {
            assert_eq!(None, to_action(key, &mode), "{key:?}");
        }
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
    fn altgr_characters_are_input_while_editing() {
        // On Windows, AltGr is reported as Ctrl+Alt (e.g. AltGr+8 gives '\' on AZERTY)
        let altgr = KeyModifiers::CONTROL | KeyModifiers::ALT;

        assert_eq!(
            Some(Action::Input('\\')),
            to_action(KeyEvent::new(KeyCode::Char('\\'), altgr), &editing())
        );
        assert_eq!(
            Some(Action::Input('@')),
            to_action(KeyEvent::new(KeyCode::Char('@'), altgr), &editing())
        );
    }

    #[test]
    fn altgr_characters_are_ignored_while_navigating() {
        let altgr = KeyModifiers::CONTROL | KeyModifiers::ALT;

        assert_eq!(
            None,
            to_action(KeyEvent::new(KeyCode::Char('@'), altgr), &Mode::Navigating)
        );
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

    #[test]
    fn paste_is_an_action_only_while_editing() {
        let text = || "/ipc/node.socket".to_string();

        assert_eq!(
            Some(Action::Paste(text())),
            paste_to_action(text(), &editing())
        );
        assert_eq!(None, paste_to_action(text(), &Mode::Navigating));
        assert_eq!(
            None,
            paste_to_action(text(), &Mode::OnButton(Button::Continue))
        );
        assert_eq!(
            None,
            paste_to_action(text(), &Mode::ErrorsPopup { selected: 0 })
        );
    }

    mod mouse {
        use ratatui::crossterm::event::MouseButton;

        use super::*;

        fn mouse(kind: MouseEventKind) -> MouseEvent {
            MouseEvent {
                kind,
                column: 0,
                row: 0,
                modifiers: KeyModifiers::NONE,
            }
        }

        const SCROLL_UP: MouseEventKind = MouseEventKind::ScrollUp;
        const SCROLL_DOWN: MouseEventKind = MouseEventKind::ScrollDown;

        #[test]
        fn wheel_moves_like_the_arrows_while_navigating() {
            let mode = Mode::Navigating;

            assert_eq!(Some(Action::Up), mouse_to_action(mouse(SCROLL_UP), &mode));
            assert_eq!(
                Some(Action::Down),
                mouse_to_action(mouse(SCROLL_DOWN), &mode)
            );
        }

        #[test]
        fn only_wheel_up_moves_from_a_button() {
            let mode = Mode::OnButton(Button::Continue);

            assert_eq!(Some(Action::Up), mouse_to_action(mouse(SCROLL_UP), &mode));
            assert_eq!(None, mouse_to_action(mouse(SCROLL_DOWN), &mode));
        }

        #[test]
        fn wheel_moves_like_the_arrows_in_the_errors_popup() {
            let mode = Mode::ErrorsPopup { selected: 0 };

            assert_eq!(Some(Action::Up), mouse_to_action(mouse(SCROLL_UP), &mode));
            assert_eq!(
                Some(Action::Down),
                mouse_to_action(mouse(SCROLL_DOWN), &mode)
            );
        }

        #[test]
        fn wheel_is_ignored_while_editing() {
            assert_eq!(None, mouse_to_action(mouse(SCROLL_UP), &editing()));
            assert_eq!(None, mouse_to_action(mouse(SCROLL_DOWN), &editing()));
        }

        #[test]
        fn clicks_and_moves_are_ignored() {
            for kind in [
                MouseEventKind::Down(MouseButton::Left),
                MouseEventKind::Up(MouseButton::Left),
                MouseEventKind::Moved,
            ] {
                assert_eq!(
                    None,
                    mouse_to_action(mouse(kind), &Mode::Navigating),
                    "{kind:?}"
                );
            }
        }
    }
}
