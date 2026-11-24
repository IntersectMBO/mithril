//! Terminal shell running the TUI: owns the terminal and reads the keyboard, paste and mouse events

use std::io::{self, stdout};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyEventKind,
};
use ratatui::crossterm::execute;

use crate::runner::ReviewOutcome;
use crate::schema::{FieldError, FieldSpec};
use crate::store::Store;
use crate::tui::review::keys::{mouse_to_action, paste_to_action, to_action};
use crate::tui::review::model::ReviewModel;
use crate::tui::review::view::render;

/// Let the user review the store values described by the specs in a table (blocking)
pub fn review(
    specs: Vec<FieldSpec>,
    store: Store,
    errors: Vec<FieldError>,
) -> io::Result<ReviewOutcome> {
    let mut terminal = ratatui::try_init()?;
    let result = TerminalModes::enable().and_then(|_terminal_modes| {
        run_review(&mut terminal, ReviewModel::new(specs, store, errors))
    });
    ratatui::restore();

    result
}

fn run_review(terminal: &mut DefaultTerminal, mut model: ReviewModel) -> io::Result<ReviewOutcome> {
    loop {
        terminal.draw(|frame| render(&model, frame))?;

        let action = match event::read()? {
            // Only key presses: some platforms (e.g. Windows) also send key releases
            Event::Key(key) if key.kind == KeyEventKind::Press => to_action(key, model.mode()),
            Event::Paste(text) => paste_to_action(text, model.mode()),
            Event::Mouse(mouse) => mouse_to_action(mouse, model.mode()),
            _ => None,
        };

        if let Some(action) = action
            && let Some(outcome) = model.update(action)
        {
            return Ok(outcome);
        }
    }
}

/// Terminal modes enabled while this guard is alive: mouse capture and bracketed paste
///
/// Without the mouse capture, terminals turn each wheel step into several arrow key presses.
/// Without the bracketed paste, a pasted text arrives as typed keys, its newlines as `Enter`.
/// The modes are disabled on drop, also on a panic: the ratatui panic hook does not disable them,
/// which would leave the terminal printing escape sequences on each mouse move or paste.
struct TerminalModes;

impl TerminalModes {
    fn enable() -> io::Result<Self> {
        // Created first, so the modes are disabled when dropped if enabling one of them fails
        let modes = Self;
        execute!(stdout(), EnableMouseCapture)?;
        // Not supported by every terminal (e.g. legacy Windows consoles), a paste then arrives
        // as typed keys
        let _ = execute!(stdout(), EnableBracketedPaste);

        Ok(modes)
    }
}

impl Drop for TerminalModes {
    fn drop(&mut self) {
        // Nothing else can be done if it fails while dropping
        let _ = execute!(stdout(), DisableBracketedPaste);
        let _ = execute!(stdout(), DisableMouseCapture);
    }
}
