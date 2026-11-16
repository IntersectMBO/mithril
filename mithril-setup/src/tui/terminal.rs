//! Terminal shell running the TUI: owns the terminal and reads the keyboard events

use std::io;

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyEventKind};

use crate::runner::ReviewOutcome;
use crate::schema::{FieldError, FieldSpec};
use crate::store::Store;
use crate::tui::review::keys::to_action;
use crate::tui::review::model::ReviewModel;
use crate::tui::review::view::render;

/// Let the user review the store values described by the specs in a table (blocking)
pub fn review(
    specs: Vec<FieldSpec>,
    store: Store,
    errors: Vec<FieldError>,
) -> io::Result<ReviewOutcome> {
    let mut terminal = ratatui::try_init()?;
    let result = run_review(&mut terminal, ReviewModel::new(specs, store, errors));
    ratatui::restore();

    result
}

fn run_review(terminal: &mut DefaultTerminal, mut model: ReviewModel) -> io::Result<ReviewOutcome> {
    loop {
        terminal.draw(|frame| render(&model, frame))?;

        // Only key presses: some platforms (e.g. Windows) also send key releases
        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && let Some(action) = to_action(key, model.mode())
            && let Some(outcome) = model.update(action)
        {
            return Ok(outcome);
        }
    }
}
