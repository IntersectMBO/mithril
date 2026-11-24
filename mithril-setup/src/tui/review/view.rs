//! Rendering of the review table

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, HighlightSpacing, Paragraph, Row, Table, TableState};

use crate::tui::review::model::{Button, Mode, ReviewModel};
use crate::tui::widgets::ButtonWidget;

const NAVIGATING_HELP: &str =
    "↑/↓ move · Enter edit · Ctrl+S go to Continue · Esc go to Abort · Ctrl+C abort";
const EDITING_HELP: &str = "Enter save · Esc cancel · Ctrl+C abort";
const BUTTONS_HELP: &str = "←/→ choose · ↑ back to the table · Enter press · Ctrl+C abort";

const ABORT_DESCRIPTION: &str = "Quit the setup without saving the values";
const CONTINUE_DESCRIPTION: &str = "Check the values and go to the next step";

// Layout sizes are counted in terminal cells: rows for heights, characters for widths
/// Minimum height of the table, it takes all the remaining rows
const TABLE_MIN_HEIGHT: u16 = 3;
/// Height of the buttons line
const BUTTONS_HEIGHT: u16 = 1;
/// Space between two buttons
const BUTTONS_SPACING: u16 = 3;
/// Height of the footer: description and help lines, plus top and bottom borders
const FOOTER_HEIGHT: u16 = 4;
/// Width of the label column
// Maybe later: compute the label width from the longest label (with a maximum)?
const LABEL_WIDTH: u16 = 28;
/// Width of the origin column, fits the longest origin ("Discovered")
const ORIGIN_WIDTH: u16 = 12;

/// Draw the review table, its buttons and its footer in the frame
pub fn render(model: &ReviewModel, frame: &mut Frame) {
    let [table_area, buttons_area, footer_area] = Layout::vertical([
        Constraint::Min(TABLE_MIN_HEIGHT),
        Constraint::Length(BUTTONS_HEIGHT),
        Constraint::Length(FOOTER_HEIGHT),
    ])
    .areas(frame.area());

    let model_rows = model.rows();

    let table_rows = model_rows.iter().enumerate().map(|(index, row)| {
        let value = match model.mode() {
            Mode::Editing { buffer, cursor } if index == model.selected() => {
                edited_value(buffer, *cursor)
            }
            _ => Line::from(row.value.clone().unwrap_or_default()),
        };
        let origin = row.origin.map(|origin| format!("{origin:?}")).unwrap_or_default();

        Row::new(vec![
            Cell::from(row.label),
            Cell::from(value),
            Cell::from(origin),
            Cell::from(row.errors.join("; ")),
        ])
    });

    let table = Table::new(
        table_rows,
        // Value and Errors columns share the remaining width equally
        [
            Constraint::Length(LABEL_WIDTH),
            Constraint::Fill(1),
            Constraint::Length(ORIGIN_WIDTH),
            Constraint::Fill(1),
        ],
    )
    .header(Row::new(vec!["Label", "Value", "Origin", "Errors"]).bold())
    .block(Block::bordered().title(" Review "))
    // While editing the row is bold, so the reversed cursor stands out
    .row_highlight_style(match model.mode() {
        Mode::Editing { .. } => Style::new().bold(),
        Mode::Navigating | Mode::OnButton(_) => Style::new().reversed(),
    })
    .highlight_symbol("> ")
    // Keep the space of the highlight symbol when no row is selected, so the columns don't move
    .highlight_spacing(HighlightSpacing::Always);

    // No row is selected while a button is focused, so only one element is highlighted
    let selected_row = match model.mode() {
        Mode::OnButton(_) => None,
        Mode::Navigating | Mode::Editing { .. } => Some(model.selected()),
    };
    let mut table_state = TableState::default().with_selected(selected_row);
    frame.render_stateful_widget(table, table_area, &mut table_state);

    let focused_button = match model.mode() {
        Mode::OnButton(button) => Some(*button),
        Mode::Navigating | Mode::Editing { .. } => None,
    };
    let abort_button = ButtonWidget {
        label: "Abort",
        focused: focused_button == Some(Button::Abort),
    };
    let continue_button = ButtonWidget {
        label: "Continue",
        focused: focused_button == Some(Button::Continue),
    };
    // Buttons take their own width and are centered in the line
    let [abort_area, continue_area] = Layout::horizontal([
        Constraint::Length(abort_button.width()),
        Constraint::Length(continue_button.width()),
    ])
    .flex(Flex::Center)
    .spacing(BUTTONS_SPACING)
    .areas(buttons_area);
    frame.render_widget(abort_button, abort_area);
    frame.render_widget(continue_button, continue_area);

    let description = match model.mode() {
        Mode::OnButton(Button::Abort) => ABORT_DESCRIPTION,
        Mode::OnButton(Button::Continue) => CONTINUE_DESCRIPTION,
        Mode::Navigating | Mode::Editing { .. } => model_rows
            .get(model.selected())
            .map(|row| row.description)
            .unwrap_or_default(),
    };
    let help = match model.mode() {
        Mode::Navigating => NAVIGATING_HELP,
        Mode::Editing { .. } => EDITING_HELP,
        Mode::OnButton(_) => BUTTONS_HELP,
    };
    let footer = Paragraph::new(vec![Line::from(description), Line::from(help).dim()])
        .block(Block::bordered());
    frame.render_widget(footer, footer_area);
}

/// Edited value with the character under the cursor reversed (a space past the end)
fn edited_value(buffer: &str, cursor: usize) -> Line<'static> {
    let before: String = buffer.chars().take(cursor).collect();
    let current: String = buffer.chars().nth(cursor).unwrap_or(' ').to_string();
    let after: String = buffer.chars().skip(cursor + 1).collect();

    Line::from(vec![
        Span::raw(before),
        Span::raw(current).reversed(),
        Span::raw(after),
    ])
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::style::Modifier;

    use crate::schema::{FieldError, FieldSpec, Presence};
    use crate::store::{Origin, Store};
    use crate::tui::review::model::Action;

    use super::*;

    fn model() -> ReviewModel {
        let specs = vec![
            FieldSpec {
                key: "socket",
                label: "Socket path",
                description: "Path of the node socket",
                presence: Presence::Required,
                rules: vec![],
            },
            FieldSpec {
                key: "network",
                label: "Network",
                description: "Name of the network",
                presence: Presence::Required,
                rules: vec![],
            },
        ];
        let mut store = Store::default();
        store.set("socket", "/ipc/node.socket", Origin::Discovered);
        let errors = vec![FieldError::new("network", "Network is required")];

        ReviewModel::new(specs, store, errors)
    }

    fn rendered_buffer(model: &ReviewModel) -> Buffer {
        let mut terminal = Terminal::new(TestBackend::new(100, 12)).unwrap();
        terminal.draw(|frame| render(model, frame)).unwrap();

        terminal.backend().buffer().clone()
    }

    fn lines(buffer: &Buffer) -> Vec<String> {
        buffer
            .content()
            .chunks(buffer.area.width as usize)
            .map(|line| line.iter().map(|cell| cell.symbol()).collect())
            .collect()
    }

    /// Render the model and return the drawn text, one line per terminal row
    fn rendered_text(model: &ReviewModel) -> String {
        lines(&rendered_buffer(model)).join("\n")
    }

    /// Whether the cell at `offset` characters after the start of `text` is drawn reversed
    fn is_reversed(buffer: &Buffer, text: &str, offset: usize) -> bool {
        let (y, x) = lines(buffer)
            .iter()
            .enumerate()
            .find_map(|(y, line)| {
                line.find(text)
                    .map(|byte_index| (y, line[..byte_index].chars().count()))
            })
            .unwrap_or_else(|| panic!("'{text}' not found in:\n{}", lines(buffer).join("\n")));

        buffer[((x + offset) as u16, y as u16)]
            .modifier
            .contains(Modifier::REVERSED)
    }

    #[test]
    fn shows_the_columns_headers() {
        let text = rendered_text(&model());

        for header in ["Label", "Value", "Origin", "Errors"] {
            assert!(text.contains(header), "'{header}' not found in:\n{text}");
        }
    }

    #[test]
    fn shows_each_row_label_value_origin_and_errors() {
        let text = rendered_text(&model());

        for expected in [
            "Socket path",
            "/ipc/node.socket",
            "Discovered",
            "Network",
            "Network is required",
        ] {
            assert!(
                text.contains(expected),
                "'{expected}' not found in:\n{text}"
            );
        }
    }

    #[test]
    fn shows_the_description_of_the_selected_row_only() {
        let mut model = model();
        model.update(Action::Down);

        let text = rendered_text(&model);

        assert!(text.contains("Name of the network"), "{text}");
        assert!(!text.contains("Path of the node socket"), "{text}");
    }

    #[test]
    fn shows_the_navigating_keys_help() {
        let text = rendered_text(&model());

        assert!(text.contains(NAVIGATING_HELP), "{text}");
        assert!(!text.contains(EDITING_HELP), "{text}");
    }

    #[test]
    fn shows_the_editing_keys_help() {
        let mut model = model();
        model.update(Action::Edit);

        let text = rendered_text(&model);

        assert!(text.contains(EDITING_HELP), "{text}");
        assert!(!text.contains(NAVIGATING_HELP), "{text}");
    }

    #[test]
    fn selected_row_is_reversed_while_navigating() {
        let buffer = rendered_buffer(&model());

        assert!(is_reversed(&buffer, "/ipc/node.socket", 0));
    }

    #[test]
    fn only_the_character_under_the_cursor_is_reversed_while_editing() {
        let mut model = model();
        model.update(Action::Edit);
        model.update(Action::Left);
        model.update(Action::Left);

        let buffer = rendered_buffer(&model);

        // "/ipc/node.socket": the cursor is on the 'e' (offset 14)
        assert!(!is_reversed(&buffer, "/ipc/node.socket", 13));
        assert!(is_reversed(&buffer, "/ipc/node.socket", 14));
        assert!(!is_reversed(&buffer, "/ipc/node.socket", 15));
    }

    #[test]
    fn cursor_at_the_end_add_an_empty_reversed_cell_after_the_value() {
        let mut model = model();
        model.update(Action::Edit);

        let buffer = rendered_buffer(&model);

        assert!(!is_reversed(&buffer, "/ipc/node.socket", 15));
        assert!(is_reversed(&buffer, "/ipc/node.socket", 16));
    }
}
