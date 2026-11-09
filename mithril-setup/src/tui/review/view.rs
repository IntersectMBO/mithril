//! Rendering of the review table

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph, Row, Table, TableState};

use crate::tui::review::model::{Mode, ReviewModel};

const NAVIGATING_HELP: &str = "↑/↓ move · Enter edit · Ctrl+S confirm · Esc/Ctrl+C abort";
const EDITING_HELP: &str = "Enter save · Esc cancel · Ctrl+C abort";
const CURSOR: &str = "▏";

// Layout sizes are counted in terminal cells: rows for heights, characters for widths
/// Minimum height of the table, it takes all the remaining rows
const TABLE_MIN_HEIGHT: u16 = 3;
/// Height of the footer: description and help lines, plus top and bottom borders
const FOOTER_HEIGHT: u16 = 4;
/// Width of the label column
// Maybe later: compute the label width from the longest label (with a maximum)?
const LABEL_WIDTH: u16 = 28;
/// Width of the origin column, fits the longest origin ("Discovered")
const ORIGIN_WIDTH: u16 = 12;

/// Draw the review table and its footer in the frame
pub fn render(model: &ReviewModel, frame: &mut Frame) {
    let [table_area, footer_area] =
        Layout::vertical([Constraint::Min(TABLE_MIN_HEIGHT), Constraint::Length(FOOTER_HEIGHT)])
            .areas(frame.area());

    let model_rows = model.rows();

    let table_rows = model_rows.iter().enumerate().map(|(index, row)| {
        let value = match model.mode() {
            Mode::Editing { buffer } if index == model.selected() => format!("{buffer}{CURSOR}"),
            _ => row.value.clone().unwrap_or_default(),
        };
        let origin = row.origin.map(|origin| format!("{origin:?}")).unwrap_or_default();

        Row::new(vec![
            row.label.to_string(),
            value,
            origin,
            row.errors.join("; "),
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
    .row_highlight_style(Style::new().reversed())
    .highlight_symbol("> ");

    let mut table_state = TableState::default().with_selected(Some(model.selected()));
    frame.render_stateful_widget(table, table_area, &mut table_state);

    let description = model_rows
        .get(model.selected())
        .map(|row| row.description)
        .unwrap_or_default();
    let help = match model.mode() {
        Mode::Navigating => NAVIGATING_HELP,
        Mode::Editing { .. } => EDITING_HELP,
    };
    let footer = Paragraph::new(vec![Line::from(description), Line::from(help).dim()])
        .block(Block::bordered());
    frame.render_widget(footer, footer_area);
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

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

    /// Render the model and return the drawn text, one line per terminal row
    fn rendered_text(model: &ReviewModel) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 12)).unwrap();
        terminal.draw(|frame| render(model, frame)).unwrap();

        let buffer = terminal.backend().buffer();
        let width = buffer.area.width as usize;
        buffer
            .content()
            .chunks(width)
            .map(|line| line.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
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
    fn shows_the_edited_buffer_with_a_cursor() {
        let mut model = model();
        model.update(Action::Edit);

        let text = rendered_text(&model);

        assert!(
            text.contains(&format!("/ipc/node.socket{CURSOR}")),
            "{text}"
        );
    }
}
