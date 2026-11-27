//! Popup listing the fields in error, opened when confirming values in error

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, ListState, StatefulWidget, Widget};

use crate::tui::review::model::Row;
use crate::tui::widgets::WrappedText;

/// Width of the popup, in percent of the area it is drawn over
const WIDTH_PERCENT: u16 = 80;
/// Height of the popup top and bottom borders
const BORDERS_HEIGHT: u16 = 2;
/// Width of the popup left and right borders
const BORDERS_WIDTH: u16 = 2;
/// Symbol in front of the chosen field
const HIGHLIGHT_SYMBOL: &str = "> ";

/// Popup listing the fields in error with their errors, centered over the area it is drawn in
pub struct ErrorsPopup<'a> {
    /// Rows in error, in rows order
    pub rows: Vec<&'a Row>,

    /// Position of the chosen field in the rows
    pub selected: usize,
}

impl ErrorsPopup<'_> {
    /// Title of the popup, with the number of fields in error
    fn title(&self) -> String {
        match self.rows.len() {
            1 => " 1 value to fix ".to_string(),
            count => format!(" {count} values to fix "),
        }
    }

    /// One item per field, its label and errors going on more lines when they don't fit
    fn items(&self, width: usize) -> Vec<ListItem<'static>> {
        self.rows
            .iter()
            .map(|row| {
                let text = format!("{}: {}", row.label, row.errors.join("; "));
                let lines: Vec<Line> = WrappedText::words(&text)
                    .lines(width)
                    .into_iter()
                    .map(Line::from)
                    .collect();
                ListItem::new(lines)
            })
            .collect()
    }
}

impl Widget for ErrorsPopup<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let [popup_area] = Layout::horizontal([Constraint::Percentage(WIDTH_PERCENT)])
            .flex(Flex::Center)
            .areas(area);
        let highlight_width = Span::raw(HIGHLIGHT_SYMBOL).width() as u16;
        let text_width = popup_area.width.saturating_sub(BORDERS_WIDTH + highlight_width);

        let items = self.items(text_width.into());
        // Taller than the area, the popup takes its height and the list scrolls to the chosen field
        let height = BORDERS_HEIGHT + items.iter().map(ListItem::height).sum::<usize>() as u16;
        let [popup_area] = Layout::vertical([Constraint::Length(height)])
            .flex(Flex::Center)
            .areas(popup_area);

        let list = List::new(items)
            .block(Block::bordered().title(self.title()).border_style(Style::new().red()))
            .highlight_symbol(HIGHLIGHT_SYMBOL)
            .highlight_style(Style::new().reversed());
        let mut list_state = ListState::default().with_selected(Some(self.selected));

        // The table under the popup is cleared first, so it doesn't show through
        Clear.render(popup_area, buf);
        StatefulWidget::render(list, popup_area, buf, &mut list_state);
    }
}
