//! Columns of the review table, their widths are counted in characters

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Stylize;
use ratatui::text::{Line, Span};

/// Width of the label column
// Maybe later: compute the label width from the longest label (with a maximum)?
const LABEL_WIDTH: u16 = 28;
/// Maximum width of the value column, fits the aggregator endpoints (up to 69 characters)
pub const VALUE_MAX_WIDTH: u16 = 70;
/// Width of the origin column, fits the longest origin ("Discovered")
const ORIGIN_WIDTH: u16 = 12;
/// Width of the status column, fits the longest status ("Not set", "Missing" and "Invalid")
const STATUS_WIDTH: u16 = 7;
/// Columns of the table: label, value, origin and status
///
/// The value column shrinks first on narrow terminals, the extra width of wide terminals is left
/// empty after the status column, so the origin and status stay next to the value.
pub const COLUMNS: [Constraint; 4] = [
    Constraint::Length(LABEL_WIDTH),
    Constraint::Max(VALUE_MAX_WIDTH),
    Constraint::Length(ORIGIN_WIDTH),
    Constraint::Length(STATUS_WIDTH),
];
/// Space between two columns of the table
pub const COLUMN_SPACING: u16 = 1;
/// Symbol in front of the selected row
pub const HIGHLIGHT_SYMBOL: &str = "> ";

/// Value column of the table, fits the values in its width
pub struct ValueColumn {
    /// Width of the column, in characters (at least one)
    width: usize,
}

impl ValueColumn {
    /// Value column of a table whose columns are drawn in the given area (inside its borders)
    ///
    /// The table does not expose the widths of its columns, they are computed the same way it does:
    /// the highlight symbol first, then the columns in the remaining width.
    pub fn in_table(inner_area: Rect) -> Self {
        let highlight_width = Span::raw(HIGHLIGHT_SYMBOL).width() as u16;
        let columns_area = Rect::new(0, 0, inner_area.width.saturating_sub(highlight_width), 1);
        let [_, value_area, _, _] = Layout::horizontal(COLUMNS)
            .spacing(COLUMN_SPACING)
            .areas(columns_area);

        Self {
            width: usize::from(value_area.width).max(1),
        }
    }

    /// Value cut to the column width, its last shown character is `…` when it doesn't fit
    pub fn value(&self, value: &str) -> Line<'static> {
        if value.chars().count() <= self.width {
            return Line::from(value.to_string());
        }

        let shown: String = value.chars().take(self.width - 1).chain(['…']).collect();
        Line::from(shown)
    }

    /// Edited value with the character under the cursor reversed (a space past the end)
    ///
    /// When the value doesn't fit, its start is hidden so the cursor stays in the column.
    pub fn edited_value(&self, buffer: &str, cursor: usize) -> Line<'static> {
        // First shown character: the cursor is at most on the last cell of the column
        let start = (cursor + 1).saturating_sub(self.width);
        let after_width = self.width - (cursor + 1 - start);

        let before: String = buffer.chars().skip(start).take(cursor - start).collect();
        let current: String = buffer.chars().nth(cursor).unwrap_or(' ').to_string();
        let after: String = buffer.chars().skip(cursor + 1).take(after_width).collect();

        Line::from(vec![
            Span::raw(before),
            Span::raw(current).reversed(),
            Span::raw(after),
        ])
    }
}
