//! Button drawn on a single line

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::widgets::Widget;

/// A button drawn as its label between brackets, reversed when focused
pub struct ButtonWidget {
    /// Text of the button
    pub label: &'static str,

    /// Whether the button has the focus
    pub focused: bool,
}

impl ButtonWidget {
    fn line(&self) -> Line<'static> {
        let line = Line::from(format!("[ {} ]", self.label));
        if self.focused { line.reversed() } else { line }
    }

    /// Width of the button, in characters
    pub fn width(&self) -> u16 {
        self.line().width() as u16
    }
}

impl Widget for ButtonWidget {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.line().render(area, buf);
    }
}
