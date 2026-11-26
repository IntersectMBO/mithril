//! Rendering of the result screen, showing the success or the failure of the setup

use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout};
use ratatui::style::{Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph};

use crate::tui::setup_result::model::{Button, COMMAND_INTRO, ResultModel, SetupResult};
use crate::tui::widgets::{ButtonWidget, WrappedText};

const HELP: &[&str] = &["←/→ choose", "Enter press", "Esc exit"];

/// Title of the box on a success
const SUCCESS_TITLE: &str = " Setup result ";
/// Mark in front of the message, telling the setup succeeded
const SUCCESS_MARK: &str = "✓";
/// Title of the box on a failure
const FAILURE_TITLE: &str = " Setup failed ";
/// Mark in front of the message, telling the setup failed
const FAILURE_MARK: &str = "✗";

// Layout sizes are counted in terminal cells: rows for heights, characters for widths
/// Minimum height of the content, it takes all the remaining rows
const CONTENT_MIN_HEIGHT: u16 = 3;
/// Height of the buttons line
const BUTTONS_HEIGHT: u16 = 1;
/// Space between two buttons
const BUTTONS_SPACING: u16 = 3;
/// Height of the footer top and bottom borders, the height of its lines is added to it
const FOOTER_BORDERS_HEIGHT: u16 = 2;

/// Draw the result of the setup, its buttons and the keys help in the frame
pub fn render(model: &ResultModel, frame: &mut Frame) {
    // The footer takes the full width, its help goes on more lines when it doesn't fit
    let footer_block = Block::bordered();
    let help_lines =
        WrappedText::key_help(HELP).lines(footer_block.inner(frame.area()).width.into());
    let footer_height = FOOTER_BORDERS_HEIGHT + help_lines.len() as u16;

    let [content_area, buttons_area, footer_area] = Layout::vertical([
        Constraint::Min(CONTENT_MIN_HEIGHT),
        Constraint::Length(BUTTONS_HEIGHT),
        Constraint::Length(footer_height),
    ])
    .areas(frame.area());

    let text_area = Block::bordered().inner(content_area);
    let text_width = usize::from(text_area.width);
    let wrapped =
        |text: &str| WrappedText::words(text).lines(text_width).into_iter().map(Line::from);

    let (content_block, text_lines): (Block, Vec<Line>) = match model.setup_result() {
        SetupResult::Success { message, command } => (
            Block::bordered().title(SUCCESS_TITLE),
            wrapped(&format!("{SUCCESS_MARK} {message}"))
                .map(|line| line.green())
                .chain([Line::default()])
                .chain(wrapped(COMMAND_INTRO))
                .chain(wrapped(command).map(|line| line.bold()))
                .collect(),
        ),
        SetupResult::Failure { message, reason } => (
            Block::bordered()
                .title(FAILURE_TITLE)
                .border_style(Style::new().red()),
            wrapped(&format!("{FAILURE_MARK} {message}"))
                .map(|line| line.red())
                .chain([Line::default()])
                .chain(wrapped(reason))
                .collect(),
        ),
    };

    // The text is centered in the box, each line horizontally and all the lines vertically
    let [centered_text_area] = Layout::vertical([Constraint::Length(text_lines.len() as u16)])
        .flex(Flex::Center)
        .areas(text_area);
    frame.render_widget(content_block, content_area);
    frame.render_widget(Paragraph::new(text_lines).centered(), centered_text_area);

    let back_button = ButtonWidget {
        label: "Back",
        focused: model.focused() == Button::Back,
    };
    let exit_button = ButtonWidget {
        label: "Exit",
        focused: model.focused() == Button::Exit,
    };
    // Buttons take their own width and are centered in the line
    let [back_area, exit_area] = Layout::horizontal([
        Constraint::Length(back_button.width()),
        Constraint::Length(exit_button.width()),
    ])
    .flex(Flex::Center)
    .spacing(BUTTONS_SPACING)
    .areas(buttons_area);
    frame.render_widget(back_button, back_area);
    frame.render_widget(exit_button, exit_area);

    let footer_lines: Vec<Line> =
        help_lines.into_iter().map(|line| Line::from(line).dim()).collect();
    frame.render_widget(
        Paragraph::new(footer_lines).block(footer_block),
        footer_area,
    );
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::style::Modifier;

    use crate::tui::setup_result::model::{Action, SetupResult};

    use super::*;

    const COMMAND: &str = "./mithril-signer-setup.sh --env-file ./mithril-signer.env";

    fn setup_result() -> SetupResult {
        SetupResult::Success {
            message: "The setup script is generated",
            command: COMMAND,
        }
    }

    fn model() -> ResultModel {
        ResultModel::new(setup_result())
    }

    fn failure_model() -> ResultModel {
        ResultModel::new(SetupResult::Failure {
            message: "The setup script could not be generated",
            reason: "Could not write the script: permission denied".to_string(),
        })
    }

    fn rendered_buffer(model: &ResultModel, width: u16) -> Buffer {
        let mut terminal = Terminal::new(TestBackend::new(width, 14)).unwrap();
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

    /// Whether the first cell of `text` is drawn reversed
    fn is_reversed(buffer: &Buffer, text: &str) -> bool {
        let (y, line) = lines(buffer)
            .into_iter()
            .enumerate()
            .find(|(_, line)| line.contains(text))
            .unwrap_or_else(|| panic!("'{text}' not found"));
        let x = line[..line.find(text).unwrap()].chars().count();

        buffer[(x as u16, y as u16)].modifier.contains(Modifier::REVERSED)
    }

    #[test]
    fn shows_the_message_the_command_the_buttons_and_the_help() {
        let text = lines(&rendered_buffer(&model(), 100)).join("\n");

        for expected in [
            "✓ The setup script is generated",
            COMMAND_INTRO,
            "./mithril-signer-setup.sh --env-file ./mithril-signer.env",
            "[ Back ]",
            "[ Exit ]",
            "←/→ choose · Enter press · Esc exit",
        ] {
            assert!(
                text.contains(expected),
                "'{expected}' not found in:\n{text}"
            );
        }
    }

    #[test]
    fn failure_shows_the_message_the_reason_and_the_buttons_without_command() {
        let text = lines(&rendered_buffer(&failure_model(), 100)).join("\n");

        for expected in [
            FAILURE_TITLE,
            "✗ The setup script could not be generated",
            "Could not write the script: permission denied",
            "[ Back ]",
            "[ Exit ]",
        ] {
            assert!(
                text.contains(expected),
                "'{expected}' not found in:\n{text}"
            );
        }
        assert!(!text.contains(COMMAND_INTRO), "{text}");
    }

    #[test]
    fn only_the_focused_button_is_reversed() {
        let mut model = model();

        let buffer = rendered_buffer(&model, 100);
        assert!(is_reversed(&buffer, "[ Exit ]"));
        assert!(!is_reversed(&buffer, "[ Back ]"));

        model.update(Action::Left);

        let buffer = rendered_buffer(&model, 100);
        assert!(is_reversed(&buffer, "[ Back ]"));
        assert!(!is_reversed(&buffer, "[ Exit ]"));
    }

    #[test]
    fn command_goes_on_more_lines_on_a_narrow_terminal() {
        // 38 characters inside the borders
        let text = lines(&rendered_buffer(&model(), 40)).join("\n");

        assert!(!text.contains(COMMAND), "{text}");
        assert!(
            text.contains("./mithril-signer-setup.sh --env-file"),
            "{text}"
        );
        assert!(text.contains("./mithril-signer.env"), "{text}");
    }

    /// Empty cells before and after the text of a line drawn inside the box borders
    fn inner_margins(line: &str) -> (usize, usize) {
        let inner: Vec<char> = line.chars().skip(1).take(line.chars().count() - 2).collect();
        let before = inner.iter().take_while(|c| **c == ' ').count();
        let after = inner.iter().rev().take_while(|c| **c == ' ').count();

        (before, after)
    }

    #[test]
    fn each_line_is_centered_horizontally_in_the_box() {
        let lines = lines(&rendered_buffer(&model(), 100));

        for text in ["✓ The setup script is generated", COMMAND_INTRO, COMMAND] {
            let line = lines.iter().find(|line| line.contains(text)).unwrap();
            let (before, after) = inner_margins(line);

            assert!(before.abs_diff(after) <= 1, "'{text}' not centered: {line}");
        }
    }

    #[test]
    fn text_is_centered_vertically_in_the_box() {
        let lines = lines(&rendered_buffer(&model(), 100));
        let top = lines.iter().position(|line| line.starts_with('┌')).unwrap();
        let bottom = lines.iter().position(|line| line.starts_with('└')).unwrap();
        let is_empty = |line: &&String| {
            let (before, _) = inner_margins(line);
            before == line.chars().count() - 2
        };

        let inside = &lines[top + 1..bottom];
        let empty_before = inside.iter().take_while(is_empty).count();
        let empty_after = inside.iter().rev().take_while(is_empty).count();

        assert!(
            empty_before.abs_diff(empty_after) <= 1,
            "{empty_before} empty lines before, {empty_after} after:\n{}",
            lines.join("\n")
        );
        assert!(empty_before > 0, "{}", lines.join("\n"));
    }
}
