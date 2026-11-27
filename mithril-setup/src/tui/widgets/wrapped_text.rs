//! Text put on several lines when it doesn't fit a width

/// Separator between two key help items on the same line
pub const KEY_HELP_SEPARATOR: &str = " · ";

/// Text made of pieces (words, key help items) to put on lines of a given width
pub struct WrappedText<'a> {
    pieces: Vec<&'a str>,
    separator: &'static str,
}

impl<'a> WrappedText<'a> {
    /// Words of the text, separated by spaces
    pub fn words(text: &'a str) -> Self {
        Self {
            pieces: text.split(' ').collect(),
            separator: " ",
        }
    }

    /// Items of a key help, separated by ` · `
    pub fn key_help(items: &[&'a str]) -> Self {
        Self {
            pieces: items.to_vec(),
            separator: KEY_HELP_SEPARATOR,
        }
    }

    /// Lines of the text in the given width, at least one (empty for an empty text)
    ///
    /// A piece that doesn't fit on a line goes on the next one, a piece longer than the width is
    /// cut over several lines.
    pub fn lines(&self, width: usize) -> Vec<String> {
        let width = width.max(1);
        let mut lines: Vec<String> = vec![];

        let separator_length = self.separator.chars().count();

        for piece in &self.pieces {
            let piece_length = piece.chars().count();

            match lines.last_mut() {
                Some(line) if line.chars().count() + separator_length + piece_length <= width => {
                    line.push_str(self.separator);
                    line.push_str(piece);
                }
                _ => {
                    let chars: Vec<char> = piece.chars().collect();
                    lines.extend(chars.chunks(width).map(String::from_iter));
                }
            }
        }

        if lines.is_empty() {
            lines.push(String::new());
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_help() -> WrappedText<'static> {
        WrappedText::key_help(&["aaa", "bbb", "ccc"])
    }

    #[test]
    fn pieces_fitting_in_the_width_are_on_one_line() {
        assert_eq!(vec!["aaa · bbb · ccc"], key_help().lines(15));
        assert_eq!(
            vec!["aaa bbb ccc"],
            WrappedText::words("aaa bbb ccc").lines(11)
        );
    }

    #[test]
    fn piece_not_fitting_in_the_width_goes_on_the_next_line() {
        assert_eq!(vec!["aaa · bbb", "ccc"], key_help().lines(14));
        assert_eq!(vec!["aaa", "bbb", "ccc"], key_help().lines(8));
        assert_eq!(
            vec!["aaa bbb", "ccc"],
            WrappedText::words("aaa bbb ccc").lines(10)
        );
    }

    #[test]
    fn piece_longer_than_the_width_is_cut_over_several_lines() {
        assert_eq!(
            vec!["aa", "abbbbb", "bb c"],
            WrappedText::words("aa abbbbbbb c").lines(6)
        );
    }

    #[test]
    fn empty_text_takes_one_empty_line() {
        assert_eq!(vec![""], WrappedText::words("").lines(10));
    }
}
