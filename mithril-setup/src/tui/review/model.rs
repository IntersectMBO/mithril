//! Pure model of the review table

use crate::runner::ReviewOutcome;
use crate::schema::{FieldError, FieldSpec};
use crate::store::{Origin, Store};

/// Actions the user can perform on the review table
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Select the previous row
    Up,

    /// Select the next row
    Down,

    /// Start editing the selected row
    Edit,

    /// Type a character at the cursor
    Input(char),

    /// Remove the character before the cursor
    Backspace,

    /// Remove the character under the cursor
    Delete,

    /// Remove the word before the cursor
    DeleteWordBackward,

    /// Remove the word after the cursor
    DeleteWordForward,

    /// Move the cursor one character to the left
    Left,

    /// Move the cursor one character to the right
    Right,

    /// Move the cursor to the start of the edited value
    Home,

    /// Move the cursor to the end of the edited value
    End,

    /// Save the edited value
    Save,

    /// Cancel the edition, discarding the edited value
    Cancel,

    /// Confirm the reviewed values, ending the review
    Confirm,

    /// Abort the review
    Abort,
}

/// Interaction mode of the review table
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Moving between rows
    Navigating,

    /// Editing the value of the selected row
    Editing {
        /// Value being edited
        buffer: String,

        /// Position of the cursor in the buffer, in characters
        cursor: usize,
    },
}

/// A row of the review table
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Key of the value in the store
    pub key: &'static str,

    /// Short name of the value
    pub label: &'static str,

    /// Help text of the value
    pub description: &'static str,

    /// Raw value, if set
    pub value: Option<String>,

    /// Where the value comes from, if set
    pub origin: Option<Origin>,

    /// Errors found on the value
    pub errors: Vec<String>,
}

/// Model of the review table
pub struct ReviewModel {
    specs: Vec<FieldSpec>,
    store: Store,
    errors: Vec<FieldError>,
    selected: usize,
    mode: Mode,
}

impl ReviewModel {
    /// Create a model reviewing the store values described by the specs
    pub fn new(specs: Vec<FieldSpec>, store: Store, errors: Vec<FieldError>) -> Self {
        Self {
            specs,
            store,
            errors,
            selected: 0,
            mode: Mode::Navigating,
        }
    }

    /// Current interaction mode
    pub fn mode(&self) -> &Mode {
        &self.mode
    }

    /// Index of the selected row
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Apply the action, returns the outcome when the review is over
    pub fn update(&mut self, action: Action) -> Option<ReviewOutcome> {
        if action == Action::Abort {
            return Some(ReviewOutcome::Aborted);
        }

        match self.mode {
            Mode::Navigating => self.update_navigating(action),
            Mode::Editing { .. } => {
                self.update_editing(action);
                None
            }
        }
    }

    fn update_navigating(&mut self, action: Action) -> Option<ReviewOutcome> {
        match action {
            Action::Up if self.selected > 0 => self.selected -= 1,
            Action::Down if self.selected + 1 < self.specs.len() => self.selected += 1,
            Action::Edit => self.start_editing_selected_value(),
            Action::Confirm => return Some(ReviewOutcome::Confirmed(self.store.clone())),
            _ => {}
        }

        None
    }

    fn update_editing(&mut self, action: Action) {
        let Mode::Editing { buffer, cursor } = &mut self.mode else {
            return;
        };

        match action {
            Action::Save => {
                let value = std::mem::take(buffer);
                self.save_selected_value(&value);
                self.mode = Mode::Navigating;
            }
            Action::Cancel => self.mode = Mode::Navigating,
            action => edit_buffer(buffer, cursor, action),
        }
    }

    /// Start editing the value of the selected row, with the cursor at its end
    fn start_editing_selected_value(&mut self) {
        if let Some(spec) = self.specs.get(self.selected) {
            let buffer = self
                .store
                .get(spec.key)
                .map(|entry| entry.value.clone())
                .unwrap_or_default();
            let cursor = buffer.chars().count();
            self.mode = Mode::Editing { buffer, cursor };
        }
    }

    /// Set (or unset if empty) the value of the selected row and re-check it
    fn save_selected_value(&mut self, value: &str) {
        let Some(spec) = self.specs.get(self.selected) else {
            return;
        };

        if value.is_empty() {
            self.store.unset(spec.key);
        } else {
            self.store.set(spec.key, value, Origin::User);
        }

        self.errors.retain(|error| error.key != spec.key);
        let value = self.store.get(spec.key).map(|entry| entry.value.as_str());
        if let Err(errors) = spec.check(value) {
            self.errors.extend(errors);
        }
    }

    /// Rows of the table, one per spec in specs order
    pub fn rows(&self) -> Vec<Row> {
        self.specs
            .iter()
            .map(|spec| {
                let entry = self.store.get(spec.key);
                Row {
                    key: spec.key,
                    label: spec.label,
                    description: spec.description,
                    value: entry.map(|entry| entry.value.clone()),
                    origin: entry.map(|entry| entry.origin),
                    errors: self
                        .errors
                        .iter()
                        .filter(|error| error.key == spec.key)
                        .map(|error| error.message.clone())
                        .collect(),
                }
            })
            .collect()
    }
}

/// Apply a text editing action to the buffer and its cursor, other actions are ignored
fn edit_buffer(buffer: &mut String, cursor: &mut usize, action: Action) {
    let length = buffer.chars().count();

    match action {
        Action::Input(character) => {
            buffer.insert(byte_index(buffer, *cursor), character);
            *cursor += 1;
        }
        Action::Backspace if *cursor > 0 => {
            *cursor -= 1;
            buffer.remove(byte_index(buffer, *cursor));
        }
        Action::Delete if *cursor < length => {
            buffer.remove(byte_index(buffer, *cursor));
        }
        Action::DeleteWordBackward => {
            let start = previous_word_start(buffer, *cursor);
            buffer.replace_range(byte_index(buffer, start)..byte_index(buffer, *cursor), "");
            *cursor = start;
        }
        Action::DeleteWordForward => {
            let end = next_word_end(buffer, *cursor);
            buffer.replace_range(byte_index(buffer, *cursor)..byte_index(buffer, end), "");
        }
        Action::Left if *cursor > 0 => *cursor -= 1,
        Action::Right if *cursor < length => *cursor += 1,
        Action::Home => *cursor = 0,
        Action::End => *cursor = length,
        _ => {}
    }
}

/// Position of the start of the word before the cursor
fn previous_word_start(buffer: &str, cursor: usize) -> usize {
    cursor - word_length(buffer[..byte_index(buffer, cursor)].chars().rev())
}

/// Position of the end of the word after the cursor
fn next_word_end(buffer: &str, cursor: usize) -> usize {
    cursor + word_length(buffer.chars().skip(cursor))
}

/// Number of characters of the first word of `chars`
///
/// Like in the fish shell, a word is a run of characters of the same kind: either alphanumeric
/// characters or separators (non-alphanumeric characters), e.g. `/abc//test` is made of the
/// words `/`, `abc`, `//` and `test`.
fn word_length(chars: impl Iterator<Item = char>) -> usize {
    let mut chars = chars.peekable();
    let Some(is_alphanumeric) = chars.peek().map(|c| c.is_alphanumeric()) else {
        return 0;
    };

    chars.take_while(|c| c.is_alphanumeric() == is_alphanumeric).count()
}

/// Byte index in the buffer of the character at the given position, or the buffer length past its end
fn byte_index(buffer: &str, position: usize) -> usize {
    buffer
        .char_indices()
        .nth(position)
        .map(|(index, _)| index)
        .unwrap_or(buffer.len())
}

#[cfg(test)]
mod tests {
    use crate::schema::Presence;

    use super::*;

    fn spec(key: &'static str, label: &'static str) -> FieldSpec {
        FieldSpec {
            key,
            label,
            description: "description",
            presence: Presence::Required,
            rules: vec![],
        }
    }

    #[test]
    fn rows_follow_specs_order_with_store_values_and_errors() {
        let mut store = Store::default();
        store.set("b", "value b", Origin::Discovered);
        let errors = vec![
            FieldError::new("a", "a is required"),
            FieldError::new("b", "first"),
            FieldError::new("b", "second"),
        ];

        let model = ReviewModel::new(vec![spec("a", "A"), spec("b", "B")], store, errors);

        assert_eq!(
            vec![
                Row {
                    key: "a",
                    label: "A",
                    description: "description",
                    value: None,
                    origin: None,
                    errors: vec!["a is required".to_string()],
                },
                Row {
                    key: "b",
                    label: "B",
                    description: "description",
                    value: Some("value b".to_string()),
                    origin: Some(Origin::Discovered),
                    errors: vec!["first".to_string(), "second".to_string()],
                },
            ],
            model.rows()
        );
    }

    mod helpers {
        use super::*;

        #[test]
        fn byte_index_of_a_position() {
            assert_eq!(0, byte_index("aéb", 0));
            assert_eq!(1, byte_index("aéb", 1));
            // 'é' takes two bytes
            assert_eq!(3, byte_index("aéb", 2));
        }

        #[test]
        fn byte_index_past_the_end_is_the_buffer_length() {
            assert_eq!(3, byte_index("aeb", 3));
            assert_eq!(3, byte_index("aeb", 10));
        }

        #[test]
        fn word_length_counts_the_first_run_of_characters_of_the_same_kind() {
            assert_eq!(0, word_length("".chars()));
            assert_eq!(3, word_length("ipc/node".chars()));
            assert_eq!(1, word_length("/ipc/node".chars()));
            assert_eq!(2, word_length("//ipc/node".chars()));
            assert_eq!(2, word_length("//".chars()));
            assert_eq!(3, word_length("été/".chars()));
        }

        #[test]
        fn previous_word_start_of_a_cursor() {
            assert_eq!(0, previous_word_start("/ipc/node", 0));
            assert_eq!(5, previous_word_start("/ipc/node", 9));
            assert_eq!(4, previous_word_start("/ipc/node", 5));
            assert_eq!(1, previous_word_start("/ipc/node", 3));
        }

        #[test]
        fn next_word_end_of_a_cursor() {
            assert_eq!(9, next_word_end("/ipc/node", 9));
            assert_eq!(1, next_word_end("/ipc/node", 0));
            assert_eq!(5, next_word_end("/ipc/node", 4));
            assert_eq!(4, next_word_end("/ipc/node", 2));
        }
    }

    mod navigation {
        use super::*;

        fn model_with_three_rows() -> ReviewModel {
            ReviewModel::new(
                vec![spec("a", "A"), spec("b", "B"), spec("c", "C")],
                Store::default(),
                vec![],
            )
        }

        #[test]
        fn first_row_is_selected_at_start() {
            assert_eq!(0, model_with_three_rows().selected());
        }

        #[test]
        fn down_selects_the_next_row() {
            let mut model = model_with_three_rows();

            let outcome = model.update(Action::Down);

            assert_eq!(None, outcome);
            assert_eq!(1, model.selected());
        }

        #[test]
        fn down_on_the_last_row_keeps_it_selected() {
            let mut model = model_with_three_rows();
            model.update(Action::Down);
            model.update(Action::Down);

            model.update(Action::Down);

            assert_eq!(2, model.selected());
        }

        #[test]
        fn up_selects_the_previous_row() {
            let mut model = model_with_three_rows();
            model.update(Action::Down);

            let outcome = model.update(Action::Up);

            assert_eq!(None, outcome);
            assert_eq!(0, model.selected());
        }

        #[test]
        fn up_on_the_first_row_keeps_it_selected() {
            let mut model = model_with_three_rows();

            model.update(Action::Up);

            assert_eq!(0, model.selected());
        }
    }

    mod editing {
        use crate::rules::integer_between;

        use super::*;

        fn port_field_spec() -> FieldSpec {
            FieldSpec {
                rules: vec![integer_between(1, 65535)],
                ..spec("port", "Port")
            }
        }

        fn model_with_port(initial_store_value: Option<&str>) -> ReviewModel {
            let mut store = Store::default();
            if let Some(value) = initial_store_value {
                store.set("port", value, Origin::Discovered);
            }

            ReviewModel::new(vec![port_field_spec()], store, vec![])
        }

        /// Editing mode with the cursor at the end of the buffer
        fn editing(buffer: &str) -> Mode {
            editing_at(buffer, buffer.chars().count())
        }

        fn editing_at(buffer: &str, cursor: usize) -> Mode {
            Mode::Editing {
                buffer: buffer.to_string(),
                cursor,
            }
        }

        /// Model editing the given port value
        fn editing_port(value: &str) -> ReviewModel {
            let mut model = model_with_port(Some(value));
            model.update(Action::Edit);
            model
        }

        fn port_row(model: &ReviewModel) -> Row {
            model.rows().remove(0)
        }

        #[test]
        fn navigating_at_start() {
            assert_eq!(&Mode::Navigating, model_with_port(None).mode());
        }

        #[test]
        fn edit_starts_editing_with_the_current_value() {
            let mut model = model_with_port(Some("3000"));

            let outcome = model.update(Action::Edit);

            assert_eq!(None, outcome);
            assert_eq!(&editing("3000"), model.mode());
        }

        #[test]
        fn edit_an_unset_value_starts_with_an_empty_buffer() {
            let mut model = model_with_port(None);

            model.update(Action::Edit);

            assert_eq!(&editing(""), model.mode());
        }

        #[test]
        fn input_and_backspace_change_the_buffer() {
            let mut model = model_with_port(Some("30"));
            model.update(Action::Edit);

            model.update(Action::Input('0'));
            model.update(Action::Input('1'));
            model.update(Action::Backspace);

            assert_eq!(&editing("300"), model.mode());
        }

        #[test]
        fn navigation_is_ignored_while_editing() {
            let mut model = ReviewModel::new(
                vec![spec("a", "A"), spec("b", "B")],
                Store::default(),
                vec![],
            );
            model.update(Action::Edit);

            model.update(Action::Down);

            assert_eq!(0, model.selected());
            assert_eq!(&editing(""), model.mode());
        }

        #[test]
        fn save_sets_the_buffer_as_a_user_value_and_stops_editing() {
            let mut model = model_with_port(Some("3000"));
            model.update(Action::Edit);
            model.update(Action::Input('1'));

            let outcome = model.update(Action::Save);

            assert_eq!(None, outcome);
            assert_eq!(&Mode::Navigating, model.mode());

            let row = port_row(&model);
            assert_eq!(Some("30001".to_string()), row.value);
            assert_eq!(Some(Origin::User), row.origin);
        }

        #[test]
        fn save_an_empty_buffer_unsets_the_value() {
            let mut model = model_with_port(Some("3"));
            model.update(Action::Edit);
            model.update(Action::Backspace);

            model.update(Action::Save);

            let row = port_row(&model);
            assert_eq!(None, row.value);
            assert_eq!(None, row.origin);
        }

        #[test]
        fn save_replaces_the_errors_of_the_field_with_its_check() {
            let mut model = ReviewModel::new(
                vec![port_field_spec()],
                Store::default(),
                vec![FieldError::new("port", "previous error")],
            );
            model.update(Action::Edit);
            model.update(Action::Input('0'));

            model.update(Action::Save);

            assert_eq!(
                vec!["0 is not between 1 and 65535".to_string()],
                port_row(&model).errors
            );
        }

        #[test]
        fn save_a_valid_value_clears_the_errors_of_the_field() {
            let mut model = ReviewModel::new(
                vec![port_field_spec()],
                Store::default(),
                vec![FieldError::new("port", "previous error")],
            );
            model.update(Action::Edit);
            model.update(Action::Input('8'));

            model.update(Action::Save);

            assert_eq!(Vec::<String>::new(), port_row(&model).errors);
        }

        #[test]
        fn cancel_stops_editing_without_changing_the_value() {
            let mut model = model_with_port(Some("3000"));
            model.update(Action::Edit);
            model.update(Action::Input('1'));

            let outcome = model.update(Action::Cancel);

            assert_eq!(None, outcome);
            assert_eq!(&Mode::Navigating, model.mode());

            let row = port_row(&model);
            assert_eq!(Some("3000".to_string()), row.value);
            assert_eq!(Some(Origin::Discovered), row.origin);
        }

        mod words {
            use super::*;

            #[test]
            fn delete_word_backward_removes_the_word_before_the_cursor() {
                let mut model = editing_port("/ipc/node.socket");

                model.update(Action::DeleteWordBackward);

                assert_eq!(&editing_at("/ipc/node.", 10), model.mode());
            }

            #[test]
            fn delete_word_backward_removes_only_the_separators_before_the_cursor() {
                let mut model = editing_port("/abc//");

                model.update(Action::DeleteWordBackward);

                assert_eq!(&editing_at("/abc", 4), model.mode());
            }

            #[test]
            fn delete_word_backward_keeps_the_text_after_the_cursor() {
                let mut model = editing_port("/ipc/node.socket");
                for _ in 0..="socket".len() {
                    model.update(Action::Left);
                }

                model.update(Action::DeleteWordBackward);

                assert_eq!(&editing_at("/ipc/.socket", 5), model.mode());
            }

            #[test]
            fn delete_word_backward_at_the_start_does_nothing() {
                let mut model = editing_port("/ipc");
                model.update(Action::Home);

                model.update(Action::DeleteWordBackward);

                assert_eq!(&editing_at("/ipc", 0), model.mode());
            }

            #[test]
            fn delete_word_forward_removes_the_word_after_the_cursor() {
                let mut model = editing_port("ipc/node");
                model.update(Action::Home);

                model.update(Action::DeleteWordForward);

                assert_eq!(&editing_at("/node", 0), model.mode());
            }

            #[test]
            fn delete_word_forward_removes_only_the_separators_after_the_cursor() {
                let mut model = editing_port("//ipc");
                model.update(Action::Home);

                model.update(Action::DeleteWordForward);

                assert_eq!(&editing_at("ipc", 0), model.mode());
            }

            #[test]
            fn delete_word_forward_keeps_the_text_before_the_cursor() {
                let mut model = editing_port("/ipc/node.socket");
                for _ in 0.."node.socket".len() {
                    model.update(Action::Left);
                }

                model.update(Action::DeleteWordForward);

                assert_eq!(&editing_at("/ipc/.socket", 5), model.mode());
            }

            #[test]
            fn delete_word_forward_at_the_end_does_nothing() {
                let mut model = editing_port("/ipc");

                model.update(Action::DeleteWordForward);

                assert_eq!(&editing_at("/ipc", 4), model.mode());
            }

            #[test]
            fn delete_word_backward_removes_accented_letters_as_part_of_the_word() {
                let mut model = editing_port("/dossier/été2");

                model.update(Action::DeleteWordBackward);

                assert_eq!(&editing_at("/dossier/", 9), model.mode());
            }
        }

        mod cursor {
            use super::*;

            #[test]
            fn left_and_right_move_the_cursor() {
                let mut model = editing_port("abcd");

                model.update(Action::Left);
                model.update(Action::Left);
                assert_eq!(&editing_at("abcd", 2), model.mode());

                model.update(Action::Right);
                assert_eq!(&editing_at("abcd", 3), model.mode());
            }

            #[test]
            fn left_at_the_start_and_right_at_the_end_keep_the_cursor() {
                let mut model = editing_port("ab");

                model.update(Action::Right);
                assert_eq!(&editing_at("ab", 2), model.mode());

                model.update(Action::Home);
                model.update(Action::Left);
                assert_eq!(&editing_at("ab", 0), model.mode());
            }

            #[test]
            fn home_and_end_move_the_cursor_to_the_bounds() {
                let mut model = editing_port("abcd");

                model.update(Action::Home);
                assert_eq!(&editing_at("abcd", 0), model.mode());

                model.update(Action::End);
                assert_eq!(&editing_at("abcd", 4), model.mode());
            }

            #[test]
            fn input_inserts_at_the_cursor() {
                let mut model = editing_port("abcd");
                model.update(Action::Left);
                model.update(Action::Left);

                model.update(Action::Input('X'));

                assert_eq!(&editing_at("abXcd", 3), model.mode());
            }

            #[test]
            fn backspace_removes_the_character_before_the_cursor() {
                let mut model = editing_port("abcd");
                model.update(Action::Left);

                model.update(Action::Backspace);

                assert_eq!(&editing_at("abd", 2), model.mode());
            }

            #[test]
            fn backspace_at_the_start_does_nothing() {
                let mut model = editing_port("ab");
                model.update(Action::Home);

                model.update(Action::Backspace);

                assert_eq!(&editing_at("ab", 0), model.mode());
            }

            #[test]
            fn delete_removes_the_character_under_the_cursor() {
                let mut model = editing_port("abcd");
                model.update(Action::Home);

                model.update(Action::Delete);

                assert_eq!(&editing_at("bcd", 0), model.mode());
            }

            #[test]
            fn delete_at_the_end_does_nothing() {
                let mut model = editing_port("ab");

                model.update(Action::Delete);

                assert_eq!(&editing_at("ab", 2), model.mode());
            }

            #[test]
            fn multibyte_characters_count_as_one_cursor_step() {
                let mut model = editing_port("aéb");
                model.update(Action::Left);

                model.update(Action::Backspace);
                model.update(Action::Input('è'));

                assert_eq!(&editing_at("aèb", 2), model.mode());
            }
        }
    }

    mod ending {
        use super::*;

        fn model() -> ReviewModel {
            let mut store = Store::default();
            store.set("a", "value", Origin::Discovered);

            ReviewModel::new(vec![spec("a", "A")], store, vec![])
        }

        #[test]
        fn confirm_returns_the_reviewed_store() {
            let mut model = model();
            model.update(Action::Edit);
            model.update(Action::Input('!'));
            model.update(Action::Save);

            let outcome = model.update(Action::Confirm);

            let mut expected_store = Store::default();
            expected_store.set("a", "value!", Origin::User);
            assert_eq!(Some(ReviewOutcome::Confirmed(expected_store)), outcome);
        }

        #[test]
        fn confirm_is_ignored_while_editing() {
            let mut model = model();
            model.update(Action::Edit);

            let outcome = model.update(Action::Confirm);

            assert_eq!(None, outcome);
        }

        #[test]
        fn abort_returns_aborted_while_navigating() {
            let outcome = model().update(Action::Abort);

            assert_eq!(Some(ReviewOutcome::Aborted), outcome);
        }

        #[test]
        fn abort_returns_aborted_while_editing() {
            let mut model = model();
            model.update(Action::Edit);

            let outcome = model.update(Action::Abort);

            assert_eq!(Some(ReviewOutcome::Aborted), outcome);
        }
    }
}
