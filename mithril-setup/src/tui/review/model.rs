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

    /// Type a character in the edited value
    Input(char),

    /// Remove the last character of the edited value
    Backspace,

    /// Save the edited value
    Save,

    /// Cancel the edition, discarding the edited value
    Cancel,
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
        match (&mut self.mode, action) {
            (Mode::Navigating, Action::Up) => self.selected = self.selected.saturating_sub(1),
            (Mode::Navigating, Action::Down) => {
                if self.selected + 1 < self.specs.len() {
                    self.selected += 1;
                }
            }
            (Mode::Navigating, Action::Edit) => {
                if let Some(spec) = self.specs.get(self.selected) {
                    let buffer = self
                        .store
                        .get(spec.key)
                        .map(|entry| entry.value.clone())
                        .unwrap_or_default();
                    self.mode = Mode::Editing { buffer };
                }
            }
            (Mode::Editing { buffer }, Action::Input(character)) => buffer.push(character),
            (Mode::Editing { buffer }, Action::Backspace) => {
                buffer.pop();
            }
            (Mode::Editing { buffer }, Action::Save) => {
                let value = std::mem::take(buffer);
                self.save_selected_value(&value);
                self.mode = Mode::Navigating;
            }
            (Mode::Editing { .. }, Action::Cancel) => self.mode = Mode::Navigating,
            _ => {}
        }

        None
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

        fn editing(buffer: &str) -> Mode {
            Mode::Editing {
                buffer: buffer.to_string(),
            }
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
    }
}
