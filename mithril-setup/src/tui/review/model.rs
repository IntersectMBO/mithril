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
}

impl ReviewModel {
    /// Create a model reviewing the store values described by the specs
    pub fn new(specs: Vec<FieldSpec>, store: Store, errors: Vec<FieldError>) -> Self {
        Self {
            specs,
            store,
            errors,
            selected: 0,
        }
    }

    /// Index of the selected row
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Apply the action, returns the outcome when the review is over
    pub fn update(&mut self, action: Action) -> Option<ReviewOutcome> {
        match action {
            Action::Up => self.selected = self.selected.saturating_sub(1),
            Action::Down => {
                if self.selected + 1 < self.specs.len() {
                    self.selected += 1;
                }
            }
        }

        None
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
}
