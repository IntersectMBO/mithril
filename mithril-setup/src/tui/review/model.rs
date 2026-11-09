//! Pure model of the review table

use crate::schema::{FieldError, FieldSpec};
use crate::store::{Origin, Store};

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
}

impl ReviewModel {
    /// Create a model reviewing the store values described by the specs
    pub fn new(specs: Vec<FieldSpec>, store: Store, errors: Vec<FieldError>) -> Self {
        Self {
            specs,
            store,
            errors,
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
}
