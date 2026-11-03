//! Store module

/// Compute a field value from the other fields of the store, if possible
pub type GuessFunction = fn(&Store) -> Option<String>;

/// Type of a field
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    /// A string field
    String,
    /// A signed integer field
    Int,
    /// A boolean field
    Bool,
    /// Path to a file
    FilePath,
    /// Path to a existing file
    FilePathToCheck,
}

/// State of a field
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldState {
    /// The field is not set
    Unset,
    /// The field is filled with default value
    Default,
    /// The field is discovered from the environment
    Discovered,
    /// The field is guessed from other fields
    Guessed,
    /// The field is filled by the user
    FilledByUser,
}

/// Representation of a field in the store
#[derive(Debug, Clone)]
pub struct Field {
    /// Name
    pub name: String,

    /// Description
    pub description: String,

    /// Type of the field, for verification
    pub kind: FieldType,

    /// Default value
    pub default: Option<String>,

    /// Value of the field
    pub value: Option<String>,

    /// State of the field
    pub state: FieldState,

    /// A Optionally guess function to compute the value of the field from other fields
    pub guess: Option<GuessFunction>, //TODO redefin PartialEq to ignore this field, or implement a custom PartialEq
}

impl Field {
    /// Create a new field
    pub fn init(
        name: String,
        description: String,
        kind: FieldType,
        default: Option<String>,
    ) -> Self {
        Self {
            name,
            description,
            kind,
            default,
            value: None,
            state: FieldState::Unset,
            guess: None,
        }
    }

    /// Set a guess function for the field
    pub fn guessed_by(mut self, guess: GuessFunction) -> Self {
        self.guess = Some(guess);
        self
    }
}

// `guess` is ignored: function pointer addresses are not reliable for comparison
impl PartialEq for Field {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            name,
            description,
            kind,
            default,
            value,
            state,
            guess: _,
        } = self;

        *name == other.name
            && *description == other.description
            && *kind == other.kind
            && *default == other.default
            && *value == other.value
            && *state == other.state
    }
}

impl Eq for Field {}

/// Representation of the store containing all fields
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Store {
    fields: Vec<Field>,
}

impl Store {
    /// Create a new store with the given fields
    pub fn new(fields: Vec<Field>) -> Self {
        Self { fields }
    }

    /// Get a reference to a field by its name
    pub fn get_field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Update field value and state by its name if it exists
    fn update_field(
        &mut self,
        name: &str,
        value: String,
        state: FieldState,
    ) -> anyhow::Result<&mut Self> {
        let field = self
            .fields
            .iter_mut()
            .find(|field| field.name == name)
            .ok_or_else(|| anyhow::anyhow!("Field '{name}' not found"))?;

        field.value = Some(value);
        field.state = state;

        self.apply_guesses();

        Ok(self)
    }

    /// Update field value and state to Discovered by its name if it exists
    pub fn discover_field(&mut self, name: &str, value: String) -> anyhow::Result<&mut Self> {
        self.update_field(name, value, FieldState::Discovered)
    }

    /// Update field value and state to FilledByUser by its name if it exists
    pub fn user_update_field(&mut self, name: &str, value: String) -> anyhow::Result<&mut Self> {
        self.update_field(name, value, FieldState::FilledByUser)
    }

    /// Check if all fields are filled (not Unset)
    pub fn is_all_fields_filled(&self) -> bool {
        self.fields.iter().all(|field| field.state != FieldState::Unset)
    }

    /// Recompute every guessable field that the user or the discovery did not set
    fn apply_guesses(&mut self) {
        // loop until stable so guesses can chain (network -> magic_id -> ...)
        for _ in 0..self.fields.len() {
            let mut changed = false;
            for i in 0..self.fields.len() {
                let field = &self.fields[i];
                let overridable = matches!(
                    field.state,
                    FieldState::Unset | FieldState::Default | FieldState::Guessed
                );
                let Some(guess) = field.guess.filter(|_| overridable) else {
                    continue;
                };
                if let Some(value) = guess(self)
                    && self.fields[i].value.as_ref() != Some(&value)
                {
                    self.fields[i].value = Some(value);
                    self.fields[i].state = FieldState::Guessed;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    mod field {
        use super::*;

        #[test]
        fn test_field_are_initialized_at_unset_state() {
            let field = Field::init(
                "Color".to_string(),
                "The color".to_string(),
                FieldType::String,
                Some("red".to_string()),
            );
            assert_eq!(field.state, FieldState::Unset);
        }
    }

    mod store {
        use super::*;

        #[test]
        fn test_store_can_get_field_by_name() {
            let field1 = Field::init(
                "color".to_string(),
                "The color".to_string(),
                FieldType::String,
                Some("red".to_string()),
            );
            let field2 = Field::init(
                "shape".to_string(),
                "The shape".to_string(),
                FieldType::Int,
                None,
            );
            let store = Store::new(vec![field1, field2]);

            let retrieved_field = store.get_field("color");
            assert!(retrieved_field.is_some());
            assert_eq!(retrieved_field.unwrap().name, "color");

            let non_existent_field = store.get_field("non_existent");
            assert!(non_existent_field.is_none());
        }

        #[test]
        fn test_update_field_update_value_and_state_in_the_store() {
            let field = Field::init(
                "color".to_string(),
                "The color".to_string(),
                FieldType::String,
                Some("red".to_string()),
            );

            let mut store = Store::new(vec![field]);

            let updated_field = store
                .discover_field("color", "blue".to_string())
                .unwrap()
                .get_field("color")
                .unwrap();

            assert_eq!("blue".to_string(), updated_field.value.clone().unwrap());
            assert_eq!(FieldState::Discovered, updated_field.state);
        }

        #[test]
        fn test_is_all_fields_filled_returns_true_when_all_fields_are_filled() {
            let field1 = Field::init(
                "color".to_string(),
                "The color".to_string(),
                FieldType::String,
                Some("red".to_string()),
            );
            let field2 = Field::init(
                "shape".to_string(),
                "The shape".to_string(),
                FieldType::Int,
                None,
            );
            let mut store = Store::new(vec![field1, field2]);
            assert!(!store.is_all_fields_filled());

            store.user_update_field("color", "blue".to_string()).unwrap();
            store.user_update_field("shape", "square".to_string()).unwrap();
            assert!(store.is_all_fields_filled());
        }
    }

    mod guessing {
        use super::*;

        fn guess_parent_colors(store: &Store) -> Option<String> {
            match store.get_field("color").and_then(|field| field.value.as_deref()) {
                Some("purple") => Some("red and blue".to_string()),
                Some("orange") => Some("red and yellow".to_string()),
                Some("green") => Some("blue and yellow".to_string()),
                _ => None,
            }
        }

        #[test]
        fn test_apply_guesses() {
            let field1 = Field::init(
                "color".to_string(),
                "The color".to_string(),
                FieldType::String,
                Some("red".to_string()),
            );

            let field2 = Field::init(
                "parent colors".to_string(),
                "the parent colors".to_string(),
                FieldType::String,
                None,
            )
            .guessed_by(guess_parent_colors);

            let mut store = Store::new(vec![field1, field2]);

            // Check that the parent colors field was guessed correctly
            assert_eq!(store.get_field("parent colors").unwrap().value, None);

            // Update the color field to trigger the guess for parent colors
            store.user_update_field("color", "purple".to_string()).unwrap();

            // Check that the parent colors field was guessed correctly
            assert_eq!(
                store.get_field("parent colors").unwrap().value,
                Some("red and blue".to_string())
            );
        }
    }
}
