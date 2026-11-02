//! Store module

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
    /// The filed is filled with default value
    Default,
    /// The field is discovered from the environment
    Discovered,
    /// The field is guessed from other fields
    Guessed,
    /// The field is filled by the user
    FilledByUser,
}

/// Representation of a field in the store
#[derive(Debug, Clone, PartialEq, Eq)]
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
        }
    }
}

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
}

#[cfg(test)]
mod test {
    use super::*;

    mod field {
        use super::*;

        #[test]
        fn test_field_are_initialized_at_unset_state() {
            let field = Field::init(
                "network".to_string(),
                "The Cardano network to target".to_string(),
                FieldType::String,
                Some("preview".to_string()),
            );
            assert_eq!(field.state, FieldState::Unset);
        }
    }

    mod store {
        use super::*;

        #[test]
        fn test_store_can_get_field_by_name() {
            let field1 = Field::init(
                "network".to_string(),
                "The Cardano network to target".to_string(),
                FieldType::String,
                Some("preview".to_string()),
            );
            let field2 = Field::init(
                "magic_id".to_string(),
                "Magic id of the Cardano network".to_string(),
                FieldType::Int,
                None,
            );
            let store = Store::new(vec![field1, field2]);

            let retrieved_field = store.get_field("network");
            assert!(retrieved_field.is_some());
            assert_eq!(retrieved_field.unwrap().name, "network");

            let non_existent_field = store.get_field("non_existent");
            assert!(non_existent_field.is_none());
        }

        #[test]
        fn test_update_field_update_value_and_state_in_the_store() {
            let field = Field::init(
                "network".to_string(),
                "The Cardano network to target".to_string(),
                FieldType::String,
                Some("preview".to_string()),
            );

            let mut store = Store::new(vec![field]);

            let updated_field = store
                .discover_field("network", "mainnet".to_string())
                .unwrap()
                .get_field("network")
                .unwrap();

            assert_eq!("mainnet".to_string(), updated_field.value.clone().unwrap());
            assert_eq!(FieldState::Discovered, updated_field.state);
        }

        #[test]
        fn test_is_all_fields_filled_returns_true_when_all_fields_are_filled() {
            let field1 = Field::init(
                "network".to_string(),
                "The Cardano network to target".to_string(),
                FieldType::String,
                Some("preview".to_string()),
            );
            let field2 = Field::init(
                "magic_id".to_string(),
                "Magic id of the Cardano network".to_string(),
                FieldType::Int,
                None,
            );
            let mut store = Store::new(vec![field1, field2]);
            assert!(!store.is_all_fields_filled());

            store.user_update_field("network", "mainnet".to_string()).unwrap();
            store.user_update_field("magic_id", "42".to_string()).unwrap();
            assert!(store.is_all_fields_filled());
        }
    }
}
