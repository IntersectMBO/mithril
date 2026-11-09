//! Store

use std::collections::BTreeMap;

/// Where a configuration value comes from
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Read from the environment
    Discovered,

    /// Deduced from other values
    Guessed,

    /// Entered by the user
    User,
}

/// A configuration value with its origin
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Raw value
    pub value: String,

    /// Where the value comes from
    pub origin: Origin,
}

/// Configuration values indexed by key, an absent key means the value is unset
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Store {
    entries: BTreeMap<String, Entry>,
}

impl Store {
    /// Get the entry of the given key, if set
    pub fn get(&self, key: &str) -> Option<&Entry> {
        self.entries.get(key)
    }

    /// Set the value of the given key with its origin, replacing any previous entry
    pub fn set(&mut self, key: &str, value: &str, origin: Origin) {
        self.entries.insert(
            key.to_string(),
            Entry {
                value: value.to_string(),
                origin,
            },
        );
    }

    /// Unset the value of the given key
    pub fn unset(&mut self, key: &str) {
        self.entries.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_none_when_key_is_unset() {
        let store = Store::default();

        assert_eq!(None, store.get("network"));
    }

    #[test]
    fn get_returns_the_entry_previously_set() {
        let mut store = Store::default();

        store.set("network", "preview", Origin::Guessed);

        assert_eq!(
            Some(&Entry {
                value: "preview".to_string(),
                origin: Origin::Guessed
            }),
            store.get("network")
        );
    }

    #[test]
    fn set_replaces_the_previous_entry() {
        let mut store = Store::default();
        store.set("network", "preview", Origin::Guessed);

        store.set("network", "preprod", Origin::User);

        assert_eq!(
            Some(&Entry {
                value: "preprod".to_string(),
                origin: Origin::User
            }),
            store.get("network")
        );
    }

    #[test]
    fn unset_removes_the_entry() {
        let mut store = Store::default();
        store.set("network", "preview", Origin::Guessed);

        store.unset("network");

        assert_eq!(None, store.get("network"));
    }

    #[test]
    fn unset_an_absent_key_does_nothing() {
        let mut store = Store::default();

        store.unset("network");

        assert_eq!(Store::default(), store);
    }
}
