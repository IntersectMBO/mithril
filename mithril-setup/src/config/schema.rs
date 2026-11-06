//! Schema: static description of the configuration values expected by a setup

use crate::rules::FieldRule;

/// Description of a configuration value
#[derive(Clone)]
pub struct FieldSpec {
    /// Key of the value in the store
    pub key: &'static str,

    /// Short name displayed to the user
    pub label: &'static str,

    /// Help text displayed to the user
    pub description: &'static str,

    /// Whether the value must be set
    pub presence: Presence,

    /// Rules the value must follow when set
    pub rules: Vec<FieldRule>,
}

/// Whether a configuration value must be set
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// The value must be set
    Required,

    /// The value may be unset
    Optional,
}

impl FieldSpec {
    /// Check the given value against the spec, returns all the errors found
    pub fn check(&self, value: Option<&str>) -> Result<(), Vec<String>> {
        let errors: Vec<String> = match value {
            None => match self.presence {
                Presence::Required => vec![format!("{} is required", self.label)],
                Presence::Optional => vec![],
            },
            Some(value) => self.rules.iter().filter_map(|rule| rule(value).err()).collect(),
        };

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn spec(presence: Presence, rules: Vec<FieldRule>) -> FieldSpec {
        FieldSpec {
            key: "key",
            label: "Label",
            description: "Description",
            presence,
            rules,
        }
    }

    fn failing_rule(reason: &'static str) -> FieldRule {
        Arc::new(|_| Err(reason.to_string()))
    }

    fn passing_rule() -> FieldRule {
        Arc::new(|_| Ok(()))
    }

    #[test]
    fn unset_required_value_is_rejected() {
        let result = spec(Presence::Required, vec![]).check(None);

        assert_eq!(Err(vec!["Label is required".to_string()]), result);
    }

    #[test]
    fn unset_optional_value_is_accepted_without_running_rules() {
        let result = spec(Presence::Optional, vec![failing_rule("boom")]).check(None);

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn set_value_is_accepted_when_all_rules_pass() {
        let result =
            spec(Presence::Required, vec![passing_rule(), passing_rule()]).check(Some("value"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn set_value_is_rejected_with_the_errors_of_all_failing_rules() {
        let result = spec(
            Presence::Required,
            vec![failing_rule("first"), passing_rule(), failing_rule("second")],
        )
        .check(Some("value"));

        assert_eq!(Err(vec!["first".to_string(), "second".to_string()]), result);
    }
}
