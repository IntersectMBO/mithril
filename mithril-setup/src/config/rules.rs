//! Field rules: small, pure and composable checks of a single raw value

use std::sync::Arc;

/// Check of a single raw value, returns the reason of the rejection
pub type FieldRule = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// Maximum number of characters of a value quoted in a rejection reason
///
/// Same as the review table value column, so the aggregator endpoints (up to 69 characters) are
/// quoted whole.
const QUOTED_VALUE_MAX_LENGTH: usize = 70;

/// The value between quotes for a rejection reason, cut with `…` when it is too long
fn quoted(value: &str) -> String {
    if value.chars().count() <= QUOTED_VALUE_MAX_LENGTH {
        return format!("'{value}'");
    }

    let shown: String = value.chars().take(QUOTED_VALUE_MAX_LENGTH - 1).collect();
    format!("'{shown}…'")
}

/// The value is an integer between `min` and `max` (both included)
pub fn integer_between(min: u64, max: u64) -> FieldRule {
    Arc::new(move |value| {
        let integer: u64 = value
            .parse()
            .map_err(|_| format!("{} is not a positive integer", quoted(value)))?;

        if (min..=max).contains(&integer) {
            Ok(())
        } else {
            Err(format!("{integer} is not between {min} and {max}"))
        }
    })
}

/// The value is one of the allowed values
pub fn one_of(allowed: &'static [&'static str]) -> FieldRule {
    Arc::new(move |value| {
        if allowed.contains(&value) {
            Ok(())
        } else {
            Err(format!(
                "{} is not one of: {}",
                quoted(value),
                allowed.join(", ")
            ))
        }
    })
}

/// The value is a syntactically valid path, it may not exist
pub fn valid_path() -> FieldRule {
    Arc::new(|value| {
        if value.is_empty() {
            Err("path is empty".to_string())
        } else if value.contains('\0') {
            Err("path contains a NUL byte".to_string())
        } else {
            Ok(())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    mod quoted {
        use super::*;

        #[test]
        fn value_up_to_the_maximum_length_is_quoted_whole() {
            let value = "x".repeat(QUOTED_VALUE_MAX_LENGTH);

            assert_eq!(format!("'{value}'"), quoted(&value));
        }

        #[test]
        fn value_over_the_maximum_length_is_cut_with_an_ellipsis() {
            let value = "x".repeat(QUOTED_VALUE_MAX_LENGTH + 1);

            let cut = "x".repeat(QUOTED_VALUE_MAX_LENGTH - 1);
            assert_eq!(format!("'{cut}…'"), quoted(&value));
        }

        #[test]
        fn rejection_reasons_quote_the_cut_value() {
            let value = "x".repeat(QUOTED_VALUE_MAX_LENGTH + 1);

            for rule in [integer_between(1, 10), one_of(&["mainnet"])] {
                let reason = rule(&value).unwrap_err();

                assert!(reason.starts_with(&quoted(&value)), "{reason}");
            }
        }
    }

    mod integer_between {
        use super::*;

        #[test]
        fn accepts_integers_within_bounds_included() {
            let rule = integer_between(1, 10);

            assert_eq!(Ok(()), rule("1"));
            assert_eq!(Ok(()), rule("5"));
            assert_eq!(Ok(()), rule("10"));
        }

        #[test]
        fn rejects_integers_out_of_bounds() {
            let rule = integer_between(1, 10);

            assert!(rule("0").is_err());
            assert!(rule("11").is_err());
        }

        #[test]
        fn rejects_non_integers() {
            let rule = integer_between(1, 10);

            assert!(rule("").is_err());
            assert!(rule("abc").is_err());
            assert!(rule("-1").is_err());
            assert!(rule("1.5").is_err());
        }
    }

    mod one_of {
        use super::*;

        #[test]
        fn accepts_allowed_values() {
            let rule = one_of(&["mainnet", "preprod"]);

            assert_eq!(Ok(()), rule("mainnet"));
            assert_eq!(Ok(()), rule("preprod"));
        }

        #[test]
        fn rejects_other_values() {
            let rule = one_of(&["mainnet", "preprod"]);

            assert!(rule("preview").is_err());
            assert!(rule("").is_err());
        }
    }

    mod valid_path {
        use super::*;

        #[test]
        fn accepts_absolute_and_relative_paths_even_if_they_do_not_exist() {
            let rule = valid_path();

            assert_eq!(Ok(()), rule("/does/not/exist/node.socket"));
            assert_eq!(Ok(()), rule("relative/path"));
        }

        #[test]
        fn rejects_empty_path() {
            assert!(valid_path()("").is_err());
        }

        #[test]
        fn rejects_path_with_nul_byte() {
            assert!(valid_path()("/tmp/a\0b").is_err());
        }
    }
}
