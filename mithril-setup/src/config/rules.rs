//! Field rules: small, pure and composable checks of a single raw value

use std::sync::Arc;

/// Check of a single raw value, returns the reason of the rejection
pub type FieldRule = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// The value is an integer between `min` and `max` (both included)
pub fn integer_between(min: u64, max: u64) -> FieldRule {
    Arc::new(move |value| {
        let integer: u64 = value
            .parse()
            .map_err(|_| format!("'{value}' is not a positive integer"))?;

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
            Err(format!("'{value}' is not one of: {}", allowed.join(", ")))
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
