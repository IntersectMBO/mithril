//! Field rules: small, pure and composable checks of a single raw value

use std::net::IpAddr;
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
    Arc::new(move |value| match value.parse::<u64>() {
        Ok(integer) if (min..=max).contains(&integer) => Ok(()),
        _ => Err(format!(
            "{} is not an integer between {min} and {max} (maximum value accepted)",
            quoted(value)
        )),
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
            Err(format!("{} is an empty path", quoted(value)))
        } else if value.contains('\0') {
            Err(format!("{} contains a NUL byte", quoted(value)))
        } else {
            Ok(())
        }
    })
}

/// The value is an absolute Unix path, it may not exist
///
/// The configuration is for a Unix machine, the check doesn't depend on the platform running it.
pub fn absolute_path() -> FieldRule {
    Arc::new(|value| {
        if value.starts_with('/') {
            Ok(())
        } else {
            Err(format!("{} is not an absolute path", quoted(value)))
        }
    })
}

/// The value has no whitespace, it would need quoting in the generated configuration
pub fn no_whitespace() -> FieldRule {
    Arc::new(|value| {
        if value.contains(char::is_whitespace) {
            Err(format!("{} contains whitespace", quoted(value)))
        } else {
            Ok(())
        }
    })
}

/// The value is an HTTP or HTTPS URL with a host, e.g. `https://example.com/path`
pub fn http_url() -> FieldRule {
    Arc::new(|value| {
        let after_scheme = value
            .strip_prefix("https://")
            .or_else(|| value.strip_prefix("http://"));

        match after_scheme {
            Some(rest) if !rest.is_empty() && !rest.starts_with('/') => Ok(()),
            _ => Err(format!("{} is not an http(s) URL", quoted(value))),
        }
    })
}

/// The value is an IPv4 or IPv6 address, e.g. `0.0.0.0` or `::1`, not a host name
pub fn ip_address() -> FieldRule {
    Arc::new(|value| match value.parse::<IpAddr>() {
        Ok(_) => Ok(()),
        Err(_) => Err(format!("{} is not an IP address", quoted(value))),
    })
}

/// The value is a JSON object, e.g. `{"key": "value"}`
pub fn json_object() -> FieldRule {
    Arc::new(
        |value| match serde_json::from_str::<serde_json::Value>(value) {
            Ok(serde_json::Value::Object(_)) => Ok(()),
            Ok(_) => Err(format!("{} is not a JSON object", quoted(value))),
            Err(error) => Err(format!("{} is not valid JSON: {error}", quoted(value))),
        },
    )
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
        fn rejects_integers_out_of_bounds_and_non_integers() {
            let rule = integer_between(1, 10);

            for value in ["0", "11", "18446744073709551616", "", "abc", "-1", "1.5"] {
                assert_eq!(
                    Err(format!(
                        "{} is not an integer between 1 and 10 (maximum value accepted)",
                        quoted(value)
                    )),
                    rule(value),
                    "{value}"
                );
            }
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
        fn rejects_empty_path_and_path_with_nul_byte() {
            assert_eq!(Err("'' is an empty path".to_string()), valid_path()(""));
            assert_eq!(
                Err("'/tmp/a\0b' contains a NUL byte".to_string()),
                valid_path()("/tmp/a\0b")
            );
        }
    }

    mod absolute_path {
        use super::*;

        #[test]
        fn accepts_absolute_paths_even_if_they_do_not_exist() {
            assert_eq!(Ok(()), absolute_path()("/does/not/exist/node.socket"));
        }

        #[test]
        fn rejects_relative_empty_and_windows_paths() {
            assert_eq!(
                Err("'relative/path' is not an absolute path".to_string()),
                absolute_path()("relative/path")
            );
            assert!(absolute_path()("").is_err());
            assert!(absolute_path()(r"C:\cardano\db").is_err());
        }
    }

    mod no_whitespace {
        use super::*;

        #[test]
        fn accepts_values_without_whitespace() {
            assert_eq!(Ok(()), no_whitespace()("/cardano/db"));
        }

        #[test]
        fn rejects_values_with_spaces_or_tabs() {
            assert_eq!(
                Err("'/cardano/my db' contains whitespace".to_string()),
                no_whitespace()("/cardano/my db")
            );
            assert!(no_whitespace()("/cardano/my\tdb").is_err());
        }
    }

    mod http_url {
        use super::*;

        #[test]
        fn accepts_http_and_https_urls() {
            let rule = http_url();

            assert_eq!(Ok(()), rule("https://aggregator.example.com/aggregator"));
            assert_eq!(Ok(()), rule("http://192.168.1.50:3132"));
        }

        #[test]
        fn rejects_other_schemes_and_urls_without_host() {
            let rule = http_url();

            for value in ["ftp://example.com", "example.com", "https://", "https:///path", ""] {
                assert_eq!(
                    Err(format!("{} is not an http(s) URL", quoted(value))),
                    rule(value),
                    "{value}"
                );
            }
        }
    }

    mod ip_address {
        use super::*;

        #[test]
        fn accepts_ipv4_and_ipv6_addresses() {
            let rule = ip_address();

            for value in ["0.0.0.0", "127.0.0.1", "::", "::1", "fe80::1"] {
                assert_eq!(Ok(()), rule(value), "{value}");
            }
        }

        #[test]
        fn rejects_host_names_invalid_addresses_and_addresses_with_a_port() {
            let rule = ip_address();

            for value in ["localhost", "256.0.0.1", "0.0.0", "0.0.0.0:9090", " 0.0.0.0", ""] {
                assert_eq!(
                    Err(format!("{} is not an IP address", quoted(value))),
                    rule(value),
                    "{value}"
                );
            }
        }
    }

    mod json_object {
        use super::*;

        #[test]
        fn accepts_json_objects() {
            assert_eq!(
                Ok(()),
                json_object()(r#"{"address": "addr1", "keys": [1, 2]}"#)
            );
        }

        #[test]
        fn rejects_other_json_values() {
            assert_eq!(
                Err("'[1, 2]' is not a JSON object".to_string()),
                json_object()("[1, 2]")
            );
        }

        #[test]
        fn rejects_invalid_json() {
            let reason = json_object()("{address").unwrap_err();

            assert!(
                reason.starts_with("'{address' is not valid JSON: "),
                "{reason}"
            );
        }
    }
}
