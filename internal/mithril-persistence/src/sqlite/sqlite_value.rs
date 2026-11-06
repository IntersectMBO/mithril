use std::fmt::Display;

use anyhow::Context;
use sqlite::Value;

use mithril_common::{StdError, StdResult};

/// Helpers to convert Rust values into SQLite [Value]s.
///
/// Not a value type itself: each function returns a [sqlite::Value].
pub struct SqliteValue;

impl SqliteValue {
    /// Convert a value into a SQLite integer, failing when it does not fit in an `i64`.
    ///
    /// The `field_name` and the value are included in the error message.
    pub fn try_integer<T>(field_name: &str, value: T) -> StdResult<Value>
    where
        T: TryInto<i64> + Display,
        T::Error: Into<StdError>,
    {
        let error_context = format!("{field_name} '{value}' does not fit in a database integer");
        let integer = value.try_into().map_err(Into::into).with_context(|| error_context)?;

        Ok(Value::Integer(integer))
    }

    /// Same as [Self::try_integer], with `None` converted to a SQLite null.
    pub fn try_integer_or_null<T>(field_name: &str, value: Option<T>) -> StdResult<Value>
    where
        T: TryInto<i64> + Display,
        T::Error: Into<StdError>,
    {
        match value {
            Some(value) => Self::try_integer(field_name, value),
            None => Ok(Value::Null),
        }
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::entities::Epoch;

    use super::*;

    mod try_integer {
        use super::*;

        #[test]
        fn convert_values_that_fit_in_i64() {
            assert_eq!(
                Value::Integer(123),
                SqliteValue::try_integer("test", 123).unwrap()
            );
            assert_eq!(
                Value::Integer(i64::MAX),
                SqliteValue::try_integer("test", i64::MAX).unwrap()
            );
            assert_eq!(
                Value::Integer(123),
                SqliteValue::try_integer("test", 123u64).unwrap()
            );
            assert_eq!(
                Value::Integer(123),
                SqliteValue::try_integer("test", Epoch(123)).unwrap()
            );
        }

        #[test]
        fn fail_with_field_name_and_value_in_error_when_value_does_not_fit_in_i64() {
            let error = SqliteValue::try_integer("my_field", u64::MAX)
                .expect_err("u64::MAX should not fit in an i64");

            let message = error.to_string();
            assert!(
                message.contains("my_field"),
                "unexpected message: {message}"
            );
            assert!(
                message.contains(&u64::MAX.to_string()),
                "unexpected message: {message}"
            );
        }
    }

    mod try_integer_or_null {
        use super::*;

        #[test]
        fn convert_none_to_null() {
            assert_eq!(
                Value::Null,
                SqliteValue::try_integer_or_null("test", None::<u64>).unwrap()
            );
        }

        #[test]
        fn convert_some_value_that_fit_in_i64() {
            assert_eq!(
                Value::Integer(123),
                SqliteValue::try_integer_or_null("test", Some(123u64)).unwrap()
            );
            assert_eq!(
                Value::Integer(123),
                SqliteValue::try_integer_or_null("test", Some(Epoch(123))).unwrap()
            );
        }

        #[test]
        fn fail_with_field_name_and_value_in_error_when_some_value_does_not_fit_in_i64() {
            let error = SqliteValue::try_integer_or_null("my_field", Some(u64::MAX))
                .expect_err("u64::MAX should not fit in an i64");

            let message = error.to_string();
            assert!(
                message.contains("my_field"),
                "unexpected message: {message}"
            );
            assert!(
                message.contains(&u64::MAX.to_string()),
                "unexpected message: {message}"
            );
        }
    }
}
