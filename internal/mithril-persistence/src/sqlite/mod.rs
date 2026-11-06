//! SQLite module.
//! This module provides a minimal yet useful Entity framework on top of SQLite
//! with ability to perform any SQL query possible and hydrate results in Rust
//! structs.
mod cleaner;
mod condition;
mod connection_builder;
mod connection_extensions;
mod connection_pool;
mod cursor;
mod entity;
mod projection;
mod query;
mod source_alias;
mod sqlite_value;
mod transaction;

pub use cleaner::{OptimizeMode, SqliteCleaner, SqliteCleaningTask};
pub use condition::{GetAllCondition, WhereCondition};
pub use connection_builder::{ConnectionBuilder, ConnectionOptions};
pub use connection_extensions::ConnectionExtensions;
pub use connection_pool::{SqliteConnectionPool, SqlitePooledConnection};
pub use cursor::EntityCursor;
pub use entity::{HydrationError, SqLiteEntity};
pub use projection::{Projection, ProjectionField};
pub use query::Query;
pub use source_alias::SourceAlias;
pub use sqlite_value::SqliteValue;
pub use transaction::Transaction;

/// Type of the connection used in Mithril
pub type SqliteConnection = sqlite::ConnectionThreadSafe;

/// Helpers to handle SQLite errors
pub mod error {
    /// Sqlite error type used in Mithril
    pub type SqliteError = sqlite::Error;

    /// SQLITE_BUSY error code
    ///
    /// see: <https://www.sqlite.org/rescode.html#busy>
    pub const SQLITE_BUSY: isize = 5;
}

#[cfg(test)]
mod test {
    use sqlite::Connection;

    #[test]
    fn sqlite_version_should_be_3_42_or_more() {
        let connection = Connection::open_thread_safe(":memory:").unwrap();
        let mut statement = connection.prepare("select sqlite_version()").unwrap();
        let cursor = statement.iter().next().unwrap().unwrap();
        let db_version = cursor.read::<&str, _>(0);
        let version = semver::Version::parse(db_version)
            .expect("Sqlite version should be parsable to semver");
        let requirement = semver::VersionReq::parse(">=3.42.0").unwrap();

        assert!(
            requirement.matches(&version),
            "Sqlite version {version} is lower than 3.42.0"
        )
    }
}
