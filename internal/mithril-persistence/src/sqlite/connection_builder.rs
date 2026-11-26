use std::ops::Not;
use std::path::{Path, PathBuf};

use anyhow::Context;
use slog::{Logger, debug};
use sqlite::ffi::sqlite3_extended_result_codes;
use sqlite::{Connection, ConnectionThreadSafe};

use mithril_common::StdResult;
use mithril_common::logging::LoggerExtensions;

use crate::database::{ApplicationNodeType, DatabaseVersionChecker, SqlMigration};
use crate::sqlite::SqliteConnectionPool;

/// Builder of SQLite connection
pub struct ConnectionBuilder {
    connection_path: PathBuf,
    sql_migrations: Vec<SqlMigration>,
    options: Vec<ConnectionOptions>,
    node_type: ApplicationNodeType,
    base_logger: Logger,
}

/// Options to apply to the connection
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum ConnectionOptions {
    /// Enable Write Ahead Log journal mod (not available for in memory connection)
    EnableWriteAheadLog,

    /// Enable foreign key support
    EnableForeignKeys,

    /// Disable foreign key support after the migrations are run
    ///
    /// This option take priority over [ConnectionOptions::EnableForeignKeys] if both are enabled.
    ForceDisableForeignKeys,
}

impl ConnectionBuilder {
    pub(crate) const APPLY_MIGRATIONS_LOG: &str = "Applying database migrations";

    /// Time a connection waits for a lock held by another connection before failing
    const BUSY_TIMEOUT_IN_MILLISECONDS: usize = 30_000;

    /// Builder of file SQLite connection
    pub fn open_file(path: &Path) -> Self {
        Self {
            connection_path: path.to_path_buf(),
            sql_migrations: vec![],
            options: vec![],
            node_type: ApplicationNodeType::Signer,
            base_logger: Logger::root(slog::Discard, slog::o!()),
        }
    }

    /// Builder of in memory SQLite connection
    pub fn open_memory() -> Self {
        Self::open_file(":memory:".as_ref())
    }

    /// Set migrations to apply at build time
    pub fn with_migrations(mut self, migrations: Vec<SqlMigration>) -> Self {
        self.sql_migrations = migrations;
        self
    }

    /// Set the [ConnectionOptions] to enabled on the connection.
    pub fn with_options(mut self, options: &[ConnectionOptions]) -> Self {
        for option in options {
            self.options.push(option.clone());
        }
        self
    }

    /// Set the logger to log to at build time
    pub fn with_logger(mut self, logger: Logger) -> Self {
        self.base_logger = logger;
        self
    }

    /// Set the node type (default: [ApplicationNodeType::Signer]).
    pub fn with_node_type(mut self, node_type: ApplicationNodeType) -> Self {
        self.node_type = node_type;
        self
    }

    /// Build a connection based on the builder configuration
    pub fn build(&self) -> StdResult<ConnectionThreadSafe> {
        let connection = self.build_without_migrations()?;

        let migrations = self.sql_migrations.clone();
        self.apply_migrations(&connection, migrations)?;
        if self.options.contains(&ConnectionOptions::ForceDisableForeignKeys) {
            connection
                .execute("pragma foreign_keys=false")
                .with_context(|| "SQLite initialization: could not disable FOREIGN KEY support.")?;
        }

        Ok(connection)
    }

    /// Build a connection pool based on the builder configuration
    pub fn build_pool(self, pool_size: usize) -> StdResult<SqliteConnectionPool> {
        self.build()
            .with_context(|| "SQLite initialization: failed to initialize connection")?;

        SqliteConnectionPool::build(pool_size, self)
    }

    /// Build a connection based on the builder configuration without applying any defined migrations
    ///
    /// Useful for connections built after the database is already initialized
    pub fn build_without_migrations(&self) -> StdResult<ConnectionThreadSafe> {
        let logger = self.base_logger.new_with_component_name::<Self>();

        debug!(logger, "Opening SQLite connection"; "path" => self.connection_path.display(), "options" => ?self.options);
        let connection =
            Connection::open_thread_safe(&self.connection_path).with_context(|| {
                format!(
                    "SQLite initialization: could not open connection with string '{}'.",
                    self.connection_path.display()
                )
            })?;

        // SAFETY: the handle is valid, it belongs to the connection opened above
        unsafe { sqlite3_extended_result_codes(connection.as_raw(), 1) };

        connection
            .execute(format!(
                "pragma busy_timeout = {}",
                Self::BUSY_TIMEOUT_IN_MILLISECONDS
            ))
            .with_context(|| "SQLite initialization: could not set the busy timeout.")?;

        if self.options.contains(&ConnectionOptions::EnableWriteAheadLog) {
            connection
                .execute("pragma journal_mode = wal; pragma synchronous = normal;")
                .with_context(|| "SQLite initialization: could not enable WAL.")?;
        }

        if self.options.contains(&ConnectionOptions::EnableForeignKeys) {
            connection
                .execute("pragma foreign_keys=true")
                .with_context(|| "SQLite initialization: could not enable FOREIGN KEY support.")?;
        }

        Ok(connection)
    }

    /// Apply a list of migration to the connection.
    pub fn apply_migrations(
        &self,
        connection: &ConnectionThreadSafe,
        sql_migrations: Vec<SqlMigration>,
    ) -> StdResult<()> {
        let logger = self.base_logger.new_with_component_name::<Self>();

        if sql_migrations.is_empty().not() {
            // Check database migrations
            debug!(logger, "{}", Self::APPLY_MIGRATIONS_LOG);
            let mut db_checker = DatabaseVersionChecker::new(
                self.base_logger.clone(),
                self.node_type.clone(),
                connection,
            );

            for migration in sql_migrations {
                db_checker.add_migration(migration);
            }

            db_checker.apply().with_context(|| "Database migration error")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use sqlite::Value;

    use mithril_common::temp_dir_create;
    use mithril_common::test::TempDir;

    use crate::sqlite::ConnectionOptions::ForceDisableForeignKeys;
    use crate::sqlite::error::SQLITE_BUSY_SNAPSHOT;

    use super::*;

    // see: https://www.sqlite.org/pragma.html#pragma_journal_mode
    const DEFAULT_SQLITE_JOURNAL_MODE: &str = "delete";
    // see: https://www.sqlite.org/pragma.html#pragma_synchronous
    const NORMAL_SYNCHRONOUS_FLAG: i64 = 1;

    fn execute_single_cell_query(connection: &Connection, query: &str) -> Value {
        let mut statement = connection.prepare(query).unwrap();
        let mut row = statement.iter().next().unwrap().unwrap();
        row.take(0)
    }

    #[test]
    fn test_open_in_memory_without_foreign_key() {
        let connection = ConnectionBuilder::open_memory().build().unwrap();

        let journal_mode = execute_single_cell_query(&connection, "pragma journal_mode;");
        let foreign_keys = execute_single_cell_query(&connection, "pragma foreign_keys;");

        assert_eq!(Value::String("memory".to_string()), journal_mode);
        assert_eq!(Value::Integer(false.into()), foreign_keys);
    }

    #[test]
    fn test_open_with_foreign_key() {
        let connection = ConnectionBuilder::open_memory()
            .with_options(&[ConnectionOptions::EnableForeignKeys])
            .build()
            .unwrap();

        let journal_mode = execute_single_cell_query(&connection, "pragma journal_mode;");
        let foreign_keys = execute_single_cell_query(&connection, "pragma foreign_keys;");

        assert_eq!(Value::String("memory".to_string()), journal_mode);
        assert_eq!(Value::Integer(true.into()), foreign_keys);
    }

    #[test]
    fn test_open_file_without_wal_and_foreign_keys() {
        let dirpath = TempDir::create(
            "mithril_test_database",
            "test_open_file_without_wal_and_foreign_keys",
        );
        let filepath = dirpath.join("db.sqlite3");
        assert!(!filepath.exists());

        let connection = ConnectionBuilder::open_file(&filepath).build().unwrap();

        let journal_mode = execute_single_cell_query(&connection, "pragma journal_mode;");
        let foreign_keys = execute_single_cell_query(&connection, "pragma foreign_keys;");

        assert!(filepath.exists());
        assert_eq!(
            Value::String(DEFAULT_SQLITE_JOURNAL_MODE.to_string()),
            journal_mode
        );
        assert_eq!(Value::Integer(false.into()), foreign_keys);
    }

    #[test]
    fn test_open_file_with_wal_and_foreign_keys() {
        let dirpath = TempDir::create(
            "mithril_test_database",
            "test_open_file_with_wal_and_foreign_keys",
        );
        let filepath = dirpath.join("db.sqlite3");
        assert!(!filepath.exists());

        let connection = ConnectionBuilder::open_file(&filepath)
            .with_options(&[
                ConnectionOptions::EnableForeignKeys,
                ConnectionOptions::EnableWriteAheadLog,
            ])
            .build()
            .unwrap();

        let journal_mode = execute_single_cell_query(&connection, "pragma journal_mode;");
        let foreign_keys = execute_single_cell_query(&connection, "pragma foreign_keys;");

        assert!(filepath.exists());
        assert_eq!(Value::String("wal".to_string()), journal_mode);
        assert_eq!(Value::Integer(true.into()), foreign_keys);
    }

    #[test]
    fn enabling_wal_option_also_set_synchronous_flag_to_normal() {
        let dirpath = TempDir::create(
            "mithril_test_database",
            "enabling_wal_option_also_set_synchronous_flag_to_normal",
        );

        let connection = ConnectionBuilder::open_file(&dirpath.join("db.sqlite3"))
            .with_options(&[ConnectionOptions::EnableWriteAheadLog])
            .build()
            .unwrap();

        let synchronous_flag = execute_single_cell_query(&connection, "pragma synchronous;");

        assert_eq!(Value::Integer(NORMAL_SYNCHRONOUS_FLAG), synchronous_flag);
    }

    #[test]
    fn builder_apply_given_migrations() {
        let connection = ConnectionBuilder::open_memory()
            .with_migrations(vec![
                SqlMigration::new(1, "create table first(id integer);"),
                SqlMigration::new(2, "create table second(id integer);"),
            ])
            .build()
            .unwrap();

        let tables_list = execute_single_cell_query(
            &connection,
            // Note: exclude sqlite system tables and migration system `db_version` table
            "SELECT group_concat(name) FROM sqlite_schema \
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'db_version' \
            ORDER BY name;",
        );

        assert_eq!(Value::String("first,second".to_string()), tables_list);
    }

    #[test]
    fn building_pool_apply_given_migrations() {
        let temp_dir = temp_dir_create!();
        let pool = ConnectionBuilder::open_file(&temp_dir.join("db.sqlite"))
            .with_migrations(vec![SqlMigration::new(1, "create table test(id integer);")])
            .build_pool(1)
            .unwrap();

        let connection = pool.connection().unwrap();
        connection
            .execute("SELECT * from test;")
            .expect("Migrations should have created the 'test' table");
    }

    #[test]
    fn can_disable_foreign_keys_even_if_a_migration_enable_them() {
        let connection = ConnectionBuilder::open_memory()
            .with_migrations(vec![SqlMigration::new(1, "pragma foreign_keys=true;")])
            .with_options(&[ForceDisableForeignKeys])
            .build()
            .unwrap();

        let foreign_keys = execute_single_cell_query(&connection, "pragma foreign_keys;");
        assert_eq!(Value::Integer(false.into()), foreign_keys);
    }

    #[test]
    fn test_apply_a_partial_migrations() {
        let migrations = vec![
            SqlMigration::new(1, "create table first(id integer);"),
            SqlMigration::new(2, "create table second(id integer);"),
        ];

        let connection = ConnectionBuilder::open_memory().build().unwrap();

        assert!(connection.prepare("select * from first;").is_err());
        assert!(connection.prepare("select * from second;").is_err());

        ConnectionBuilder::open_memory()
            .apply_migrations(&connection, migrations[0..1].to_vec())
            .unwrap();

        assert!(connection.prepare("select * from first;").is_ok());
        assert!(connection.prepare("select * from second;").is_err());

        ConnectionBuilder::open_memory()
            .apply_migrations(&connection, migrations)
            .unwrap();

        assert!(connection.prepare("select * from first;").is_ok());
        assert!(connection.prepare("select * from second;").is_ok());
    }

    #[test]
    fn a_write_waits_for_the_write_lock_held_by_another_connection() {
        let builder = ConnectionBuilder::open_file(&temp_dir_create!().join("db.sqlite3"))
            .with_options(&[ConnectionOptions::EnableWriteAheadLog])
            .with_migrations(vec![SqlMigration::new(1, "create table test(id integer);")]);
        let locking_connection = builder.build().unwrap();
        let waiting_connection = builder.build_without_migrations().unwrap();
        locking_connection
            .execute("begin immediate; insert into test values (1);")
            .unwrap();

        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(100));
                locking_connection.execute("commit;").unwrap();
            });

            waiting_connection
                .execute("insert into test values (2);")
                .expect("The write should wait for the write lock to be released");
        });
    }

    #[test]
    fn a_write_on_an_outdated_read_snapshot_fails_with_its_extended_result_code() {
        let builder = ConnectionBuilder::open_file(&temp_dir_create!().join("db.sqlite3"))
            .with_options(&[ConnectionOptions::EnableWriteAheadLog])
            .with_migrations(vec![SqlMigration::new(1, "create table test(id integer);")]);
        let writing_connection = builder.build().unwrap();
        let outdated_connection = builder.build_without_migrations().unwrap();
        outdated_connection.execute("begin; select * from test;").unwrap();
        writing_connection.execute("insert into test values (1);").unwrap();

        let error = outdated_connection
            .execute("insert into test values (2);")
            .expect_err("The write should fail on an outdated read snapshot");

        assert_eq!(Some(SQLITE_BUSY_SNAPSHOT), error.code);
    }
}
