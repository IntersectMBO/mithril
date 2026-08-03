use anyhow::{Context, anyhow};
use chrono::Utc;
use slog::{Logger, debug, error, info};
use std::{cmp::Ordering, collections::BTreeSet};

use mithril_common::{StdError, StdResult, logging::LoggerExtensions};

use super::{
    ApplicationNodeType, DatabaseVersion, DbVersion, GetDatabaseVersionQuery,
    UpdateDatabaseVersionQuery,
};

use crate::sqlite::{
    ConnectionExtensions, OptimizeMode, SqliteCleaner, SqliteCleaningTask, SqliteConnection,
};

/// Struct to perform application version check in the database.
pub struct DatabaseVersionChecker<'conn> {
    /// Pathbuf to the SQLite3 file.
    connection: &'conn SqliteConnection,

    /// Application type which vesion is verified.
    application_type: ApplicationNodeType,

    /// logger
    logger: Logger,

    /// known migrations
    migrations: BTreeSet<SqlMigration>,
}

impl<'conn> DatabaseVersionChecker<'conn> {
    /// constructor
    pub fn new(
        logger: Logger,
        application_type: ApplicationNodeType,
        connection: &'conn SqliteConnection,
    ) -> Self {
        let migrations = BTreeSet::new();

        Self {
            connection,
            application_type,
            logger: logger.new_with_component_name::<Self>(),
            migrations,
        }
    }

    /// Register a migration.
    pub fn add_migration(&mut self, migration: SqlMigration) -> &mut Self {
        let _ = self.migrations.insert(migration);

        self
    }

    /// Apply migrations
    pub fn apply(&self) -> StdResult<()> {
        debug!(&self.logger, "Check database version",);
        self.create_table_if_not_exists(&self.application_type)
            .with_context(|| "Can not create table 'db_version' while applying migrations")?;
        let db_version = self
            .connection
            .fetch_first(GetDatabaseVersionQuery::get_application_version(
                &self.application_type,
            ))
            .with_context(|| "Can not get application version while applying migrations")?
            .unwrap(); // At least a record exists.

        // the current database version is equal to the maximum migration
        // version present in this software.
        // If no migration registered then version = 0.
        let migration_version = self.migrations.iter().map(|m| m.version).max().unwrap_or(0);

        match migration_version.cmp(&db_version.version) {
            Ordering::Greater => {
                debug!(
                    &self.logger,
                    "Database needs upgrade from version '{}' to version '{}', applying new migrations…",
                    db_version.version,
                    migration_version
                );
                self.apply_migrations(&db_version, self.connection)?;
                info!(
                    &self.logger,
                    "Database upgraded to version '{migration_version}'"
                );

                // Indexes may have changed, optimize the database to ensure the query optimizer is aware of them
                SqliteCleaner::new(self.connection)
                    .with_logger(self.logger.clone())
                    .with_tasks(&[SqliteCleaningTask::Optimize(OptimizeMode::Default)])
                    .run()
                    .with_context(|| "Database optimization error")?;
            }
            Ordering::Less => {
                error!(
                    &self.logger,
                    "Software version '{}' is older than database structure version '{}'.",
                    db_version.version,
                    migration_version,
                );

                Err(anyhow!(
                    "This software version is older than the database structure. Aborting launch to prevent possible data corruption."
                ))?;
            }
            Ordering::Equal => {
                debug!(&self.logger, "database up to date");
            }
        };

        Ok(())
    }

    fn apply_migrations(
        &self,
        starting_version: &DatabaseVersion,
        connection: &SqliteConnection,
    ) -> StdResult<()> {
        for migration in &self
            .migrations
            .iter()
            .filter(|&m| m.version > starting_version.version)
            .collect::<Vec<&SqlMigration>>()
        {
            self.check_minimum_required_version(starting_version.version, migration)?;
            connection.execute(&migration.alterations)?;
            let db_version = DatabaseVersion {
                version: migration.version,
                application_type: self.application_type.clone(),
                updated_at: Utc::now(),
            };
            let _ = connection
                .fetch_first(UpdateDatabaseVersionQuery::one(db_version))
                .with_context(|| {
                    format!(
                        "Can not save database version when applying migration: '{}'",
                        migration.version
                    )
                })?;
        }

        Ok(())
    }

    /// Method to create the table at the beginning of the migration procedure.
    /// This code is temporary and should not last.
    pub fn create_table_if_not_exists(
        &self,
        application_type: &ApplicationNodeType,
    ) -> StdResult<()> {
        let connection = self.connection;
        let table_exists = connection.query_single_cell::<_, i64>(
            "select exists(select name from sqlite_master where type='table' and name='db_version') as table_exists",
            &[],
        )? == 1;

        if !table_exists {
            let sql = format!("
create table db_version (application_type text not null primary key, version integer not null, updated_at text not null);
insert into db_version (application_type, version, updated_at) values ('{application_type}', 0, '{}');
", Utc::now().to_rfc3339());
            connection.execute(sql)?;
        }

        Ok(())
    }

    /// Checks if the database version meets the minimum required version to apply a squashed migration.
    /// If the database version 0 or if the migration doesn't specify a fallback distribution version, the check passes.
    /// For migrations with a fallback distribution version, the check passes if the database version is exactly
    /// one less than the migration version (i.e., there's no gap between them).
    fn check_minimum_required_version(
        &self,
        db_version: DbVersion,
        migration: &SqlMigration,
    ) -> StdResult<()> {
        if db_version == 0 {
            return Ok(());
        }

        if let Some(fallback_distribution_version) = &migration.fallback_distribution_version {
            let min_required_version = migration.version - 1;
            if db_version < min_required_version {
                return Err(self.generate_fallback_migration_error(
                    migration.version,
                    fallback_distribution_version,
                ));
            }
        }

        Ok(())
    }

    fn generate_fallback_migration_error(
        &self,
        migration_version: i64,
        fallback_distribution_version: &str,
    ) -> StdError {
        anyhow!(
            r#"
                Minimum required database version is not met to apply migration '{}'.
                Please migrate your {} node database with the minimum node version compatible available in the distribution: '{}'.

                First, download the required node version in your current directory by running the following command:
                curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/IntersectMBO/mithril/refs/heads/main/mithril-install.sh | sh -s -- -c mithril-{} -d {} -p "$(pwd)"

                Then run the database migrate command:
                mithril-{} database migrate --stores-directory /path/to/stores-directory
            "#,
            migration_version,
            self.application_type,
            fallback_distribution_version,
            self.application_type,
            fallback_distribution_version,
            self.application_type
        )
    }
}

/// Represent a file containing SQL structure or data alterations.
#[derive(Debug, Clone)]
pub struct SqlMigration {
    /// The semver version this migration targets.
    pub version: DbVersion,

    /// SQL statements to alter the database.
    pub alterations: String,

    /// The distribution version the user can fallback to in order to update their database before updating to the latest node.
    pub fallback_distribution_version: Option<String>,
}

impl SqlMigration {
    /// Create a new SQL migration instance.
    pub fn new<T: Into<String>>(version: DbVersion, alteration: T) -> Self {
        Self {
            version,
            alterations: alteration.into(),
            fallback_distribution_version: None,
        }
    }

    /// Create a new squashed SQL migration instance with the fallback distribution version.
    pub fn new_squashed<T: Into<String>>(
        version: DbVersion,
        fallback_distribution_version: T,
        alteration: T,
    ) -> Self {
        Self {
            version,
            alterations: alteration.into(),
            fallback_distribution_version: Some(fallback_distribution_version.into()),
        }
    }
}

impl PartialOrd for SqlMigration {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SqlMigration {
    fn cmp(&self, other: &Self) -> Ordering {
        self.version.cmp(&other.version)
    }
}

impl PartialEq for SqlMigration {
    fn eq(&self, other: &Self) -> bool {
        self.version.eq(&other.version)
    }
}

impl Eq for SqlMigration {}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use mithril_common::test::TempDir;
    use mithril_common::{StdResult, current_function};
    use sqlite::{Connection, ConnectionThreadSafe};
    use std::path::PathBuf;

    use super::*;

    const CREATE_TABLE_SQL_REQUEST: &str = "create table whatever (thing_id integer); insert into whatever (thing_id) values (1), (2), (3), (4);";
    const ALTER_TABLE_SQL_REQUEST: &str = "alter table whatever add column thing_content text; update whatever set thing_content = 'some content'";

    fn discard_logger() -> Logger {
        Logger::root(slog::Discard, slog::o!())
    }

    fn check_database_version(connection: &SqliteConnection, db_version: DbVersion) {
        let version = connection
            .fetch_first(GetDatabaseVersionQuery::get_application_version(
                &ApplicationNodeType::Aggregator,
            ))
            .unwrap()
            .unwrap();

        assert_eq!(db_version, version.version);
    }

    fn create_sqlite_file(test_name: &str) -> StdResult<(PathBuf, SqliteConnection)> {
        let dirpath = TempDir::create("mithril_test_database", test_name);
        let filepath = dirpath.join("db.sqlite3");

        let connection = Connection::open_thread_safe(&filepath)
            .with_context(|| "connection to sqlite file failure")?;

        Ok((filepath, connection))
    }

    fn get_table_whatever_column_count(connection: &SqliteConnection) -> i64 {
        let sql = "select count(*) as column_count from pragma_table_info('whatever');";

        connection
            .prepare(sql)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .unwrap()
            .read::<i64, _>(0)
    }

    fn create_db_checker(connection: &ConnectionThreadSafe) -> DatabaseVersionChecker<'_> {
        DatabaseVersionChecker::new(
            discard_logger(),
            ApplicationNodeType::Aggregator,
            connection,
        )
    }

    #[test]
    fn test_upgrade_with_migration() {
        let (_filepath, connection) = create_sqlite_file(current_function!()).unwrap();
        let mut db_checker = create_db_checker(&connection);

        db_checker.apply().unwrap();
        assert_eq!(0, get_table_whatever_column_count(&connection));

        db_checker.apply().unwrap();
        assert_eq!(0, get_table_whatever_column_count(&connection));

        let alterations = "create table whatever (thing_id integer); insert into whatever (thing_id) values (1), (2), (3), (4);";
        let migration = SqlMigration {
            version: 1,
            alterations: alterations.to_string(),
            fallback_distribution_version: None,
        };
        db_checker.add_migration(migration);
        db_checker.apply().unwrap();
        assert_eq!(1, get_table_whatever_column_count(&connection));
        check_database_version(&connection, 1);

        db_checker.apply().unwrap();
        assert_eq!(1, get_table_whatever_column_count(&connection));
        check_database_version(&connection, 1);

        let alterations = "alter table whatever add column thing_content text; update whatever set thing_content = 'some content'";
        let migration = SqlMigration {
            version: 2,
            alterations: alterations.to_string(),
            fallback_distribution_version: None,
        };
        db_checker.add_migration(migration);
        db_checker.apply().unwrap();
        assert_eq!(2, get_table_whatever_column_count(&connection));
        check_database_version(&connection, 2);

        // in the test below both migrations are declared in reversed order to
        // ensure they are played in the right order. The last one depends on
        // the 3rd.
        let alterations = "alter table whatever add column one_last_thing text; update whatever set one_last_thing = more_thing";
        let migration = SqlMigration {
            version: 4,
            alterations: alterations.to_string(),
            fallback_distribution_version: None,
        };
        db_checker.add_migration(migration);
        let alterations = "alter table whatever add column more_thing text; update whatever set more_thing = 'more thing'";
        let migration = SqlMigration {
            version: 3,
            alterations: alterations.to_string(),
            fallback_distribution_version: None,
        };
        db_checker.add_migration(migration);
        db_checker.apply().unwrap();
        assert_eq!(4, get_table_whatever_column_count(&connection));
        check_database_version(&connection, 4);
    }

    #[test]
    fn test_upgrade_with_migration_with_a_version_gap() {
        let (_filepath, connection) = create_sqlite_file(current_function!()).unwrap();
        let mut db_checker = create_db_checker(&connection);

        let alterations = "create table whatever (thing_id integer); insert into whatever (thing_id) values (1), (2), (3), (4);";
        let migration = SqlMigration {
            version: 3,
            alterations: alterations.to_string(),
            fallback_distribution_version: None,
        };
        db_checker.add_migration(migration);
        db_checker.apply().unwrap();
        assert_eq!(1, get_table_whatever_column_count(&connection));
        check_database_version(&connection, 3);

        let alterations = "alter table whatever add column thing_content text; update whatever set thing_content = 'some content'";
        let migration_with_version_gap = SqlMigration {
            version: 10,
            alterations: alterations.to_string(),
            fallback_distribution_version: None,
        };
        db_checker.add_migration(migration_with_version_gap);
        db_checker.apply().unwrap();
        assert_eq!(2, get_table_whatever_column_count(&connection));
        check_database_version(&connection, 10);
    }

    #[test]
    fn starting_with_migration() {
        let (_filepath, connection) = create_sqlite_file(current_function!()).unwrap();
        let mut db_checker = create_db_checker(&connection);

        let alterations = "create table whatever (thing_id integer); insert into whatever (thing_id) values (1), (2), (3), (4);";
        let migration = SqlMigration {
            version: 1,
            alterations: alterations.to_string(),
            fallback_distribution_version: None,
        };
        db_checker.add_migration(migration);
        db_checker.apply().unwrap();
        assert_eq!(1, get_table_whatever_column_count(&connection));
        check_database_version(&connection, 1);
    }

    #[test]
    /// This test case ensure that when multiple migrations are played and one fails:
    /// * previous migrations are ok and the database version is updated
    /// * further migrations are not played.
    fn test_failing_migration() {
        let (_filepath, connection) = create_sqlite_file(current_function!()).unwrap();
        let mut db_checker = create_db_checker(&connection);
        // Table whatever does not exist, this should fail with error.
        let alterations = "create table whatever (thing_id integer); insert into whatever (thing_id) values (1), (2), (3), (4);";
        let migration = SqlMigration {
            version: 1,
            alterations: alterations.to_string(),
            fallback_distribution_version: None,
        };
        db_checker.add_migration(migration);
        let alterations = "alter table wrong add column thing_content text; update whatever set thing_content = 'some content'";
        let migration = SqlMigration {
            version: 2,
            alterations: alterations.to_string(),
            fallback_distribution_version: None,
        };
        db_checker.add_migration(migration);
        let alterations = "alter table whatever add column thing_content text; update whatever set thing_content = 'some content'";
        let migration = SqlMigration {
            version: 3,
            alterations: alterations.to_string(),
            fallback_distribution_version: None,
        };
        db_checker.add_migration(migration);
        db_checker.apply().unwrap_err();
        check_database_version(&connection, 1);
    }

    #[test]
    fn test_fail_downgrading() {
        let (_filepath, connection) = create_sqlite_file(current_function!()).unwrap();
        let mut db_checker = create_db_checker(&connection);
        let migration = SqlMigration {
            version: 1,
            alterations: CREATE_TABLE_SQL_REQUEST.to_string(),
            fallback_distribution_version: None,
        };
        db_checker.add_migration(migration);
        db_checker.apply().unwrap();
        check_database_version(&connection, 1);

        // re instantiate a new checker with no migration registered (version 0).
        let db_checker = create_db_checker(&connection);
        assert!(
            db_checker.apply().is_err(),
            "using an old version with an up to date database should fail"
        );
        check_database_version(&connection, 1);
    }

    #[test]
    fn check_minimum_required_version_does_not_fail_when_no_fallback_distribution_version() {
        let (_filepath, connection) = create_sqlite_file(current_function!()).unwrap();
        let db_checker = create_db_checker(&connection);

        let alterations = CREATE_TABLE_SQL_REQUEST;
        let migration = SqlMigration {
            version: 3,
            alterations: alterations.to_string(),
            fallback_distribution_version: None,
        };

        db_checker.check_minimum_required_version(1, &migration).expect(
            "Check minimum required version should not fail when no fallback distribution version",
        );
    }

    #[test]
    fn check_minimum_required_version_does_not_fail_when_fallback_distribution_version_with_fresh_database()
     {
        let (_filepath, connection) = create_sqlite_file(current_function!()).unwrap();
        let db_checker = create_db_checker(&connection);

        let alterations = CREATE_TABLE_SQL_REQUEST;
        let migration = SqlMigration {
            version: 2,
            alterations: alterations.to_string(),
            fallback_distribution_version: Some("2511.0".to_string()),
        };

        db_checker
            .check_minimum_required_version(0, &migration)
            .expect("Check minimum required version should not fail with fresh database");
    }

    #[test]
    fn check_minimum_required_version_does_not_fail_when_no_gap_between_db_version_and_migration_version()
     {
        let (_filepath, connection) = create_sqlite_file(current_function!()).unwrap();
        let db_checker = create_db_checker(&connection);

        let migration = SqlMigration {
            version: 2,
            alterations: CREATE_TABLE_SQL_REQUEST.to_string(),
            fallback_distribution_version: Some("2511.0".to_string()),
        };

        db_checker
            .check_minimum_required_version(1, &migration)
            .expect("Check minimum required version should not fail when no gap between db version and migration version");
    }

    #[test]
    fn check_minimum_required_version_fails_when_gap_between_db_version_and_migration_version() {
        let (_filepath, connection) = create_sqlite_file(current_function!()).unwrap();
        let db_checker = DatabaseVersionChecker::new(
            discard_logger(),
            ApplicationNodeType::Aggregator,
            &connection,
        );

        let migration = SqlMigration {
            version: 3,
            alterations: CREATE_TABLE_SQL_REQUEST.to_string(),
            fallback_distribution_version: Some("2511.0".to_string()),
        };

        let error = db_checker
            .check_minimum_required_version(1, &migration)
            .expect_err("Check minimum required version should fail when gap between db version and migration version");

        assert!(error.to_string().contains("curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/IntersectMBO/mithril/refs/heads/main/mithril-install.sh | sh -s -- -c mithril-aggregator -d 2511.0 -p \"$(pwd)\""));
    }

    #[test]
    fn apply_fails_when_trying_to_apply_squashed_migration_on_old_database() {
        let (_filepath, connection) = create_sqlite_file(current_function!()).unwrap();
        let mut db_checker = DatabaseVersionChecker::new(
            discard_logger(),
            ApplicationNodeType::Aggregator,
            &connection,
        );

        let migration = SqlMigration {
            version: 1,
            alterations: CREATE_TABLE_SQL_REQUEST.to_string(),
            fallback_distribution_version: None,
        };
        db_checker.add_migration(migration);
        db_checker.apply().unwrap();
        check_database_version(&connection, 1);

        let squashed_migration = SqlMigration {
            version: 3,
            alterations: ALTER_TABLE_SQL_REQUEST.to_string(),
            fallback_distribution_version: Some("2511.0".to_string()),
        };
        db_checker.add_migration(squashed_migration);

        let error = db_checker
            .apply()
            .expect_err("Should fail when applying squashed migration on old database");

        assert!(error.to_string().contains("curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/IntersectMBO/mithril/refs/heads/main/mithril-install.sh | sh -s -- -c mithril-aggregator -d 2511.0 -p \"$(pwd)\""));
    }
}
