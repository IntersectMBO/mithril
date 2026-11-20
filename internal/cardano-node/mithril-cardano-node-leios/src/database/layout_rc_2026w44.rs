use anyhow::Context;
use sqlite::{Connection, State};

use mithril_common::StdResult;

use super::LeiosImmutableDatabaseLayout;

/// Layout of the LeiosDB immutable partition of the `rc-2026w44` release of the Leios node.
///
/// Three tables keyed by the endorser block hash: `ebs` (announcing slot and announced size),
/// `ebBodies` (body and transaction bounds) and `ebClosures` (the concatenated transactions).
pub struct LayoutRc2026w44;

impl LeiosImmutableDatabaseLayout for LayoutRc2026w44 {
    fn name(&self) -> &'static str {
        "rc-2026w44"
    }

    fn has_closure(&self, connection: &Connection, endorser_block_hash: &str) -> StdResult<bool> {
        let hash_bytes = hex::decode(endorser_block_hash)
            .with_context(|| format!("Invalid endorser block hash '{endorser_block_hash}'"))?;
        let mut statement = connection
            .prepare(
                "SELECT 1 FROM ebs \
                 JOIN ebBodies ON ebBodies.ebHashBytes = ebs.ebHashBytes \
                 JOIN ebClosures ON ebClosures.ebHashBytes = ebs.ebHashBytes \
                 WHERE ebs.ebHashBytes = ?",
            )
            .with_context(|| "Could not prepare the closure query")?;
        statement.bind((1, hash_bytes.as_slice()))?;

        Ok(statement.next()? == State::Row)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mithril_common::test::TempDir;

    use crate::database::LeiosImmutableDatabase;
    use crate::test::LeiosFixtures;

    use super::*;

    fn fixture_database(test_name: &str) -> LeiosImmutableDatabase {
        let db_directory = TempDir::create("layout_rc_2026w44", test_name);
        LeiosFixtures::copy_to(&db_directory);

        LeiosImmutableDatabase::open_read_only(&db_directory, Arc::new(LayoutRc2026w44)).unwrap()
    }

    #[test]
    fn has_the_closure_of_a_certified_endorser_block() {
        let database = fixture_database("has_closure");

        let has_closure = database.has_closure(LeiosFixtures::ENDORSER_BLOCK_HASHES[0]).unwrap();

        assert!(has_closure);
    }

    #[test]
    fn has_no_closure_for_an_unknown_endorser_block() {
        let database = fixture_database("has_no_closure");

        let has_closure = database.has_closure(&"0".repeat(64)).unwrap();

        assert!(!has_closure);
    }

    #[test]
    fn fails_on_an_endorser_block_hash_that_is_not_hex() {
        let database = fixture_database("not_hex");

        database
            .has_closure("not-hex")
            .expect_err("should fail on a non hex hash");
    }
}
