use sqlite::Value;

use mithril_common::entities::{BlockHash, BlockNumber, SlotNumber};

use crate::database::record::CardanoBlockRecord;
use crate::sqlite::{Query, SourceAlias, SqLiteEntity, WhereCondition};

/// Simple queries to retrieve [CardanoBlockRecord] from the sqlite database.
pub struct GetCardanoBlockQuery {
    condition: WhereCondition,
}

impl GetCardanoBlockQuery {
    pub fn all() -> Self {
        Self {
            condition: WhereCondition::default(),
        }
    }

    // Useful in test and probably in the future.
    pub fn by_block_hash(block_hash: &BlockHash) -> Self {
        Self {
            condition: WhereCondition::new(
                "block_hash = ?*",
                vec![Value::String(block_hash.to_owned())],
            ),
        }
    }

    pub fn by_block_hashes(
        transactions_hashes: Vec<BlockHash>,
        up_to_or_equal: BlockNumber,
    ) -> Self {
        let hashes_values = transactions_hashes.into_iter().map(Value::String).collect();
        let condition =
            WhereCondition::where_in("block_hash", hashes_values).and_where(WhereCondition::new(
                "block_number <= ?*",
                vec![Value::Integer(*up_to_or_equal as i64)],
            ));

        Self { condition }
    }

    /// Get the blocks with the given block numbers
    pub fn by_block_numbers(block_numbers: Vec<BlockNumber>) -> Self {
        let block_numbers_values = block_numbers
            .into_iter()
            .map(|block_number| Value::Integer(*block_number as i64))
            .collect();

        Self {
            condition: WhereCondition::where_in("block_number", block_numbers_values),
        }
    }

    pub fn with_highest_block_number_below_slot_number(slot_number: SlotNumber) -> Self {
        Self {
            condition: WhereCondition::new(
                "block_number = (select max(block_number) from cardano_block where slot_number <= ?*)",
                vec![Value::Integer(*slot_number as i64)],
            ),
        }
    }

    pub fn with_highest_block_number() -> Self {
        Self {
            condition: WhereCondition::new(
                "block_number = (select max(block_number) from cardano_block)",
                vec![],
            ),
        }
    }
}

impl Query for GetCardanoBlockQuery {
    type Entity = CardanoBlockRecord;

    fn filters(&self) -> WhereCondition {
        self.condition.clone()
    }

    fn get_definition(&self, condition: &str) -> String {
        let aliases = SourceAlias::new(&[("{:cardano_block:}", "cardano_block")]);
        let projection = Self::Entity::get_projection().expand(aliases);

        format!(
            "select {projection} from cardano_block where {condition} order by block_number, block_hash"
        )
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::entities::BlockNumber;

    use crate::database::query::InsertCardanoBlockQuery;
    use crate::database::test_helper::cardano_tx_db_connection;
    use crate::sqlite::{ConnectionExtensions, SqliteConnection};

    use super::*;

    fn test_blocks_set() -> Vec<CardanoBlockRecord> {
        vec![
            block_record(BlockNumber(10), SlotNumber(50)),
            block_record(BlockNumber(14), SlotNumber(54)),
            block_record(BlockNumber(15), SlotNumber(55)),
            block_record(BlockNumber(20), SlotNumber(60)),
            block_record(BlockNumber(24), SlotNumber(64)),
            block_record(BlockNumber(30), SlotNumber(70)),
        ]
    }

    fn connection_with_test_data_set() -> SqliteConnection {
        let connection = cardano_tx_db_connection().unwrap();
        insert_blocks(&connection, test_blocks_set());
        connection
    }

    fn insert_blocks(connection: &SqliteConnection, records: Vec<CardanoBlockRecord>) {
        connection
            .fetch_first(InsertCardanoBlockQuery::insert_many(records).unwrap())
            .unwrap();
    }

    fn block_record(block_number: BlockNumber, slot_number: SlotNumber) -> CardanoBlockRecord {
        CardanoBlockRecord::new(
            format!("block_hash-{block_number}"),
            block_number,
            slot_number,
        )
    }

    #[test]
    fn with_highest_block_number() {
        let connection = cardano_tx_db_connection().unwrap();

        let cursor = connection
            .fetch(GetCardanoBlockQuery::with_highest_block_number())
            .unwrap();
        assert_eq!(0, cursor.count());

        insert_blocks(&connection, test_blocks_set());

        let records: Vec<CardanoBlockRecord> = connection
            .fetch_collect(GetCardanoBlockQuery::with_highest_block_number())
            .unwrap();
        assert_eq!(vec![block_record(BlockNumber(30), SlotNumber(70))], records);
    }

    #[test]
    fn by_block_numbers() {
        let connection = connection_with_test_data_set();

        let records: Vec<CardanoBlockRecord> = connection
            .fetch_collect(GetCardanoBlockQuery::by_block_numbers(vec![
                BlockNumber(30),
                BlockNumber(15),
                BlockNumber(99),
            ]))
            .unwrap();

        assert_eq!(
            vec![
                block_record(BlockNumber(15), SlotNumber(55)),
                block_record(BlockNumber(30), SlotNumber(70)),
            ],
            records
        );
    }

    #[test]
    fn with_highest_block_number_below_slot_number() {
        let connection = cardano_tx_db_connection().unwrap();

        let cursor = connection
            .fetch(
                GetCardanoBlockQuery::with_highest_block_number_below_slot_number(SlotNumber(51)),
            )
            .unwrap();
        assert_eq!(0, cursor.count());

        insert_blocks(
            &connection,
            vec![block_record(BlockNumber(2), SlotNumber(5))],
        );

        let records: Vec<CardanoBlockRecord> = connection
            .fetch_collect(
                GetCardanoBlockQuery::with_highest_block_number_below_slot_number(SlotNumber(5)),
            )
            .unwrap();
        assert_eq!(vec![block_record(BlockNumber(2), SlotNumber(5))], records);

        insert_blocks(
            &connection,
            vec![
                block_record(BlockNumber(10), SlotNumber(50)),
                block_record(BlockNumber(11), SlotNumber(51)),
                block_record(BlockNumber(14), SlotNumber(54)),
                block_record(BlockNumber(15), SlotNumber(55)),
            ],
        );

        let records: Vec<CardanoBlockRecord> = connection
            .fetch_collect(
                GetCardanoBlockQuery::with_highest_block_number_below_slot_number(SlotNumber(53)),
            )
            .unwrap();
        assert_eq!(vec![block_record(BlockNumber(11), SlotNumber(51))], records);

        let records: Vec<CardanoBlockRecord> = connection
            .fetch_collect(
                GetCardanoBlockQuery::with_highest_block_number_below_slot_number(SlotNumber(54)),
            )
            .unwrap();
        assert_eq!(vec![block_record(BlockNumber(14), SlotNumber(54))], records);
    }

    mod by_block_hashes {
        use super::*;

        #[tokio::test]
        async fn empty_hashes_list() {
            let connection = connection_with_test_data_set();
            let result: Vec<CardanoBlockRecord> = connection
                .fetch_collect(GetCardanoBlockQuery::by_block_hashes(
                    vec![],
                    BlockNumber(30),
                ))
                .unwrap();

            assert_eq!(Vec::<CardanoBlockRecord>::new(), result);
        }

        #[tokio::test]
        async fn one_hash_exactly_at_boundary_block_number() {
            let connection = connection_with_test_data_set();
            let result: Vec<CardanoBlockRecord> = connection
                .fetch_collect(GetCardanoBlockQuery::by_block_hashes(
                    vec!["block_hash-30".to_string()],
                    BlockNumber(30),
                ))
                .unwrap();

            assert_eq!(vec![block_record(BlockNumber(30), SlotNumber(70))], result);
        }

        #[tokio::test]
        async fn multiple_hashes_with_one_above_block_number_boundary() {
            let connection = connection_with_test_data_set();
            let result: Vec<CardanoBlockRecord> = connection
                .fetch_collect(GetCardanoBlockQuery::by_block_hashes(
                    vec![
                        "block_hash-10".to_string(),
                        "block_hash-15".to_string(),
                        "block_hash-24".to_string(),
                    ],
                    BlockNumber(20),
                ))
                .unwrap();

            assert_eq!(
                vec![
                    block_record(BlockNumber(10), SlotNumber(50)),
                    block_record(BlockNumber(15), SlotNumber(55)),
                ],
                result
            );
        }

        #[tokio::test]
        async fn all_hashes_higher_than_block_number_boundary() {
            let connection = connection_with_test_data_set();
            let result: Vec<CardanoBlockRecord> = connection
                .fetch_collect(GetCardanoBlockQuery::by_block_hashes(
                    vec!["block_hash-10".to_string(), "block_hash-15".to_string()],
                    BlockNumber(5),
                ))
                .unwrap();

            assert_eq!(Vec::<CardanoBlockRecord>::new(), result);
        }
    }
}
