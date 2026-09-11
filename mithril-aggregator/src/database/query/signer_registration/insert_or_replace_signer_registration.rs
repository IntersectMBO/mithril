use sqlite::Value;

use mithril_persistence::sqlite::{Query, SourceAlias, SqLiteEntity, WhereCondition};

use crate::database::record::SignerRegistrationRecord;

/// Query to insert or replace [SignerRegistrationRecord] in the sqlite database
pub struct InsertOrReplaceSignerRegistrationRecordQuery {
    condition: WhereCondition,
}

impl InsertOrReplaceSignerRegistrationRecordQuery {
    pub fn one(signer_registration_record: SignerRegistrationRecord) -> Self {
        let condition = WhereCondition::new(
            "(signer_id, epoch_setting_id, verification_key, verification_key_signature, operational_certificate, kes_period, stake, verification_key_for_snark, verification_key_signature_for_snark, created_at, proof_of_bound_possession_for_snark) values (?*, ?*, ?*, ?*, ?*, ?*, ?*, ?*, ?*, ?*, ?*)",
            vec![
                Value::String(signer_registration_record.signer_id),
                Value::Integer(signer_registration_record.epoch_settings_id.try_into().unwrap()),
                Value::String(signer_registration_record.verification_key_for_concatenation),
                signer_registration_record
                    .verification_key_signature_for_concatenation
                    .map(Value::String)
                    .unwrap_or(Value::Null),
                signer_registration_record
                    .operational_certificate
                    .map(Value::String)
                    .unwrap_or(Value::Null),
                signer_registration_record
                    .kes_evolutions
                    .map(|k| Value::Integer(i64::try_from(k).unwrap()))
                    .unwrap_or(Value::Null),
                signer_registration_record
                    .stake
                    .map(|s| Value::Integer(i64::try_from(s).unwrap()))
                    .unwrap_or(Value::Null),
                #[cfg(feature = "future_snark")]
                signer_registration_record
                    .verification_key_for_snark
                    .map(Value::String)
                    .unwrap_or(Value::Null),
                #[cfg(not(feature = "future_snark"))]
                Value::Null,
                #[cfg(feature = "future_snark")]
                signer_registration_record
                    .verification_key_signature_for_snark
                    .map(Value::String)
                    .unwrap_or(Value::Null),
                #[cfg(not(feature = "future_snark"))]
                Value::Null,
                Value::String(signer_registration_record.created_at.to_rfc3339()),
                #[cfg(feature = "future_snark")]
                signer_registration_record
                    .proof_of_bound_possession_for_snark
                    .map(Value::String)
                    .unwrap_or(Value::Null),
                #[cfg(not(feature = "future_snark"))]
                Value::Null,
            ],
        );

        Self { condition }
    }
}

impl Query for InsertOrReplaceSignerRegistrationRecordQuery {
    type Entity = SignerRegistrationRecord;

    fn filters(&self) -> WhereCondition {
        self.condition.clone()
    }

    fn get_definition(&self, condition: &str) -> String {
        // it is important to alias the fields with the same name as the table
        // since the table cannot be aliased in a RETURNING statement in SQLite.
        let projection = Self::Entity::get_projection().expand(SourceAlias::new(&[(
            "{:signer_registration:}",
            "signer_registration",
        )]));

        format!("insert or replace into signer_registration {condition} returning {projection}")
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::entities::Epoch;
    use mithril_common::test::builder::MithrilFixtureBuilder;
    use mithril_persistence::sqlite::ConnectionExtensions;

    use crate::database::test_helper::main_db_connection;

    use super::*;

    #[test]
    fn test_update_signer_registration_record() {
        let fixture = MithrilFixtureBuilder::default().with_signers(5).build();
        let signer_with_stakes = fixture.signers_with_stake();

        let connection = main_db_connection().unwrap();

        for signer_with_stake in signer_with_stakes.clone() {
            let signer_registration_record =
                SignerRegistrationRecord::from_signer_with_stake(signer_with_stake, Epoch(1));
            let signer_registration_record_saved = connection
                .fetch_first(InsertOrReplaceSignerRegistrationRecordQuery::one(
                    signer_registration_record.clone(),
                ))
                .unwrap();
            assert_eq!(
                Some(signer_registration_record),
                signer_registration_record_saved
            );
        }

        for mut signer_with_stake in signer_with_stakes {
            signer_with_stake.stake += 10;
            let signer_registration_record =
                SignerRegistrationRecord::from_signer_with_stake(signer_with_stake, Epoch(1));
            let signer_registration_record_saved = connection
                .fetch_first(InsertOrReplaceSignerRegistrationRecordQuery::one(
                    signer_registration_record.clone(),
                ))
                .unwrap();
            assert_eq!(
                Some(signer_registration_record),
                signer_registration_record_saved
            );
        }
    }
}
