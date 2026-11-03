use anyhow::Context;
use sqlite::Value;

use mithril_common::StdResult;
use mithril_persistence::sqlite::{Query, SourceAlias, SqLiteEntity, WhereCondition};

use crate::database::record::SignerRegistrationRecord;

/// Query to insert or replace [SignerRegistrationRecord] in the sqlite database
pub struct InsertOrReplaceSignerRegistrationRecordQuery {
    condition: WhereCondition,
}

impl InsertOrReplaceSignerRegistrationRecordQuery {
    /// Build the query for the record, failing when a numeric field does not fit a database integer.
    pub fn one(signer_registration_record: SignerRegistrationRecord) -> StdResult<Self> {
        let epoch_settings_id = i64::try_from(*signer_registration_record.epoch_settings_id)
            .with_context(|| {
                format!(
                    "Epoch '{}' does not fit in a database integer",
                    signer_registration_record.epoch_settings_id
                )
            })?;
        let kes_evolutions = signer_registration_record
            .kes_evolutions
            .map(|kes_evolutions| {
                i64::try_from(kes_evolutions).with_context(|| {
                    format!("KES evolutions '{kes_evolutions}' do not fit in a database integer")
                })
            })
            .transpose()?;
        let stake = signer_registration_record
            .stake
            .map(|stake| {
                i64::try_from(stake)
                    .with_context(|| format!("Stake '{stake}' does not fit in a database integer"))
            })
            .transpose()?;
        let condition = WhereCondition::new(
            "(signer_id, epoch_setting_id, verification_key, verification_key_signature, operational_certificate, kes_period, stake, verification_key_for_snark, verification_key_signature_for_snark, created_at, proof_of_bound_possession_for_snark) values (?*, ?*, ?*, ?*, ?*, ?*, ?*, ?*, ?*, ?*, ?*)",
            vec![
                Value::String(signer_registration_record.signer_id),
                Value::Integer(epoch_settings_id),
                Value::String(signer_registration_record.verification_key_for_concatenation),
                signer_registration_record
                    .verification_key_signature_for_concatenation
                    .map(Value::String)
                    .unwrap_or(Value::Null),
                signer_registration_record
                    .operational_certificate
                    .map(Value::String)
                    .unwrap_or(Value::Null),
                kes_evolutions.map(Value::Integer).unwrap_or(Value::Null),
                stake.map(Value::Integer).unwrap_or(Value::Null),
                #[cfg(feature = "snark")]
                signer_registration_record
                    .verification_key_for_snark
                    .map(Value::String)
                    .unwrap_or(Value::Null),
                #[cfg(not(feature = "snark"))]
                Value::Null,
                #[cfg(feature = "snark")]
                signer_registration_record
                    .verification_key_signature_for_snark
                    .map(Value::String)
                    .unwrap_or(Value::Null),
                #[cfg(not(feature = "snark"))]
                Value::Null,
                Value::String(signer_registration_record.created_at.to_rfc3339()),
                #[cfg(feature = "snark")]
                signer_registration_record
                    .proof_of_bound_possession_for_snark
                    .map(Value::String)
                    .unwrap_or(Value::Null),
                #[cfg(not(feature = "snark"))]
                Value::Null,
            ],
        );

        Ok(Self { condition })
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
    use mithril_common::crypto_helper::KesEvolutions;
    use mithril_common::entities::{Epoch, SignerWithStake};
    use mithril_common::test::builder::MithrilFixtureBuilder;
    use mithril_common::test::double::fake_keys;
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
                .fetch_first(
                    InsertOrReplaceSignerRegistrationRecordQuery::one(
                        signer_registration_record.clone(),
                    )
                    .unwrap(),
                )
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
                .fetch_first(
                    InsertOrReplaceSignerRegistrationRecordQuery::one(
                        signer_registration_record.clone(),
                    )
                    .unwrap(),
                )
                .unwrap();
            assert_eq!(
                Some(signer_registration_record),
                signer_registration_record_saved
            );
        }
    }

    fn signer_registration_record() -> SignerRegistrationRecord {
        let signer_with_stake = SignerWithStake {
            party_id: "party_id".to_string(),
            verification_key_for_concatenation: fake_keys::signer_verification_key()[0]
                .try_into()
                .unwrap(),
            verification_key_signature_for_concatenation: None,
            operational_certificate: None,
            kes_evolutions: None,
            stake: 10,
            #[cfg(feature = "snark")]
            verification_key_for_snark: None,
            #[cfg(feature = "snark")]
            verification_key_signature_for_snark: None,
            #[cfg(feature = "snark")]
            proof_of_bound_possession_for_snark: None,
        };

        SignerRegistrationRecord::from_signer_with_stake(signer_with_stake, Epoch(1))
    }

    #[test]
    fn one_fails_with_an_epoch_that_does_not_fit_a_database_integer() {
        let mut signer_registration_record = signer_registration_record();
        signer_registration_record.epoch_settings_id = Epoch(u64::MAX);

        assert!(
            InsertOrReplaceSignerRegistrationRecordQuery::one(signer_registration_record).is_err(),
            "an epoch above i64::MAX must be rejected"
        );
    }

    #[test]
    fn one_fails_with_kes_evolutions_that_do_not_fit_a_database_integer() {
        let mut signer_registration_record = signer_registration_record();
        signer_registration_record.kes_evolutions = Some(KesEvolutions(u64::MAX));

        assert!(
            InsertOrReplaceSignerRegistrationRecordQuery::one(signer_registration_record).is_err(),
            "KES evolutions above i64::MAX must be rejected"
        );
    }

    #[test]
    fn one_fails_with_a_stake_that_does_not_fit_a_database_integer() {
        let mut signer_registration_record = signer_registration_record();
        signer_registration_record.stake = Some(u64::MAX);

        assert!(
            InsertOrReplaceSignerRegistrationRecordQuery::one(signer_registration_record).is_err(),
            "a stake above i64::MAX must be rejected"
        );
    }
}
