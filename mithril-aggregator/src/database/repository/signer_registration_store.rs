use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;

use mithril_common::StdResult;
use mithril_common::entities::{Epoch, PartyId, Signer, SignerWithStake};
use mithril_persistence::sqlite::{ConnectionExtensions, SqliteConnection};

use crate::VerificationKeyStorer;
use crate::database::query::{
    DeleteSignerRegistrationRecordQuery, GetSignerRegistrationRecordQuery,
    InsertOrReplaceSignerRegistrationRecordQuery,
};
use crate::database::record::SignerRegistrationRecord;
use crate::services::EpochPruningTask;

/// Service to deal with signer_registration (read & write).
pub struct SignerRegistrationStore {
    connection: Arc<SqliteConnection>,

    /// Number of epochs before previous records will be deleted at the next registration round
    /// opening
    verification_key_epoch_retention_limit: Option<u64>,
}

impl SignerRegistrationStore {
    /// Create a new [SignerRegistrationStore] service
    pub fn new(
        connection: Arc<SqliteConnection>,
        verification_key_epoch_retention_limit: Option<u64>,
    ) -> Self {
        Self {
            connection,
            verification_key_epoch_retention_limit,
        }
    }
}

#[async_trait]
impl VerificationKeyStorer for SignerRegistrationStore {
    async fn save_verification_key(
        &self,
        epoch: Epoch,
        signer: SignerWithStake,
    ) -> StdResult<Option<SignerWithStake>> {
        let existing_record = self
            .connection
            .fetch_first(GetSignerRegistrationRecordQuery::by_signer_id_and_epoch(
                signer.party_id.to_owned(),
                epoch,
            )?)
            .with_context(|| {
                format!(
                    "Get signer registration record failure with signer_id: '{}', epoch: '{}'",
                    signer.party_id, epoch
                )
            })?;

        let _updated_record = self
            .connection
            .fetch_first(InsertOrReplaceSignerRegistrationRecordQuery::one(
                SignerRegistrationRecord::from_signer_with_stake(signer, epoch),
            ))
            .with_context(|| format!("persist verification key failure, epoch: {epoch}"))?;

        match existing_record {
            None => Ok(None),
            Some(previous_record) => Ok(Some(previous_record.into())),
        }
    }

    async fn get_verification_keys(
        &self,
        epoch: Epoch,
    ) -> StdResult<Option<HashMap<PartyId, Signer>>> {
        let cursor = self
            .connection
            .fetch(GetSignerRegistrationRecordQuery::by_epoch(epoch)?)
            .with_context(|| format!("get verification key failure, epoch: {epoch}"))?;

        let signer_with_stakes: HashMap<PartyId, Signer> =
            HashMap::from_iter(cursor.map(|record| (record.signer_id.to_owned(), record.into())));

        match signer_with_stakes.is_empty() {
            true => Ok(None),
            false => Ok(Some(signer_with_stakes)),
        }
    }

    async fn get_signers(&self, epoch: Epoch) -> StdResult<Option<Vec<SignerWithStake>>> {
        let cursor = self
            .connection
            .fetch(GetSignerRegistrationRecordQuery::by_epoch(epoch)?)
            .with_context(|| format!("get verification key failure, epoch: {epoch}"))?;

        let signer_with_stakes: Vec<SignerWithStake> = cursor.map(|record| record.into()).collect();

        match signer_with_stakes.is_empty() {
            true => Ok(None),
            false => Ok(Some(signer_with_stakes)),
        }
    }

    async fn prune_verification_keys(&self, max_epoch_to_prune: Epoch) -> StdResult<()> {
        self.connection
            .apply(DeleteSignerRegistrationRecordQuery::below_epoch_threshold(
                max_epoch_to_prune,
            ))?;

        Ok(())
    }
}

#[async_trait]
impl EpochPruningTask for SignerRegistrationStore {
    fn pruned_data(&self) -> &'static str {
        "Signer registration"
    }

    async fn prune(&self, epoch: Epoch) -> StdResult<()> {
        let registration_epoch = epoch.offset_to_recording_epoch();

        if let Some(retention_limit) = self.verification_key_epoch_retention_limit {
            self.prune_verification_keys(registration_epoch - retention_limit)
                .await
                .with_context(|| {
                    format!(
                        "VerificationKeyStorer can not prune verification keys below epoch: '{}'",
                        registration_epoch - retention_limit
                    )
                })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::database::test_helper::{insert_signer_registrations, main_db_connection};

    use mithril_common::entities::{Epoch, PartyId, Signer, SignerWithStake};
    use mithril_common::test::double::fake_keys;
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::VerificationKeyStorer;

    use super::*;

    /// Build simple fake signers with stakes.
    /// It could be done by `fake_data::signers_with_stakes` which produce verification keys dynamically
    /// but take longer.
    fn build_fake_signers_with_stakes(nb: u64) -> Vec<SignerWithStake> {
        let verification_keys = fake_keys::signer_verification_key();
        let nb_keys = verification_keys.len() as u64;
        (1..=nb)
            .map(|party_idx| SignerWithStake {
                party_id: format!("party_id:{party_idx}"),
                verification_key_for_concatenation: verification_keys
                    [(party_idx % nb_keys) as usize]
                    .try_into()
                    .unwrap(),
                verification_key_signature_for_concatenation: None,
                operational_certificate: None,
                kes_evolutions: None,
                stake: 10,
                #[cfg(feature = "future_snark")]
                verification_key_for_snark: None,
                #[cfg(feature = "future_snark")]
                verification_key_signature_for_snark: None,
                #[cfg(feature = "future_snark")]
                proof_of_bound_possession_for_snark: None,
            })
            .collect()
    }

    fn build_signers(
        nb_epoch: u64,
        signers_per_epoch: usize,
    ) -> HashMap<Epoch, Vec<SignerWithStake>> {
        (1..=nb_epoch)
            .map(|epoch| {
                (
                    Epoch(epoch),
                    build_fake_signers_with_stakes(signers_per_epoch as u64),
                )
            })
            .collect()
    }

    fn insert_golden_signer_registration(connection: &SqliteConnection) {
        connection
            .execute(
                r#"
                insert into signer_registration
                values(
                    'pool1t9uuagsat8hlr0n0ga4wzge0jxlyjuhl6mugrm8atc285vzkf2e',
                    292,
                    '7b22766b223a5b3132382c3134322c31352c37322c35342c37332c32392c3135372c39302c3134392c33342c3235352c35312c31382c34342c33322c36302c34362c3130302c31342c3136342c39362c3138362c31382c32372c3231312c3130322c3130362c35352c332c3137302c3234302c3131342c3134372c3134362c3234382c31352c32312c3232392c3133322c3234362c3230322c3136322c34312c3135312c3138362c3136332c3232302c31342c3231372c3235352c3234352c35352c3231362c3235322c342c3137302c31362c3137382c3230392c3134392c32302c3230352c39322c3232312c38302c32392c3139302c3131372c3138382c3132382c3234372c3133312c37382c3138372c3232332c3231382c3131362c3235352c34332c3130392c3132362c3233302c3130382c33372c3131342c332c3138362c3136352c33322c3133312c3139332c3139302c34342c3134362c3234315d2c22706f70223a5b3134322c3133352c38352c342c3134362c32342c37382c34332c36332c3233382c3235312c37382c3138312c37342c37302c362c39342c3138372c3137382c3133332c3135352c3233342c3235352c3134352c3139372c3137302c3135352c3132392c3234332c3137332c31322c31392c36382c3132392c3131342c36392c3231312c33372c3233322c3139332c3130372c3233332c32392c3130332c3232382c34392c36392c38362c3137322c35352c39342c3132332c372c36322c3135382c33352c31372c3131332c38312c3136312c34342c3234392c35332c36362c39332c37302c3136392c3133372c3135372c3233342c3234372c3232332c37312c3135302c3231362c3130322c3139302c3137362c3135322c34362c3134332c3233302c31322c3138382c33312c3234362c3137312c3130352c3230392c3133382c35352c32382c3134312c36302c3132312c3132305d7d',
                    '7b227369676d61223a7b227369676d61223a7b227369676d61223a7b227369676d61223a7b227369676d61223a7b227369676d61223a5b35322c3230342c36342c3136342c3134382c36302c342c3133372c3132312c312c3130302c38352c3133382c3235302c33382c37352c39302c3133352c31392c35322c3135312c3130302c35392c372c33332c3131322c31332c3138342c3138342c32332c35352c37392c3134332c3231382c3231352c3136362c3137392c36312c3234312c3136342c38342c36302c3234312c3234302c3134362c33332c37342c3136372c37342c3230332c37382c34372c3231362c3132352c37382c31302c38312c3233322c3134332c37302c3234362c382c3130352c345d2c226c68735f706b223a5b3130342c3131332c39302c32332c3231392c3235342c382c3137352c3136372c3133312c3136382c3131322c3130392c3137362c31342c35372c38362c3139372c34392c35312c3136382c3131352c3138372c3137382c392c3233322c38362c3139352c3130362c3134322c3232372c3139365d2c227268735f706b223a5b38372c3136392c39392c3133382c3130352c3133312c3133322c3132362c3139382c3138352c3137302c3132352c39372c3137372c38342c3231302c3137362c3134322c3133382c32312c38362c3133312c3135382c3132332c36332c3131322c39392c3133322c3134352c3231322c382c3233315d7d2c226c68735f706b223a5b34302c38382c39392c372c31362c32302c37352c3132302c3234372c3233302c32372c3233392c35332c3235352c3137302c3132302c3131392c33372c3138362c3130322c35302c33362c39382c3139332c3130332c33372c352c3131362c3134322c3134382c3233322c32355d2c227268735f706b223a5b3130372c3135372c3234342c3230342c3133362c3139332c38382c3130322c3234312c3135392c39392c3233342c38342c3139322c3133302c34372c32302c3136362c322c3230302c37392c3133352c3230352c312c3235332c3233352c32382c3134372c3135352c3132322c33392c3234345d7d2c226c68735f706b223a5b3133332c3131362c3131342c36342c3132322c31332c3138362c3130342c39322c3233372c39372c38322c3232312c38322c35342c3132352c34352c3234342c3139322c39332c35362c3132362c34302c3134362c3131312c3132392c3232312c3234382c362c35342c3233372c3138355d2c227268735f706b223a5b3137312c3137302c33382c3232302c3133302c34372c3133362c3233362c37322c35332c36332c33382c32392c34362c3230352c32392c3234382c3235342c37362c32372c322c3132382c3130372c3131392c3132382c3137302c32322c3131322c3137362c3130322c3136332c37335d7d2c226c68735f706b223a5b3231312c3138392c38342c3139372c302c3231382c3134382c312c34332c36332c38342c3234322c3231392c39342c31302c3134302c3134372c3137322c38342c35392c31352c3131342c3230392c3235302c3230372c31342c3134322c33362c3135372c3230332c37382c3137355d2c227268735f706b223a5b3137302c3132392c3132332c342c3131332c3135322c3232392c3133372c392c32342c3133372c3136362c32352c3136352c34332c3132322c3132332c3230312c3234322c3231302c3137382c3234382c31342c3233302c33392c3231322c31382c33362c34382c38372c39302c3230365d7d2c226c68735f706b223a5b33332c3234322c3130372c39312c3130372c3130322c3136332c36342c33332c3231372c3233342c3138302c33382c312c3138352c3135382c3230372c3234352c3136372c3130352c3134322c33382c3233342c37362c34322c32322c372c3130342c39362c3139382c3234322c35335d2c227268735f706b223a5b39352c34302c392c3131372c3130382c3135362c3138342c3133392c39302c3138382c31352c32312c3131322c31382c3130302c3134362c3130342c352c3135362c39372c3134392c33322c34322c3234302c3134392c3138382c35322c33312c39312c39392c3131382c365d7d2c226c68735f706b223a5b3139332c3234322c37362c3230392c3134312c33372c3130312c36382c37302c392c3134312c33392c3230372c39342c3232362c33392c3136302c3131382c32332c3233302c3234342c3231302c31382c38322c3137332c3135382c3233312c3137392c3138322c31392c32322c3134365d2c227268735f706b223a5b3133322c3232392c3130382c3139392c37312c36392c3233362c36352c31382c3131372c39332c3234332c3234332c37342c36392c39382c3134302c3234392c342c33372c37372c38372c35382c31322c3132302c37332c3230332c39362c36312c3233302c39322c3132385d7d',
                    '5b5b5b3138362c39352c3232362c3137342c3132352c3235302c31302c3232322c3130322c3234302c36352c3235352c34372c3133382c38392c3131302c31342c3131302c32322c3138322c33322c3136362c3231312c392c32302c32302c35352c35382c3232392c3132302c3235302c37315d2c312c3136352c5b3130352c35342c3234352c35362c3231352c3130362c3133392c3231322c3137342c3232332c39302c3234392c3138372c34372c3134382c35302c34302c31352c3131372c3231372c3134392c3132362c3231382c3232352c3133362c36352c3231392c3136302c3134382c39332c3232382c3235312c31392c3231332c3136382c332c3233362c38392c3132302c3135392c3139382c38302c3234342c3138302c33332c3131392c3132382c3230312c3138362c3132302c32312c3130322c36322c3232392c32382c3135352c37362c31392c3235322c3232312c3234372c3137342c3135392c365d5d2c5b3234312c32372c31332c34342c3131342c37382c3138392c3234392c3135302c3135302c35332c3134342c3233362c3135312c38382c3134302c3132382c3136322c36302c3232382c38382c3131312c392c3134342c3233322c38332c39342c3231302c3135362c3136382c33352c3234325d5d',
                    29,
                    9497629046,
                    '2023-08-12T00:03:51.236860002+00:00',
                    null,
                    null
                );
            "#,
            )
            .unwrap();
    }

    #[tokio::test]
    async fn test_golden_master() {
        let connection = main_db_connection().unwrap();
        insert_golden_signer_registration(&connection);

        let repository = SignerRegistrationStore::new(Arc::new(connection), None);
        repository
            .get_verification_keys(Epoch(292))
            .await
            .expect("Getting Golden signer registration should not fail")
            .expect("Signer registration should exist for this epoch");
    }

    pub fn init_signer_registration_store(
        initial_data: HashMap<Epoch, Vec<SignerWithStake>>,
        verification_key_epoch_retention_limit: Option<u64>,
    ) -> Arc<SignerRegistrationStore> {
        let connection = main_db_connection().unwrap();

        let initial_data = initial_data.into_iter().collect();
        insert_signer_registrations(&connection, initial_data).unwrap();

        Arc::new(SignerRegistrationStore::new(
            Arc::new(connection),
            verification_key_epoch_retention_limit,
        ))
    }

    #[tokio::test]
    pub async fn save_key_in_empty_store() {
        let signers = build_signers(0, 0);
        let store = init_signer_registration_store(signers, None);
        let res = store
            .save_verification_key(
                Epoch(0),
                SignerWithStake {
                    party_id: "0".to_string(),
                    verification_key_for_concatenation: fake_keys::signer_verification_key()[0]
                        .try_into()
                        .unwrap(),
                    verification_key_signature_for_concatenation: None,
                    operational_certificate: None,
                    kes_evolutions: None,
                    stake: 10,
                    #[cfg(feature = "future_snark")]
                    verification_key_for_snark: None,
                    #[cfg(feature = "future_snark")]
                    verification_key_signature_for_snark: None,
                    #[cfg(feature = "future_snark")]
                    proof_of_bound_possession_for_snark: None,
                },
            )
            .await
            .unwrap();

        assert!(res.is_none());
    }

    #[tokio::test]
    pub async fn update_signer_in_store() {
        let signers = build_signers(1, 1);
        let signers_on_epoch = signers.get(&Epoch(1)).unwrap().clone();
        let first_signer = signers_on_epoch.first().unwrap();

        let store = init_signer_registration_store(signers, None);
        let res = store
            .save_verification_key(
                Epoch(1),
                SignerWithStake {
                    party_id: first_signer.party_id.clone(),
                    verification_key_for_concatenation: fake_keys::signer_verification_key()[2]
                        .try_into()
                        .unwrap(),
                    verification_key_signature_for_concatenation: None,
                    operational_certificate: None,
                    kes_evolutions: None,
                    stake: 10,
                    #[cfg(feature = "future_snark")]
                    verification_key_for_snark: None,
                    #[cfg(feature = "future_snark")]
                    verification_key_signature_for_snark: None,
                    #[cfg(feature = "future_snark")]
                    proof_of_bound_possession_for_snark: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(
            Some(SignerWithStake {
                party_id: first_signer.party_id.clone(),
                verification_key_for_concatenation: fake_keys::signer_verification_key()[2]
                    .try_into()
                    .unwrap(),
                verification_key_signature_for_concatenation: None,
                operational_certificate: None,
                kes_evolutions: None,
                stake: 10,
                #[cfg(feature = "future_snark")]
                verification_key_for_snark: None,
                #[cfg(feature = "future_snark")]
                verification_key_signature_for_snark: None,
                #[cfg(feature = "future_snark")]
                proof_of_bound_possession_for_snark: None,
            }),
            res,
        );
    }

    #[tokio::test]
    pub async fn get_verification_keys_for_empty_epoch() {
        let signers = build_signers(2, 1);
        let store = init_signer_registration_store(signers, None);
        let res = store.get_verification_keys(Epoch(0)).await.unwrap();

        assert!(res.is_none());
    }

    #[tokio::test]
    pub async fn get_signers_for_empty_epoch() {
        let signers = build_signers(2, 1);
        let store = init_signer_registration_store(signers, None);
        let res = store.get_signers(Epoch(0)).await.unwrap();

        assert!(res.is_none());
    }

    #[tokio::test]
    pub async fn get_verification_keys_for_existing_epoch() {
        let signers = build_signers(2, 2);
        let store = init_signer_registration_store(signers.clone(), None);

        let epoch = Epoch(1);
        let expected_signers = signers
            .get(&epoch)
            .unwrap()
            .iter()
            .map(|s| (s.party_id.clone(), Signer::from(s.clone())))
            .collect::<HashMap<PartyId, Signer>>();

        let res = store.get_verification_keys(epoch).await.unwrap().unwrap();

        assert_eq!(expected_signers, res);
    }

    #[tokio::test]
    pub async fn get_signers_for_existing_epoch() {
        let signers = build_signers(2, 2);
        let store = init_signer_registration_store(signers.clone(), None);

        let epoch = Epoch(1);
        let mut expected_signers = signers.get(&epoch).unwrap().clone();
        expected_signers.sort_by(|a, b| a.party_id.cmp(&b.party_id));

        let mut res = store.get_signers(epoch).await.unwrap().unwrap();
        res.sort_by(|a, b| a.party_id.cmp(&b.party_id));

        assert_eq!(expected_signers, res);
    }

    #[tokio::test]
    pub async fn can_prune_keys_from_given_epoch_retention_limit() {
        let signers = build_signers(6, 2);
        let store = init_signer_registration_store(signers, None);

        for epoch in 1..6 {
            assert!(
                store.get_verification_keys(Epoch(epoch)).await.unwrap().is_some(),
                "Keys should exist before pruning"
            );
            store
                .prune_verification_keys(Epoch(epoch) + 1)
                .await
                .expect("Pruning should not fail");

            let pruned_epoch_keys = store.get_verification_keys(Epoch(epoch)).await.unwrap();
            assert_eq!(None, pruned_epoch_keys);
        }
    }

    async fn get_epochs_in_database_until(
        store: &SignerRegistrationStore,
        until_epoch: Epoch,
    ) -> Vec<Epoch> {
        let mut epochs_in_database = vec![];
        for epoch_number in 1..=(*until_epoch) {
            let current_epoch = Epoch(epoch_number);
            if store.get_verification_keys(current_epoch).await.unwrap().is_some() {
                epochs_in_database.push(current_epoch);
            }
        }

        epochs_in_database
    }

    #[tokio::test]
    async fn prune_verification_keys_epoch_older_than_given_epoch() {
        let signers = build_signers(5, 2);
        let store = init_signer_registration_store(signers, None);

        assert_eq!(
            vec!(Epoch(1), Epoch(2), Epoch(3), Epoch(4), Epoch(5)),
            get_epochs_in_database_until(&store, Epoch(8)).await
        );

        store.prune_verification_keys(Epoch(4)).await.unwrap();

        assert_eq!(
            vec!(Epoch(4), Epoch(5)),
            get_epochs_in_database_until(&store, Epoch(8)).await
        );
    }

    #[tokio::test]
    async fn prune_older_than_threshold() {
        let signers = build_signers(6, 2);
        let verification_key_epoch_retention_limit = Some(4);
        let store = init_signer_registration_store(signers, verification_key_epoch_retention_limit);

        assert_eq!(
            vec!(Epoch(1), Epoch(2), Epoch(3), Epoch(4), Epoch(5), Epoch(6)),
            get_epochs_in_database_until(&store, Epoch(8)).await
        );

        store.prune(Epoch(5)).await.unwrap();

        assert_eq!(
            vec!(Epoch(2), Epoch(3), Epoch(4), Epoch(5), Epoch(6)),
            get_epochs_in_database_until(&store, Epoch(8)).await
        );
    }

    #[tokio::test]
    async fn without_threshold_nothing_is_pruned() {
        let signers = build_signers(6, 2);
        let store = init_signer_registration_store(signers, None);

        assert_eq!(
            vec!(Epoch(1), Epoch(2), Epoch(3), Epoch(4), Epoch(5), Epoch(6)),
            get_epochs_in_database_until(&store, Epoch(8)).await
        );

        store.prune(Epoch(100)).await.unwrap();

        assert_eq!(
            vec!(Epoch(1), Epoch(2), Epoch(3), Epoch(4), Epoch(5), Epoch(6)),
            get_epochs_in_database_until(&store, Epoch(8)).await
        );
    }
}
