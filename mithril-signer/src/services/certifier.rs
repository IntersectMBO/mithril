use async_trait::async_trait;
use chrono::Utc;
use slog::{Logger, debug};
use std::sync::Arc;

use mithril_common::StdResult;
use mithril_common::entities::{ProtocolMessage, SignedEntityConfig, SignedEntityType, TimePoint};
use mithril_common::logging::LoggerExtensions;
use mithril_signed_entity_lock::SignedEntityTypeLock;

use crate::entities::BeaconToSign;
use crate::services::{SignaturePublisher, SingleSigner};

/// Certifier Service
///
/// This service is responsible for providing the beacons that need to be signed by the signer.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait CertifierService: Sync + Send {
    /// Get the beacon to sign.
    ///
    /// If all available signed entity have already been signed, `None` is returned.
    async fn get_beacon_to_sign(&self, time_point: TimePoint) -> StdResult<Option<BeaconToSign>>;

    /// Compute and publish a single signature for a given protocol message.
    async fn compute_publish_single_signature(
        &self,
        beacon_to_sign: &BeaconToSign,
        protocol_message: &ProtocolMessage,
    ) -> StdResult<()>;
}

/// Trait to provide the current signed entity configuration that can change over time.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SignedEntityConfigProvider: Sync + Send {
    /// Get the current signed entity configuration.
    async fn get(&self) -> StdResult<SignedEntityConfig>;
}

/// Trait to store beacons that have been signed in order to avoid signing them twice.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SignedBeaconStore: Sync + Send {
    /// Filter out already signed entities from a list of signed entities.
    async fn filter_out_already_signed_entities(
        &self,
        entities: Vec<SignedEntityType>,
    ) -> StdResult<Vec<SignedEntityType>>;

    /// Mark a beacon as signed.
    async fn mark_beacon_as_signed(&self, entity: &BeaconToSign) -> StdResult<()>;
}

/// Implementation of the [Certifier Service][CertifierService] for the Mithril Signer.
pub struct SignerCertifierService {
    signed_beacon_store: Arc<dyn SignedBeaconStore>,
    signed_entity_config_provider: Arc<dyn SignedEntityConfigProvider>,
    signed_entity_type_lock: Arc<SignedEntityTypeLock>,
    single_signer: Arc<dyn SingleSigner>,
    signature_publisher: Arc<dyn SignaturePublisher>,
    logger: Logger,
}

impl SignerCertifierService {
    /// Create a new `SignerCertifierService` instance.
    pub fn new(
        signed_beacon_store: Arc<dyn SignedBeaconStore>,
        signed_entity_config_provider: Arc<dyn SignedEntityConfigProvider>,
        signed_entity_type_lock: Arc<SignedEntityTypeLock>,
        single_signer: Arc<dyn SingleSigner>,
        signature_publisher: Arc<dyn SignaturePublisher>,
        logger: Logger,
    ) -> Self {
        Self {
            signed_beacon_store,
            signed_entity_config_provider,
            signed_entity_type_lock,
            single_signer,
            signature_publisher,
            logger: logger.new_with_component_name::<Self>(),
        }
    }

    async fn list_available_signed_entity_types(
        &self,
        time_point: &TimePoint,
    ) -> StdResult<Vec<SignedEntityType>> {
        let signed_entity_types = self
            .signed_entity_config_provider
            .get()
            .await?
            .list_allowed_signed_entity_types(time_point)?;
        let unlocked_signed_entities = self
            .signed_entity_type_lock
            .filter_unlocked_entries(signed_entity_types);
        let not_already_signed_entities = self
            .signed_beacon_store
            .filter_out_already_signed_entities(unlocked_signed_entities)
            .await?;

        Ok(not_already_signed_entities)
    }
}

#[async_trait]
impl CertifierService for SignerCertifierService {
    async fn get_beacon_to_sign(&self, time_point: TimePoint) -> StdResult<Option<BeaconToSign>> {
        let available_signed_entity_types =
            self.list_available_signed_entity_types(&time_point).await?;

        if available_signed_entity_types.is_empty() {
            Ok(None)
        } else {
            let signed_entity_type = available_signed_entity_types[0].clone();
            let beacon_to_sign =
                BeaconToSign::new(time_point.epoch, signed_entity_type, Utc::now());

            Ok(Some(beacon_to_sign))
        }
    }

    async fn compute_publish_single_signature(
        &self,
        beacon_to_sign: &BeaconToSign,
        protocol_message: &ProtocolMessage,
    ) -> StdResult<()> {
        if let Some(single_signature) =
            self.single_signer.compute_single_signature(protocol_message).await?
        {
            debug!(self.logger, " > There is a single signature to send");
            self.signature_publisher
                .publish(
                    &beacon_to_sign.signed_entity_type,
                    &single_signature,
                    protocol_message,
                )
                .await?;
        } else {
            debug!(self.logger, " > NO single signature to send");
        }

        debug!(self.logger, " > Marking beacon as signed"; "beacon" => ?beacon_to_sign);
        self.signed_beacon_store.mark_beacon_as_signed(beacon_to_sign).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mockall::predicate::eq;

    use mithril_common::entities::{
        CardanoBlocksTransactionsSigningConfig, CardanoTransactionsSigningConfig, ChainPoint,
        Epoch, ProtocolMessagePartKey, SignedEntityTypeDiscriminants,
    };
    use mithril_common::test::double::{Dummy, fake_data};

    use crate::services::{MockSignaturePublisher, MockSingleSigner};

    use super::{tests::tests_tooling::*, *};

    #[tokio::test]
    async fn no_beacon_can_be_signed_if_all_entities_are_locked() {
        let locker = Arc::new(SignedEntityTypeLock::new());
        let _lock_guards: Vec<_> = SignedEntityTypeDiscriminants::all()
            .into_iter()
            .map(|signed_entity_type| locker.lock(signed_entity_type))
            .collect();
        let certifier_service = SignerCertifierService {
            signed_entity_type_lock: locker.clone(),
            signed_entity_config_provider: Arc::new(DumbSignedEntityConfigProvider::new(
                CardanoTransactionsSigningConfig::dummy(),
                CardanoBlocksTransactionsSigningConfig::dummy(),
                SignedEntityTypeDiscriminants::all(),
            )),
            ..SignerCertifierService::dumb_dependencies()
        };

        let beacon_to_sign = certifier_service
            .get_beacon_to_sign(TimePoint::new(1, 14, ChainPoint::dummy()))
            .await
            .unwrap();
        assert_eq!(beacon_to_sign, None);
    }

    #[tokio::test]
    async fn only_one_unlocked_and_not_yet_signed_yield_a_beacon_to_sign() {
        let locker = Arc::new(SignedEntityTypeLock::new());
        let _lock_guards: Vec<_> = SignedEntityTypeDiscriminants::all()
            .into_iter()
            .skip(1)
            .map(|signed_entity_type| locker.lock(signed_entity_type))
            .collect();
        let certifier_service = SignerCertifierService {
            signed_entity_type_lock: locker.clone(),
            signed_entity_config_provider: Arc::new(DumbSignedEntityConfigProvider::new(
                CardanoTransactionsSigningConfig::dummy(),
                CardanoBlocksTransactionsSigningConfig::dummy(),
                SignedEntityTypeDiscriminants::all(),
            )),
            ..SignerCertifierService::dumb_dependencies()
        };

        let beacon_to_sign = certifier_service
            .get_beacon_to_sign(TimePoint::new(3, 14, ChainPoint::dummy()))
            .await
            .unwrap();
        let signed_discriminant: Option<SignedEntityTypeDiscriminants> =
            beacon_to_sign.map(|b| b.signed_entity_type.into());

        assert_eq!(
            SignedEntityTypeDiscriminants::all().first().cloned(),
            signed_discriminant
        );
    }

    #[tokio::test]
    async fn if_already_signed_a_beacon_is_not_returned_anymore() {
        let signed_beacon_store = Arc::new(DumbSignedBeaconStore::default());
        let certifier_service = SignerCertifierService {
            signed_beacon_store: signed_beacon_store.clone(),
            signed_entity_config_provider: Arc::new(DumbSignedEntityConfigProvider::new(
                CardanoTransactionsSigningConfig::dummy(),
                CardanoBlocksTransactionsSigningConfig::dummy(),
                SignedEntityTypeDiscriminants::all(),
            )),
            ..SignerCertifierService::dumb_dependencies()
        };

        let time_point = TimePoint::new(1, 14, ChainPoint::dummy());
        let first_beacon_to_sign = certifier_service
            .get_beacon_to_sign(time_point.clone())
            .await
            .unwrap()
            .unwrap();
        signed_beacon_store
            .mark_beacon_as_signed(&first_beacon_to_sign.clone())
            .await
            .unwrap();
        let second_beacon_to_sign = certifier_service
            .get_beacon_to_sign(time_point)
            .await
            .unwrap()
            .unwrap();

        assert_ne!(
            first_beacon_to_sign.signed_entity_type,
            second_beacon_to_sign.signed_entity_type
        );
    }

    #[tokio::test]
    async fn draining_out_all_beacons_to_sign_use_signed_entity_discriminant_order() {
        let signed_beacon_store = Arc::new(DumbSignedBeaconStore::default());
        let certifier_service = SignerCertifierService {
            signed_beacon_store: signed_beacon_store.clone(),
            signed_entity_config_provider: Arc::new(DumbSignedEntityConfigProvider::new(
                CardanoTransactionsSigningConfig::dummy(),
                CardanoBlocksTransactionsSigningConfig::dummy(),
                SignedEntityTypeDiscriminants::all(),
            )),
            ..SignerCertifierService::dumb_dependencies()
        };

        let time_point = TimePoint::new(1, 14, ChainPoint::dummy());
        let mut previous_beacon_to_sign = certifier_service
            .get_beacon_to_sign(time_point.clone())
            .await
            .unwrap()
            .expect("There should be a beacon to sign since nothing is locked or signed");

        loop {
            signed_beacon_store
                .mark_beacon_as_signed(&previous_beacon_to_sign)
                .await
                .unwrap();
            let next_beacon_to_sign = certifier_service
                .get_beacon_to_sign(time_point.clone())
                .await
                .unwrap();

            if let Some(beacon) = next_beacon_to_sign {
                assert!(
                    SignedEntityTypeDiscriminants::from(
                        &previous_beacon_to_sign.signed_entity_type
                    ) < SignedEntityTypeDiscriminants::from(&beacon.signed_entity_type),
                    "Beacon should follow SignedEntityTypeDiscriminants order"
                );

                previous_beacon_to_sign = beacon;
            } else {
                break;
            }
        }
    }

    #[tokio::test]
    async fn draining_out_all_beacons_to_sign_doesnt_repeat_value() {
        let signed_beacon_store = Arc::new(DumbSignedBeaconStore::default());
        let certifier_service = SignerCertifierService {
            signed_beacon_store: signed_beacon_store.clone(),
            signed_entity_config_provider: Arc::new(DumbSignedEntityConfigProvider::new(
                CardanoTransactionsSigningConfig::dummy(),
                CardanoBlocksTransactionsSigningConfig::dummy(),
                SignedEntityTypeDiscriminants::all(),
            )),
            ..SignerCertifierService::dumb_dependencies()
        };

        let mut all_signed_beacons = vec![];
        while let Some(beacon_to_sign) = certifier_service
            .get_beacon_to_sign(TimePoint::new(1, 14, ChainPoint::dummy()))
            .await
            .unwrap()
        {
            signed_beacon_store
                .mark_beacon_as_signed(&beacon_to_sign)
                .await
                .unwrap();
            all_signed_beacons.push(beacon_to_sign);
        }

        let mut dedup_signed_beacons = all_signed_beacons.clone();
        dedup_signed_beacons.dedup();
        assert!(
            !all_signed_beacons.is_empty(),
            "There should be at least one beacon to sign"
        );
        assert_eq!(
            all_signed_beacons, dedup_signed_beacons,
            "Beacon should not repeat"
        );
    }

    #[tokio::test]
    async fn compute_publish_single_signature_success_if_a_signature_was_issued() {
        let protocol_message = {
            let mut message = ProtocolMessage::new();
            message.set_message_part(ProtocolMessagePartKey::SnapshotDigest, "digest".to_string());
            message
        };
        let beacon_to_sign = BeaconToSign::new(
            Epoch(1),
            SignedEntityType::MithrilStakeDistribution(Epoch(4)),
            Utc::now(),
        );

        let signed_beacons_store = Arc::new(DumbSignedBeaconStore::default());
        let certifier_service = SignerCertifierService {
            single_signer: {
                let mut single_signer = MockSingleSigner::new();
                single_signer
                    .expect_compute_single_signature()
                    .with(eq(protocol_message.clone()))
                    .return_once(|_| Ok(Some(fake_data::single_signature(vec![1, 5, 12]))));
                Arc::new(single_signer)
            },
            signature_publisher: {
                let mut signature_publisher = MockSignaturePublisher::new();
                signature_publisher
                    .expect_publish()
                    .with(
                        eq(beacon_to_sign.signed_entity_type.clone()),
                        eq(fake_data::single_signature(vec![1, 5, 12])),
                        eq(protocol_message.clone()),
                    )
                    .returning(|_, _, _| Ok(()));
                Arc::new(signature_publisher)
            },
            signed_beacon_store: signed_beacons_store.clone(),
            ..SignerCertifierService::dumb_dependencies()
        };

        certifier_service
            .compute_publish_single_signature(&beacon_to_sign, &protocol_message)
            .await
            .expect("Single signature should be computed and published");

        let signed_beacons = signed_beacons_store.signed_beacons().await;
        assert_eq!(
            vec![beacon_to_sign.signed_entity_type.clone()],
            signed_beacons
        );
    }

    #[tokio::test]
    async fn compute_publish_single_signature_success_but_dont_publish_if_no_signature_were_issued()
    {
        let protocol_message = {
            let mut message = ProtocolMessage::new();
            message.set_message_part(ProtocolMessagePartKey::SnapshotDigest, "digest".to_string());
            message
        };
        let beacon_to_sign = BeaconToSign::new(
            Epoch(1),
            SignedEntityType::MithrilStakeDistribution(Epoch(4)),
            Utc::now(),
        );

        let signed_beacons_store = Arc::new(DumbSignedBeaconStore::default());
        let certifier_service = SignerCertifierService {
            single_signer: {
                let mut single_signer = MockSingleSigner::new();
                single_signer
                    .expect_compute_single_signature()
                    .with(eq(protocol_message.clone()))
                    .return_once(|_| Ok(None));
                Arc::new(single_signer)
            },
            signature_publisher: {
                let mut signature_publisher = MockSignaturePublisher::new();
                signature_publisher.expect_publish().never();
                Arc::new(signature_publisher)
            },
            signed_beacon_store: signed_beacons_store.clone(),
            ..SignerCertifierService::dumb_dependencies()
        };

        certifier_service
            .compute_publish_single_signature(&beacon_to_sign, &protocol_message)
            .await
            .unwrap();

        let signed_beacons = signed_beacons_store.signed_beacons().await;
        assert_eq!(
            vec![beacon_to_sign.signed_entity_type.clone()],
            signed_beacons
        );
    }

    #[tokio::test]
    async fn beacon_isnt_mark_as_signed_if_computing_signature_fails() {
        let beacon_to_sign = BeaconToSign::new(
            Epoch(1),
            SignedEntityType::MithrilStakeDistribution(Epoch(4)),
            Utc::now(),
        );

        let signed_beacons_store = Arc::new(DumbSignedBeaconStore::default());
        let certifier_service = SignerCertifierService {
            single_signer: {
                let mut single_signer = MockSingleSigner::new();
                single_signer
                    .expect_compute_single_signature()
                    .return_once(|_| Err(anyhow::anyhow!("error")));
                Arc::new(single_signer)
            },
            signed_beacon_store: signed_beacons_store.clone(),
            ..SignerCertifierService::dumb_dependencies()
        };

        certifier_service
            .compute_publish_single_signature(&beacon_to_sign, &ProtocolMessage::new())
            .await
            .unwrap_err();

        let signed_beacons = signed_beacons_store.signed_beacons().await;
        assert_eq!(Vec::<SignedEntityType>::new(), signed_beacons);
    }

    #[tokio::test]
    async fn beacon_isnt_mark_as_signed_if_publishing_signature_fails() {
        let beacon_to_sign = BeaconToSign::new(
            Epoch(1),
            SignedEntityType::MithrilStakeDistribution(Epoch(4)),
            Utc::now(),
        );

        let signed_beacons_store = Arc::new(DumbSignedBeaconStore::default());
        let certifier_service = SignerCertifierService {
            single_signer: {
                let mut single_signer = MockSingleSigner::new();
                single_signer
                    .expect_compute_single_signature()
                    .return_once(|_| Ok(Some(fake_data::single_signature(vec![1, 5, 12]))));
                Arc::new(single_signer)
            },
            signature_publisher: {
                let mut signature_publisher = MockSignaturePublisher::new();
                signature_publisher
                    .expect_publish()
                    .return_once(|_, _, _| Err(anyhow::anyhow!("error")));
                Arc::new(signature_publisher)
            },
            signed_beacon_store: signed_beacons_store.clone(),
            ..SignerCertifierService::dumb_dependencies()
        };

        certifier_service
            .compute_publish_single_signature(&beacon_to_sign, &ProtocolMessage::new())
            .await
            .unwrap_err();

        let signed_beacons = signed_beacons_store.signed_beacons().await;
        assert_eq!(Vec::<SignedEntityType>::new(), signed_beacons);
    }

    pub mod tests_tooling {
        use mithril_common::entities::CardanoBlocksTransactionsSigningConfig;
        use std::collections::BTreeSet;
        use tokio::sync::RwLock;

        use crate::test::TestLogger;

        use super::*;

        impl SignerCertifierService {
            pub(crate) fn dumb_dependencies() -> Self {
                Self {
                    signed_beacon_store: Arc::new(DumbSignedBeaconStore::default()),
                    signed_entity_config_provider: Arc::new(DumbSignedEntityConfigProvider::new(
                        CardanoTransactionsSigningConfig::dummy(),
                        CardanoBlocksTransactionsSigningConfig::dummy(),
                        SignedEntityTypeDiscriminants::all(),
                    )),
                    signed_entity_type_lock: Arc::new(SignedEntityTypeLock::new()),
                    single_signer: Arc::new(MockSingleSigner::new()),
                    signature_publisher: Arc::new(MockSignaturePublisher::new()),
                    logger: TestLogger::stdout(),
                }
            }
        }

        pub struct DumbSignedEntityConfigProvider {
            config: SignedEntityConfig,
        }

        impl DumbSignedEntityConfigProvider {
            pub fn new(
                cardano_transactions_config: CardanoTransactionsSigningConfig,
                cardano_blocks_transactions_config: CardanoBlocksTransactionsSigningConfig,
                allowed_discriminants: BTreeSet<SignedEntityTypeDiscriminants>,
            ) -> Self {
                Self {
                    config: SignedEntityConfig {
                        cardano_transactions_signing_config: Some(cardano_transactions_config),
                        cardano_blocks_transactions_signing_config: Some(
                            cardano_blocks_transactions_config,
                        ),
                        allowed_discriminants,
                    },
                }
            }
        }

        #[async_trait]
        impl SignedEntityConfigProvider for DumbSignedEntityConfigProvider {
            async fn get(&self) -> StdResult<SignedEntityConfig> {
                Ok(self.config.clone())
            }
        }

        pub struct DumbSignedBeaconStore {
            signed_beacons: RwLock<Vec<SignedEntityType>>,
        }

        impl DumbSignedBeaconStore {
            pub fn new(signed_beacons: Vec<SignedEntityType>) -> Self {
                Self {
                    signed_beacons: RwLock::new(signed_beacons),
                }
            }

            pub async fn signed_beacons(&self) -> Vec<SignedEntityType> {
                self.signed_beacons.read().await.clone()
            }
        }

        impl Default for DumbSignedBeaconStore {
            fn default() -> Self {
                Self::new(vec![])
            }
        }

        #[async_trait]
        impl SignedBeaconStore for DumbSignedBeaconStore {
            async fn filter_out_already_signed_entities(
                &self,
                entities: Vec<SignedEntityType>,
            ) -> StdResult<Vec<SignedEntityType>> {
                let already_signed_entities = self.signed_beacons.read().await.clone();
                Ok(entities
                    .into_iter()
                    .filter(|entity| !already_signed_entities.contains(entity))
                    .collect())
            }

            async fn mark_beacon_as_signed(&self, beacon: &BeaconToSign) -> StdResult<()> {
                let mut already_signed_entities = self.signed_beacons.write().await;
                already_signed_entities.push(beacon.signed_entity_type.clone());
                Ok(())
            }
        }
    }
}
