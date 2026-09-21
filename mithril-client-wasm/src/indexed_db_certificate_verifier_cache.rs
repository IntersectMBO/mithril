use anyhow::{Context, anyhow};
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use js_sys::{Array, Function, Promise, Reflect};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::future::Future;
use wasm_bindgen::prelude::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    DomException, IdbDatabase, IdbFactory, IdbKeyRange, IdbObjectStore, IdbObjectStoreParameters,
    IdbRequest, IdbTransaction, IdbTransactionMode,
};

use mithril_client::certificate_client::{CertificateVerifierCache, CertificateVerifierCacheSpace};
use mithril_client::{MithrilCertificate, MithrilResult};

const DATABASE_VERSION: u32 = 1;
const COMMITTED_CERTIFICATES_STORE: &str = "committed_certificates";
const STAGED_CERTIFICATES_STORE: &str = "staged_certificates";
const STAGED_BATCHES_STORE: &str = "staged_batches";
const ALL_STORES: [&str; 3] = [
    COMMITTED_CERTIFICATES_STORE,
    STAGED_CERTIFICATES_STORE,
    STAGED_BATCHES_STORE,
];
const EXPIRE_AT_INDEX: &str = "expire_at";
const DEFAULT_STAGING_BATCH_TTL: TimeDelta = TimeDelta::minutes(15);

/// An IndexedDB cache for the certificate verifier, persisted by the browser across page loads.
///
/// Object stores of the database:
/// - `committed_certificates`: one record per verified certificate, keyed by the space that
///   validated it and by certificate hash, holding the certificate and its expiration date.
/// - `staged_certificates`: the certificates of the chain validations in progress, keyed by
///   certificate chain validation id and certificate hash.
/// - `staged_batches`: one record per chain validation in progress, keyed by certificate chain
///   validation id, holding the expiration date of the batch.
///
/// A commit moves the staged records of a batch to the committed store in a single transaction,
/// so an interrupted commit never leaves a partially committed batch.
/// A staged batch expires when nothing has been staged under its id for the staging expiration
/// delay, expired batches and committed certificates are swept when a new batch is staged and
/// when a batch is committed.
///
/// Note: as this cache is based on IndexedDB, it can only be used in a browser (it is not
/// compatible with nodejs or other environments without IndexedDB).
pub struct IndexedDbCertificateVerifierCache {
    /// Name of the IndexedDB database
    database_name: String,
    /// Time a committed certificate stays valid
    expiration_delay: TimeDelta,
    /// Time a staged batch survives without new staged certificate
    staging_expiration_delay: TimeDelta,
}

/// A record of the committed certificates store
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct CommittedCertificateRecord {
    /// Identifier of the space the certificate is committed to, first part of the record key
    space: String,
    /// Hash of the certificate, second part of the record key
    certificate_hash: String,
    /// Date after which the record is ignored
    #[serde(with = "chrono::serde::ts_milliseconds")]
    expire_at: DateTime<Utc>,
    /// The certificate encoded in JSON
    certificate: String,
}

/// A record of the staged certificates store
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct StagedCertificateRecord {
    /// Id of the chain validation that staged the certificate, first part of the record key
    certificate_chain_validation_id: String,
    /// Hash of the certificate, second part of the record key
    certificate_hash: String,
    /// The certificate encoded in JSON
    certificate: String,
}

/// A record of the staged batches store
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct StagedBatchRecord {
    /// Id of the chain validation, key of the record
    certificate_chain_validation_id: String,
    /// Date after which the batch is dropped
    #[serde(with = "chrono::serde::ts_milliseconds")]
    expire_at: DateTime<Utc>,
}

impl CommittedCertificateRecord {
    /// Whether the record is still valid at the given date
    fn is_valid_at(&self, date: DateTime<Utc>) -> bool {
        date < self.expire_at
    }

    /// Decode the cached certificate
    fn certificate(&self) -> MithrilResult<MithrilCertificate> {
        serde_json::from_str(&self.certificate).context("Failed to decode a cached certificate")
    }
}

impl StagedCertificateRecord {
    /// Encode a certificate staged by the given chain validation
    fn new(
        certificate_chain_validation_id: &str,
        certificate: &MithrilCertificate,
    ) -> MithrilResult<Self> {
        Ok(Self {
            certificate_chain_validation_id: certificate_chain_validation_id.to_string(),
            certificate_hash: certificate.hash.clone(),
            certificate: serde_json::to_string(certificate)
                .context("Failed to encode a certificate to cache")?,
        })
    }

    /// Turn the staged record into a record committed to the given space and expiring at the
    /// given date
    fn into_committed(
        self,
        space: &CertificateVerifierCacheSpace,
        expire_at: DateTime<Utc>,
    ) -> CommittedCertificateRecord {
        CommittedCertificateRecord {
            space: space.as_str().to_string(),
            certificate_hash: self.certificate_hash,
            expire_at,
            certificate: self.certificate,
        }
    }
}

impl IndexedDbCertificateVerifierCache {
    /// `IndexedDbCertificateVerifierCache` factory
    ///
    /// The database is created on first use.
    pub fn new(database_name: &str, expiration_delay: TimeDelta) -> Self {
        Self {
            database_name: database_name.to_string(),
            expiration_delay,
            staging_expiration_delay: DEFAULT_STAGING_BATCH_TTL,
        }
    }

    /// Set how long a staged (uncommitted) batch survives without new staged certificate before
    /// being silently dropped instead of committed.
    ///
    /// Warn: Too short and a slow-but-valid `verify_chain` call may never get to commit, and too
    /// long and an abandoned batch from a failed run lingers longer.
    pub fn with_staging_expiration_delay(mut self, staging_expiration_delay: TimeDelta) -> Self {
        self.staging_expiration_delay = staging_expiration_delay;
        self
    }

    /// Run the given operation in a transaction on the given stores, the database is opened for
    /// the operation and closed afterward, the transaction is aborted when the operation fails.
    async fn run_transaction<T, Fut>(
        &self,
        stores: &[&str],
        mode: IdbTransactionMode,
        operation: impl FnOnce(IdbTransaction) -> Fut,
    ) -> MithrilResult<T>
    where
        Fut: Future<Output = MithrilResult<T>>,
    {
        let connection = DatabaseConnection::open(&self.database_name).await?;
        let transaction = connection.transaction(stores, mode)?;
        let completion = transaction.completion();

        match operation(transaction.clone()).await {
            Ok(value) => {
                completion
                    .settled()
                    .await
                    .js_context("Certificate cache transaction failed")?;
                Ok(value)
            }
            Err(error) => {
                let _ = transaction.abort();
                Err(error)
            }
        }
    }

    /// Read a certificate record committed to the given space, ignoring an expired one
    async fn read_committed(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &str,
    ) -> MithrilResult<Option<CommittedCertificateRecord>> {
        let committed_key = Self::committed_key(space, certificate_hash);

        self.run_transaction(
            &[COMMITTED_CERTIFICATES_STORE],
            IdbTransactionMode::Readonly,
            |transaction| async move {
                let committed = Self::store(&transaction, COMMITTED_CERTIFICATES_STORE)?;
                let record =
                    Self::read_record::<CommittedCertificateRecord>(committed.get(&committed_key))
                        .await?;

                Ok(record.filter(|record| record.is_valid_at(Utc::now())))
            },
        )
        .await
    }

    /// Delete the expired staged batches with their certificates and the expired committed
    /// certificates
    async fn sweep_expired(transaction: &IdbTransaction) -> MithrilResult<()> {
        let now = Utc::now();
        let batches = Self::store(transaction, STAGED_BATCHES_STORE)?;
        let staged = Self::store(transaction, STAGED_CERTIFICATES_STORE)?;
        for batch_key in Self::expired_keys(&batches, now).await? {
            let batch_range = Self::batch_key_range(&batch_key)?;
            Self::issue(staged.delete(&batch_range))?;
            Self::issue(batches.delete(&batch_key))?;
        }

        let committed = Self::store(transaction, COMMITTED_CERTIFICATES_STORE)?;
        for certificate_key in Self::expired_keys(&committed, now).await? {
            Self::issue(committed.delete(&certificate_key))?;
        }

        Ok(())
    }

    /// Keys of the records of a store expired at the given date
    async fn expired_keys(
        store: &IdbObjectStore,
        date: DateTime<Utc>,
    ) -> MithrilResult<Vec<JsValue>> {
        let index = store
            .index(EXPIRE_AT_INDEX)
            .js_context("Failed to access the certificate cache expiration index")?;
        let expired_range = IdbKeyRange::upper_bound(&Self::timestamp(date))
            .js_context("Failed to build the certificate cache expiration range")?;

        Self::read_keys(index.get_all_keys_with_key(&expired_range)).await
    }

    /// Key range of the certificates staged under the given batch key
    fn batch_key_range(batch_key: &JsValue) -> MithrilResult<IdbKeyRange> {
        IdbKeyRange::bound(
            &Array::of1(batch_key),
            &Array::of2(batch_key, &Array::new()),
        )
        .js_context("Failed to build a certificate cache batch key range")
    }

    /// Key of the record of a certificate committed to the given space
    fn committed_key(space: &CertificateVerifierCacheSpace, certificate_hash: &str) -> Array {
        Array::of2(
            &JsValue::from_str(space.as_str()),
            &JsValue::from_str(certificate_hash),
        )
    }

    /// The given date as stored in the expiration indexes
    fn timestamp(date: DateTime<Utc>) -> JsValue {
        JsValue::from_f64(date.timestamp_millis() as f64)
    }

    /// Get an object store of the transaction
    fn store(transaction: &IdbTransaction, name: &str) -> MithrilResult<IdbObjectStore> {
        transaction.object_store(name).js_context(format!(
            "Failed to access the certificate cache store '{name}'"
        ))
    }

    /// Store a record, replacing the record with the same key if any
    fn put_record<T: Serialize>(store: &IdbObjectStore, record: &T) -> MithrilResult<()> {
        let value = serde_wasm_bindgen::to_value(record)
            .map_err(|error| anyhow!("Failed to encode a certificate cache record: {error}"))?;

        Self::issue(store.put(&value))
    }

    /// Issue a write request, a failure aborts the transaction and is reported by its completion
    fn issue(request: Result<IdbRequest, JsValue>) -> MithrilResult<()> {
        request
            .js_context("Failed to issue a certificate cache request")
            .map(|_| ())
    }

    /// Issue a request and decode its result as one record, absent when the key is unknown
    async fn read_record<T: DeserializeOwned>(
        request: Result<IdbRequest, JsValue>,
    ) -> MithrilResult<Option<T>> {
        let value = Self::request_result(request).await?;
        if value.is_undefined() {
            return Ok(None);
        }

        Self::decode_record(value).map(Some)
    }

    /// Issue a request and decode its result as a list of records
    async fn read_records<T: DeserializeOwned>(
        request: Result<IdbRequest, JsValue>,
    ) -> MithrilResult<Vec<T>> {
        Self::read_array(request)
            .await?
            .iter()
            .map(Self::decode_record)
            .collect()
    }

    /// Issue a request and return its result as a list of keys
    async fn read_keys(request: Result<IdbRequest, JsValue>) -> MithrilResult<Vec<JsValue>> {
        Ok(Self::read_array(request).await?.iter().collect())
    }

    /// Issue a request and return its result as an array
    async fn read_array(request: Result<IdbRequest, JsValue>) -> MithrilResult<Array> {
        Self::request_result(request)
            .await?
            .dyn_into::<Array>()
            .map_err(|value| anyhow!("Unexpected certificate cache request result: {value:?}"))
    }

    /// Issue a request and await its result
    async fn request_result(request: Result<IdbRequest, JsValue>) -> MithrilResult<JsValue> {
        request
            .js_context("Failed to issue a certificate cache request")?
            .settled()
            .await
            .js_context("Certificate cache request failed")
    }

    /// Decode a stored record
    fn decode_record<T: DeserializeOwned>(value: JsValue) -> MithrilResult<T> {
        serde_wasm_bindgen::from_value(value)
            .map_err(|error| anyhow!("Failed to decode a certificate cache record: {error}"))
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl CertificateVerifierCache for IndexedDbCertificateVerifierCache {
    async fn stage_certificate(
        &self,
        certificate_chain_validation_id: &str,
        certificate: MithrilCertificate,
    ) -> MithrilResult<()> {
        let record = StagedCertificateRecord::new(certificate_chain_validation_id, &certificate)?;
        let batch = StagedBatchRecord {
            certificate_chain_validation_id: certificate_chain_validation_id.to_string(),
            expire_at: Utc::now() + self.staging_expiration_delay,
        };

        self.run_transaction(
            &ALL_STORES,
            IdbTransactionMode::Readwrite,
            |transaction| async move {
                let batches = Self::store(&transaction, STAGED_BATCHES_STORE)?;
                let batch_key = JsValue::from_str(certificate_chain_validation_id);
                let is_new_batch = Self::read_record::<StagedBatchRecord>(batches.get(&batch_key))
                    .await?
                    .is_none();
                if is_new_batch {
                    Self::sweep_expired(&transaction).await?;
                }

                Self::put_record(&batches, &batch)?;
                Self::put_record(
                    &Self::store(&transaction, STAGED_CERTIFICATES_STORE)?,
                    &record,
                )
            },
        )
        .await
    }

    async fn commit_staged_certificates(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_chain_validation_id: &str,
    ) -> MithrilResult<()> {
        let expire_at = Utc::now() + self.expiration_delay;

        self.run_transaction(
            &ALL_STORES,
            IdbTransactionMode::Readwrite,
            |transaction| async move {
                Self::sweep_expired(&transaction).await?;

                let staged = Self::store(&transaction, STAGED_CERTIFICATES_STORE)?;
                let committed = Self::store(&transaction, COMMITTED_CERTIFICATES_STORE)?;
                let batch_key = JsValue::from_str(certificate_chain_validation_id);
                let batch_range = Self::batch_key_range(&batch_key)?;
                for record in Self::read_records::<StagedCertificateRecord>(
                    staged.get_all_with_key(&batch_range),
                )
                .await?
                {
                    Self::put_record(&committed, &record.into_committed(space, expire_at))?;
                }

                Self::issue(staged.delete(&batch_range))?;
                Self::issue(Self::store(&transaction, STAGED_BATCHES_STORE)?.delete(&batch_key))
            },
        )
        .await
    }

    async fn get_certificate_by_hash(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &str,
    ) -> MithrilResult<Option<MithrilCertificate>> {
        self.read_committed(space, certificate_hash)
            .await?
            .map(|record| record.certificate())
            .transpose()
    }

    async fn certificate_exist(
        &self,
        space: &CertificateVerifierCacheSpace,
        certificate_hash: &str,
    ) -> MithrilResult<bool> {
        Ok(self.read_committed(space, certificate_hash).await?.is_some())
    }

    async fn reset(&self) -> MithrilResult<()> {
        self.run_transaction(
            &ALL_STORES,
            IdbTransactionMode::Readwrite,
            |transaction| async move {
                for store in ALL_STORES {
                    Self::issue(Self::store(&transaction, store)?.clear())?;
                }

                Ok(())
            },
        )
        .await
    }
}

/// A connection to the cache database, closed when dropped
struct DatabaseConnection {
    /// The open database
    database: IdbDatabase,
}

impl DatabaseConnection {
    /// Open the database with the given name, creating its stores on first use
    async fn open(database_name: &str) -> MithrilResult<Self> {
        let open_request = Self::factory()?
            .open_with_u32(database_name, DATABASE_VERSION)
            .js_context("Failed to open the certificate cache database")?;
        let upgraded_request = open_request.clone();
        let on_upgrade_needed = Closure::once(move || {
            let created = upgraded_request
                .result()
                .and_then(|database| database.dyn_into::<IdbDatabase>())
                .and_then(|database| Self::create_stores(&database));
            if created.is_err()
                && let Some(transaction) = upgraded_request.transaction()
            {
                let _ = transaction.abort();
            }
        });
        open_request.set_onupgradeneeded(Some(on_upgrade_needed.as_ref().unchecked_ref()));

        let database = open_request
            .settled()
            .await
            .js_context("Failed to open the certificate cache database")?
            .dyn_into::<IdbDatabase>()
            .map_err(|value| anyhow!("Unexpected certificate cache database handle: {value:?}"))?;

        Ok(Self { database })
    }

    /// The IndexedDB factory of the JS global scope, a window or a worker
    fn factory() -> MithrilResult<IdbFactory> {
        Reflect::get(&js_sys::global(), &JsValue::from_str("indexedDB"))
            .ok()
            .and_then(|factory| factory.dyn_into::<IdbFactory>().ok())
            .ok_or_else(|| anyhow!("IndexedDB is not available in this environment"))
    }

    /// Open a transaction on the given stores
    fn transaction(
        &self,
        stores: &[&str],
        mode: IdbTransactionMode,
    ) -> MithrilResult<IdbTransaction> {
        let store_names = stores.iter().map(|name| JsValue::from_str(name)).collect::<Array>();

        self.database
            .transaction_with_str_sequence_and_mode(&store_names, mode)
            .js_context("Failed to open a certificate cache transaction")
    }

    /// Create the object stores and their expiration indexes
    fn create_stores(database: &IdbDatabase) -> Result<(), JsValue> {
        let committed = Self::create_store(
            database,
            COMMITTED_CERTIFICATES_STORE,
            &Array::of2(
                &JsValue::from_str("space"),
                &JsValue::from_str("certificate_hash"),
            ),
        )?;
        committed.create_index_with_str(EXPIRE_AT_INDEX, "expire_at")?;
        Self::create_store(
            database,
            STAGED_CERTIFICATES_STORE,
            &Array::of2(
                &JsValue::from_str("certificate_chain_validation_id"),
                &JsValue::from_str("certificate_hash"),
            ),
        )?;
        let batches = Self::create_store(
            database,
            STAGED_BATCHES_STORE,
            &JsValue::from_str("certificate_chain_validation_id"),
        )?;
        batches.create_index_with_str(EXPIRE_AT_INDEX, "expire_at")?;

        Ok(())
    }

    /// Create an object store whose records are keyed by the given key path
    fn create_store(
        database: &IdbDatabase,
        name: &str,
        key_path: &JsValue,
    ) -> Result<IdbObjectStore, JsValue> {
        let parameters = IdbObjectStoreParameters::new();
        parameters.set_key_path(key_path);

        database.create_object_store_with_optional_parameters(name, &parameters)
    }
}

impl Drop for DatabaseConnection {
    fn drop(&mut self) {
        self.database.close();
    }
}

/// A promise settled by JS event callbacks, kept alive with the callbacks until it is awaited
struct EventPromise {
    /// The promise
    future: JsFuture,
    /// The callbacks settling the promise
    _callbacks: Vec<Closure<dyn FnMut()>>,
}

impl EventPromise {
    /// Create a promise settled by the callbacks registered by the given function with the
    /// resolve and reject functions of the promise
    fn new(register: impl FnOnce(Function, Function) -> Vec<Closure<dyn FnMut()>>) -> Self {
        let mut register = Some(register);
        let mut callbacks = Vec::new();
        let promise = Promise::new(&mut |resolve, reject| {
            if let Some(register) = register.take() {
                callbacks = register(resolve, reject);
            }
        });

        Self {
            future: JsFuture::from(promise),
            _callbacks: callbacks,
        }
    }

    /// A callback settling a promise through the given function with the value computed when it
    /// fires, settling again is harmless
    fn callback(settle: Function, value: impl Fn() -> JsValue + 'static) -> Closure<dyn FnMut()> {
        Closure::wrap(Box::new(move || {
            let _ = settle.call1(&JsValue::NULL, &value());
        }))
    }

    /// Wait for the promise to be settled
    async fn settled(self) -> Result<JsValue, JsValue> {
        self.future.await
    }
}

/// Extension to await IndexedDB requests
trait IdbRequestExt {
    /// Wait for the request to succeed with its result or to fail with its error
    async fn settled(&self) -> Result<JsValue, JsValue>;
}

impl IdbRequestExt for IdbRequest {
    async fn settled(&self) -> Result<JsValue, JsValue> {
        EventPromise::new(|resolve, reject| {
            let succeeded = self.clone();
            let on_success = EventPromise::callback(resolve, move || {
                succeeded.result().unwrap_or(JsValue::UNDEFINED)
            });
            let failed = self.clone();
            let on_error = EventPromise::callback(reject, move || {
                failed
                    .error()
                    .ok()
                    .flatten()
                    .map(JsValue::from)
                    .unwrap_or(JsValue::UNDEFINED)
            });
            self.set_onsuccess(Some(on_success.as_ref().unchecked_ref()));
            self.set_onerror(Some(on_error.as_ref().unchecked_ref()));

            vec![on_success, on_error]
        })
        .settled()
        .await
    }
}

/// Extension to await IndexedDB transactions
trait IdbTransactionExt {
    /// Watch the transaction, the promise resolves when it completes and rejects when it aborts
    /// or fails
    fn completion(&self) -> EventPromise;
}

impl IdbTransactionExt for IdbTransaction {
    fn completion(&self) -> EventPromise {
        EventPromise::new(|resolve, reject| {
            let on_complete = EventPromise::callback(resolve, || JsValue::UNDEFINED);
            let failed = self.clone();
            let on_failure = EventPromise::callback(reject, move || {
                failed
                    .error()
                    .map(JsValue::from)
                    .unwrap_or_else(|| JsValue::from_str("Transaction aborted"))
            });
            self.set_oncomplete(Some(on_complete.as_ref().unchecked_ref()));
            self.set_onerror(Some(on_failure.as_ref().unchecked_ref()));
            self.set_onabort(Some(on_failure.as_ref().unchecked_ref()));

            vec![on_complete, on_failure]
        })
    }
}

/// A JS error value, displayed by its name and message when it is a DOM exception
struct JsError(JsValue);

impl fmt::Display for JsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.dyn_ref::<DomException>() {
            Some(exception) => write!(formatter, "{}: {}", exception.name(), exception.message()),
            None => write!(formatter, "{:?}", self.0),
        }
    }
}

/// Extension adding a context to a JS error
trait JsErrorContext<T> {
    /// Convert a JS error into a Mithril error with the given context
    fn js_context<C: fmt::Display>(self, context: C) -> MithrilResult<T>;
}

impl<T> JsErrorContext<T> for Result<T, JsValue> {
    fn js_context<C: fmt::Display>(self, context: C) -> MithrilResult<T> {
        self.map_err(|error| anyhow!("{context}: {}", JsError(error)))
    }
}

#[cfg(all(test, not(feature = "test-node")))]
mod tests {
    use std::collections::{HashMap, HashSet};

    use chrono::SubsecRound;
    use mithril_common::crypto_helper::{GenesisEd25519Signer, GenesisSigner};
    use mithril_common::test::double::Dummy;
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    fn dummy_certificate(hash: &str, previous_hash: &str) -> MithrilCertificate {
        MithrilCertificate {
            hash: hash.to_string(),
            previous_hash: previous_hash.to_string(),
            ..Dummy::dummy()
        }
    }

    fn space() -> CertificateVerifierCacheSpace {
        CertificateVerifierCacheSpace::from_genesis_verifier(
            &GenesisSigner::create_deterministic_signer().create_verifier(),
        )
    }

    fn other_space() -> CertificateVerifierCacheSpace {
        CertificateVerifierCacheSpace::from_genesis_verifier(
            &GenesisSigner::from_ed25519(GenesisEd25519Signer::create_non_deterministic_signer())
                .create_verifier(),
        )
    }

    async fn empty_cache(
        database_name: &str,
        expiration_delay: TimeDelta,
    ) -> IndexedDbCertificateVerifierCache {
        let cache = IndexedDbCertificateVerifierCache::new(database_name, expiration_delay);
        cache.reset().await.unwrap();
        cache
    }

    async fn commit_certificates(
        cache: &IndexedDbCertificateVerifierCache,
        space: &CertificateVerifierCacheSpace,
        certificate_chain_validation_id: &str,
        certificates: impl IntoIterator<Item = MithrilCertificate>,
    ) {
        for certificate in certificates {
            cache
                .stage_certificate(certificate_chain_validation_id, certificate)
                .await
                .unwrap();
        }
        cache
            .commit_staged_certificates(space, certificate_chain_validation_id)
            .await
            .unwrap();
    }

    impl IndexedDbCertificateVerifierCache {
        /// `Test only` Return the committed records
        async fn committed_records(&self) -> Vec<CommittedCertificateRecord> {
            self.run_transaction(
                &[COMMITTED_CERTIFICATES_STORE],
                IdbTransactionMode::Readonly,
                |transaction| async move {
                    Self::read_records(
                        Self::store(&transaction, COMMITTED_CERTIFICATES_STORE)?.get_all(),
                    )
                    .await
                },
            )
            .await
            .unwrap()
        }

        /// `Test only` Return the record of the given certificate hash committed to the given space
        async fn committed_record(
            &self,
            space: &CertificateVerifierCacheSpace,
            certificate_hash: &str,
        ) -> CommittedCertificateRecord {
            self.committed_records()
                .await
                .into_iter()
                .find(|record| {
                    record.space == space.as_str() && record.certificate_hash == certificate_hash
                })
                .expect("Key not found")
        }

        /// `Test only` Return the content of the given space of the cache (without the expiration date)
        async fn content(
            &self,
            space: &CertificateVerifierCacheSpace,
        ) -> HashMap<String, MithrilCertificate> {
            self.committed_records()
                .await
                .into_iter()
                .filter(|record| record.space == space.as_str())
                .map(|record| {
                    (
                        record.certificate_hash.clone(),
                        record.certificate().unwrap(),
                    )
                })
                .collect()
        }

        /// `Test only` Return the ids of staged batches
        async fn staged_batch_ids(&self) -> HashSet<String> {
            let batches: Vec<StagedBatchRecord> = self
                .run_transaction(
                    &[STAGED_BATCHES_STORE],
                    IdbTransactionMode::Readonly,
                    |transaction| async move {
                        Self::read_records(
                            Self::store(&transaction, STAGED_BATCHES_STORE)?.get_all(),
                        )
                        .await
                    },
                )
                .await
                .unwrap();

            batches
                .into_iter()
                .map(|batch| batch.certificate_chain_validation_id)
                .collect()
        }

        /// `Test only` Return the hashes of the certificates staged under the given id
        async fn staged_hashes(&self, certificate_chain_validation_id: &str) -> HashSet<String> {
            let records: Vec<StagedCertificateRecord> = self
                .run_transaction(
                    &[STAGED_CERTIFICATES_STORE],
                    IdbTransactionMode::Readonly,
                    |transaction| async move {
                        let batch_range = Self::batch_key_range(&JsValue::from_str(
                            certificate_chain_validation_id,
                        ))?;
                        Self::read_records(
                            Self::store(&transaction, STAGED_CERTIFICATES_STORE)?
                                .get_all_with_key(&batch_range),
                        )
                        .await
                    },
                )
                .await
                .unwrap();

            records.into_iter().map(|record| record.certificate_hash).collect()
        }
    }

    mod stage_commit {
        use super::*;

        #[wasm_bindgen_test]
        async fn staging_a_certificate_does_not_make_it_retrievable_before_commit() {
            let cache = empty_cache(
                "staging_a_certificate_does_not_make_it_retrievable_before_commit",
                TimeDelta::hours(1),
            )
            .await;
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
            assert_eq!(
                HashSet::from(["hash".to_string()]),
                cache.staged_hashes("chain_validation_id").await
            );
        }

        #[wasm_bindgen_test]
        async fn committing_makes_previously_staged_certificates_retrievable() {
            let cache = empty_cache(
                "committing_makes_previously_staged_certificates_retrievable",
                TimeDelta::hours(1),
            )
            .await;
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(
                Some(dummy_certificate("hash", "parent")),
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
            assert!(cache.staged_hashes("chain_validation_id").await.is_empty());
            assert!(cache.staged_batch_ids().await.is_empty());
        }

        #[wasm_bindgen_test]
        async fn committing_one_id_does_not_expose_certificates_staged_under_another_id() {
            let cache = empty_cache(
                "committing_one_id_does_not_expose_certificates_staged_under_another_id",
                TimeDelta::hours(1),
            )
            .await;
            cache
                .stage_certificate("chain_id_a", dummy_certificate("hash_a", "parent"))
                .await
                .unwrap();
            cache
                .stage_certificate("chain_id_b", dummy_certificate("hash_b", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_id_a")
                .await
                .unwrap();

            assert!(
                cache
                    .get_certificate_by_hash(&space(), "hash_a")
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash_b").await.unwrap()
            );
            assert_eq!(
                HashSet::from(["chain_id_b".to_string()]),
                cache.staged_batch_ids().await
            );
        }

        #[wasm_bindgen_test]
        async fn committing_an_unknown_id_is_a_no_op_not_an_error() {
            let cache = empty_cache(
                "committing_an_unknown_id_is_a_no_op_not_an_error",
                TimeDelta::hours(1),
            )
            .await;

            cache
                .commit_staged_certificates(&space(), "never_staged")
                .await
                .unwrap();

            assert_eq!(HashMap::new(), cache.content(&space()).await);
        }

        #[wasm_bindgen_test]
        async fn committing_the_same_id_twice_is_a_no_op_the_second_time() {
            let cache = empty_cache(
                "committing_the_same_id_twice_is_a_no_op_the_second_time",
                TimeDelta::hours(1),
            )
            .await;
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(1, cache.content(&space()).await.len());
        }

        #[wasm_bindgen_test]
        async fn committing_an_expired_staged_batch_does_not_commit_it() {
            let cache = empty_cache(
                "committing_an_expired_staged_batch_does_not_commit_it",
                TimeDelta::hours(1),
            )
            .await
            .with_staging_expiration_delay(TimeDelta::zero());
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
            assert!(cache.staged_batch_ids().await.is_empty());
        }

        #[wasm_bindgen_test]
        async fn committing_in_empty_cache_adds_new_item_that_expires_after_parametrized_delay() {
            let expiration_delay = TimeDelta::hours(1);
            let start_time = Utc::now().trunc_subsecs(3);
            let cache = empty_cache(
                "committing_in_empty_cache_adds_new_item_that_expires_after_parametrized_delay",
                expiration_delay,
            )
            .await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            let records = cache.committed_records().await;

            assert_eq!(1, records.len());
            assert_eq!("hash", records[0].certificate_hash);
            assert!(records[0].expire_at - start_time >= expiration_delay);
        }

        #[wasm_bindgen_test]
        async fn committing_new_hash_does_not_alter_existing_values() {
            let cache = empty_cache(
                "committing_new_hash_does_not_alter_existing_values",
                TimeDelta::hours(1),
            )
            .await;
            commit_certificates(
                &cache,
                &space(),
                "initial_id",
                [
                    dummy_certificate("existing_hash", "existing_parent"),
                    dummy_certificate("another_hash", "another_parent"),
                ],
            )
            .await;

            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("new_hash", "new_parent")],
            )
            .await;

            assert_eq!(
                HashMap::from([
                    (
                        "existing_hash".to_string(),
                        dummy_certificate("existing_hash", "existing_parent")
                    ),
                    (
                        "another_hash".to_string(),
                        dummy_certificate("another_hash", "another_parent")
                    ),
                    (
                        "new_hash".to_string(),
                        dummy_certificate("new_hash", "new_parent")
                    ),
                ]),
                cache.content(&space()).await
            );
        }

        #[wasm_bindgen_test]
        async fn committing_a_certificate_with_an_existing_hash_updates_data_and_expiration_time() {
            let expiration_delay = TimeDelta::days(2);
            let cache = empty_cache(
                "committing_a_certificate_with_an_existing_hash_updates_data_and_expiration_time",
                expiration_delay,
            )
            .await;
            let before_update = dummy_certificate("hash", "parent");
            let unaltered = dummy_certificate("another_hash", "another_parent");
            let expected = MithrilCertificate {
                epoch: before_update.epoch + 10,
                previous_hash: "updated_parent".to_string(),
                ..before_update.clone()
            };
            commit_certificates(
                &cache,
                &space(),
                "initial_id",
                [before_update, unaltered.clone()],
            )
            .await;
            let initial_record = cache.committed_record(&space(), "hash").await;
            let start_time = Utc::now().trunc_subsecs(3);

            commit_certificates(&cache, &space(), "update_id", [expected.clone()]).await;

            let updated_record = cache.committed_record(&space(), "hash").await;
            assert_eq!(2, cache.content(&space()).await.len());
            assert_eq!(
                Some(expected),
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
            assert_eq!(
                Some(unaltered),
                cache.get_certificate_by_hash(&space(), "another_hash").await.unwrap(),
                "Existing but not updated value should not have been altered"
            );
            assert_ne!(initial_record, updated_record);
            assert!(updated_record.expire_at - start_time >= expiration_delay);
        }

        #[wasm_bindgen_test]
        async fn committing_certificates_sweeps_away_expired_batches() {
            let database_name = "committing_certificates_sweeps_away_expired_batches";
            let cache = empty_cache(database_name, TimeDelta::hours(1))
                .await
                .with_staging_expiration_delay(TimeDelta::hours(1));
            let expired_batches_cache =
                IndexedDbCertificateVerifierCache::new(database_name, TimeDelta::hours(1))
                    .with_staging_expiration_delay(TimeDelta::zero());
            cache
                .stage_certificate("to_commit_id", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();
            cache
                .stage_certificate("remaining_id", dummy_certificate("hash3", "parent3"))
                .await
                .unwrap();
            expired_batches_cache
                .stage_certificate("abandoned_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert_eq!(3, cache.staged_batch_ids().await.len());

            cache
                .commit_staged_certificates(&space(), "to_commit_id")
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["remaining_id".to_string()]),
                cache.staged_batch_ids().await
            );
            assert!(cache.staged_hashes("abandoned_id").await.is_empty());
        }

        #[wasm_bindgen_test]
        async fn committing_certificates_sweeps_away_expired_committed_certificates() {
            let database_name =
                "committing_certificates_sweeps_away_expired_committed_certificates";
            let cache = empty_cache(database_name, TimeDelta::hours(1)).await;
            let expired_cache =
                IndexedDbCertificateVerifierCache::new(database_name, TimeDelta::zero());
            commit_certificates(
                &cache,
                &space(),
                "valid_id",
                [dummy_certificate("new_hash", "parent")],
            )
            .await;
            commit_certificates(
                &expired_cache,
                &space(),
                "expired_id",
                [dummy_certificate("expired_hash", "parent")],
            )
            .await;

            assert_eq!(2, cache.committed_records().await.len());

            cache
                .commit_staged_certificates(&space(), "another_id")
                .await
                .unwrap();

            assert_eq!(
                HashMap::from([(
                    "new_hash".to_string(),
                    dummy_certificate("new_hash", "parent")
                )]),
                cache.content(&space()).await
            );
        }

        #[wasm_bindgen_test]
        async fn staging_a_new_batch_sweeps_away_other_expired_batches() {
            let database_name = "staging_a_new_batch_sweeps_away_other_expired_batches";
            let cache = empty_cache(database_name, TimeDelta::hours(1))
                .await
                .with_staging_expiration_delay(TimeDelta::hours(1));
            let expired_batches_cache =
                IndexedDbCertificateVerifierCache::new(database_name, TimeDelta::hours(1))
                    .with_staging_expiration_delay(TimeDelta::zero());
            expired_batches_cache
                .stage_certificate("expired_batch", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            cache
                .stage_certificate("new_batch", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["new_batch".to_string()]),
                cache.staged_batch_ids().await
            );
            assert!(cache.staged_hashes("expired_batch").await.is_empty());
        }

        #[wasm_bindgen_test]
        async fn staging_a_new_batch_sweeps_away_expired_committed_certificates() {
            let database_name = "staging_a_new_batch_sweeps_away_expired_committed_certificates";
            let cache = empty_cache(database_name, TimeDelta::hours(1)).await;
            let expired_cache =
                IndexedDbCertificateVerifierCache::new(database_name, TimeDelta::zero());
            commit_certificates(
                &cache,
                &space(),
                "valid_id",
                [dummy_certificate("new_hash", "parent")],
            )
            .await;
            commit_certificates(
                &expired_cache,
                &space(),
                "expired_id",
                [dummy_certificate("expired_hash", "parent")],
            )
            .await;

            assert_eq!(2, cache.committed_records().await.len());

            cache
                .stage_certificate("new_batch", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();

            assert_eq!(
                HashMap::from([(
                    "new_hash".to_string(),
                    dummy_certificate("new_hash", "parent")
                )]),
                cache.content(&space()).await
            );
        }

        #[wasm_bindgen_test]
        async fn staging_under_an_existing_batch_does_not_sweep_other_expired_batches() {
            let database_name =
                "staging_under_an_existing_batch_does_not_sweep_other_expired_batches";
            let cache = empty_cache(database_name, TimeDelta::hours(1))
                .await
                .with_staging_expiration_delay(TimeDelta::hours(1));
            let expired_batches_cache =
                IndexedDbCertificateVerifierCache::new(database_name, TimeDelta::hours(1))
                    .with_staging_expiration_delay(TimeDelta::zero());
            cache
                .stage_certificate("existing_id", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();
            expired_batches_cache
                .stage_certificate("expired_batch", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            cache
                .stage_certificate("existing_id", dummy_certificate("hash3", "parent3"))
                .await
                .unwrap();

            assert_eq!(
                HashSet::from(["expired_batch".to_string(), "existing_id".to_string()]),
                cache.staged_batch_ids().await
            );
        }

        #[wasm_bindgen_test]
        async fn staging_under_an_expired_batch_extends_its_expiration() {
            let database_name = "staging_under_an_expired_batch_extends_its_expiration";
            let cache = empty_cache(database_name, TimeDelta::hours(1)).await;
            let expired_batches_cache =
                IndexedDbCertificateVerifierCache::new(database_name, TimeDelta::hours(1))
                    .with_staging_expiration_delay(TimeDelta::zero());
            expired_batches_cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash2", "parent2"))
                .await
                .unwrap();
            cache
                .commit_staged_certificates(&space(), "chain_validation_id")
                .await
                .unwrap();

            assert_eq!(
                HashMap::from([
                    ("hash".to_string(), dummy_certificate("hash", "parent")),
                    ("hash2".to_string(), dummy_certificate("hash2", "parent2")),
                ]),
                cache.content(&space()).await
            );
        }
    }

    mod get_certificate_by_hash {
        use super::*;

        #[wasm_bindgen_test]
        async fn returns_the_certificate_when_committed() {
            let cache = empty_cache(
                "returns_the_certificate_when_committed",
                TimeDelta::hours(1),
            )
            .await;
            let expected = dummy_certificate("hash", "parent");
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [expected.clone(), dummy_certificate("another_hash", "another_parent")],
            )
            .await;

            assert_eq!(
                Some(expected),
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[wasm_bindgen_test]
        async fn returns_none_if_not_found() {
            let cache = empty_cache("returns_none_if_not_found", TimeDelta::hours(1)).await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "not_found").await.unwrap()
            );
        }

        #[wasm_bindgen_test]
        async fn returns_none_for_an_expired_certificate() {
            let cache =
                empty_cache("returns_none_for_an_expired_certificate", TimeDelta::zero()).await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            assert_eq!(1, cache.committed_records().await.len());
            assert_eq!(
                None,
                cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }
    }

    mod certificate_exist {
        use super::*;

        #[wasm_bindgen_test]
        async fn returns_false_for_a_hash_never_committed() {
            let cache = empty_cache(
                "returns_false_for_a_hash_never_committed",
                TimeDelta::hours(1),
            )
            .await;

            assert!(!cache.certificate_exist(&space(), "hash").await.unwrap());
        }

        #[wasm_bindgen_test]
        async fn returns_true_for_a_committed_hash() {
            let cache = empty_cache("returns_true_for_a_committed_hash", TimeDelta::hours(1)).await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            assert!(cache.certificate_exist(&space(), "hash").await.unwrap());
        }

        #[wasm_bindgen_test]
        async fn returns_false_for_an_expired_committed_entry() {
            let cache = empty_cache(
                "returns_false_for_an_expired_committed_entry",
                TimeDelta::zero(),
            )
            .await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            assert!(!cache.certificate_exist(&space(), "hash").await.unwrap());
        }

        #[wasm_bindgen_test]
        async fn returns_false_for_a_staged_but_uncommitted_hash() {
            let cache = empty_cache(
                "returns_false_for_a_staged_but_uncommitted_hash",
                TimeDelta::hours(1),
            )
            .await;
            cache
                .stage_certificate("chain_validation_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert!(!cache.certificate_exist(&space(), "hash").await.unwrap());
        }
    }

    mod reset {
        use super::*;

        #[wasm_bindgen_test]
        async fn reset_empty_cache_dont_raise_error() {
            let cache =
                empty_cache("reset_empty_cache_dont_raise_error", TimeDelta::hours(1)).await;

            cache.reset().await.unwrap();

            assert_eq!(HashMap::new(), cache.content(&space()).await);
        }

        #[wasm_bindgen_test]
        async fn reset_clears_committed_data() {
            let cache = empty_cache("reset_clears_committed_data", TimeDelta::hours(1)).await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [
                    dummy_certificate("hash", "parent"),
                    dummy_certificate("another_hash", "another_parent"),
                ],
            )
            .await;

            assert_eq!(2, cache.content(&space()).await.len());

            cache.reset().await.unwrap();

            assert_eq!(HashMap::new(), cache.content(&space()).await);
        }

        #[wasm_bindgen_test]
        async fn reset_clears_staged_data() {
            let cache = empty_cache("reset_clears_staged_data", TimeDelta::hours(1)).await;
            cache
                .stage_certificate("chain_id", dummy_certificate("hash", "parent"))
                .await
                .unwrap();

            assert_eq!(1, cache.staged_batch_ids().await.len());

            cache.reset().await.unwrap();

            assert_eq!(HashSet::new(), cache.staged_batch_ids().await);
            assert!(cache.staged_hashes("chain_id").await.is_empty());
        }
    }

    mod spaces {
        use super::*;

        #[wasm_bindgen_test]
        async fn a_certificate_committed_to_a_space_is_not_visible_from_another_space() {
            let cache = empty_cache(
                "a_certificate_committed_to_a_space_is_not_visible_from_another_space",
                TimeDelta::hours(1),
            )
            .await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            assert_eq!(
                None,
                cache.get_certificate_by_hash(&other_space(), "hash").await.unwrap()
            );
            assert!(!cache.certificate_exist(&other_space(), "hash").await.unwrap());
            assert_eq!(HashMap::new(), cache.content(&other_space()).await);
        }

        #[wasm_bindgen_test]
        async fn the_same_certificate_can_be_committed_to_several_spaces() {
            let cache = empty_cache(
                "the_same_certificate_can_be_committed_to_several_spaces",
                TimeDelta::hours(1),
            )
            .await;
            let other_space = other_space();
            commit_certificates(
                &cache,
                &space(),
                "first_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;
            commit_certificates(
                &cache,
                &other_space,
                "second_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            assert_eq!(2, cache.committed_records().await.len());
            assert!(cache.certificate_exist(&space(), "hash").await.unwrap());
            assert!(cache.certificate_exist(&other_space, "hash").await.unwrap());
        }

        #[wasm_bindgen_test]
        async fn reset_clears_all_spaces() {
            let cache = empty_cache("reset_clears_all_spaces", TimeDelta::hours(1)).await;
            commit_certificates(
                &cache,
                &space(),
                "first_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;
            commit_certificates(
                &cache,
                &other_space(),
                "second_id",
                [dummy_certificate("another_hash", "parent")],
            )
            .await;

            cache.reset().await.unwrap();

            assert!(cache.committed_records().await.is_empty());
        }
    }

    mod persistence {
        use super::*;

        #[wasm_bindgen_test]
        async fn committed_certificates_are_shared_by_caches_on_the_same_database() {
            let database_name = "committed_certificates_are_shared_by_caches_on_the_same_database";
            let cache = empty_cache(database_name, TimeDelta::hours(1)).await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            let other_cache =
                IndexedDbCertificateVerifierCache::new(database_name, TimeDelta::hours(1));

            assert_eq!(
                Some(dummy_certificate("hash", "parent")),
                other_cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
        }

        #[wasm_bindgen_test]
        async fn caches_on_different_databases_are_isolated() {
            let cache = empty_cache(
                "caches_on_different_databases_are_isolated",
                TimeDelta::hours(1),
            )
            .await;
            commit_certificates(
                &cache,
                &space(),
                "chain_validation_id",
                [dummy_certificate("hash", "parent")],
            )
            .await;

            let other_cache = empty_cache(
                "caches_on_different_databases_are_isolated_other",
                TimeDelta::hours(1),
            )
            .await;

            assert_eq!(
                None,
                other_cache.get_certificate_by_hash(&space(), "hash").await.unwrap()
            );
            assert!(cache.certificate_exist(&space(), "hash").await.unwrap());
        }
    }
}

#[cfg(all(test, feature = "test-node"))]
mod tests_without_indexed_db {
    use mithril_common::crypto_helper::GenesisSigner;
    use wasm_bindgen_test::*;

    use super::*;

    #[wasm_bindgen_test]
    async fn operations_fail_when_indexed_db_is_unavailable() {
        let cache = IndexedDbCertificateVerifierCache::new("unavailable", TimeDelta::hours(1));
        let space = CertificateVerifierCacheSpace::from_genesis_verifier(
            &GenesisSigner::create_deterministic_signer().create_verifier(),
        );

        let error = cache.certificate_exist(&space, "hash").await.unwrap_err();

        assert!(
            error.to_string().contains("IndexedDB is not available"),
            "Unexpected error: {error}"
        );
    }
}
