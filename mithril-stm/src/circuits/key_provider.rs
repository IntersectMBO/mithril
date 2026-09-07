//! Compute-on-miss verification key provider for one key generator.
//!
//! [`KeyProvider`] owns the on-disk key cache (the verifying/proving key file
//! paths and the expected verifying-key bytes for staleness detection) together with a
//! [`KeyGenerator`]. [`KeyProvider::key_pair`] inspects the cache
//! through a single [`CacheState`] state machine: a fresh, complete pair is returned from disk,
//! anything else (absent, stale, or partially written) is recomputed from the SRS and stored
//! atomically.
use std::{
    fs,
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};

use anyhow::Context;
use midnight_curves::Bls12;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use rand_core::{OsRng, RngCore};

use crate::codec::{TryFromBytes, TryToBytes};
use crate::{Parameters, StmResult};

use super::halo2::circuit::CertificateCircuit;
use super::halo2_ivc::keys::RecursiveCircuitKeyGenerator;
use super::key_generator::KeyGenerator;
use super::{
    MITHRIL_CIRCUIT_CACHE_FOLDER, halo2::NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
    halo2_ivc::RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
};

/// Outcome of inspecting the on-disk key cache for a complete, fresh key pair.
enum CacheState {
    /// Both key files are present and the verifying key matches the expected bytes; carries the raw
    /// key-pair bytes ready for deserialization.
    Valid {
        /// Raw verifying-key bytes read from the cache.
        verification_key: Vec<u8>,
        /// Raw proving-key bytes read from the cache.
        proving_key: Vec<u8>,
    },
    /// Nothing usable on disk: absent, stale, or a partial write.
    Empty,
}

/// Provides a key generator's verifying and proving keys: an on-disk cache (with staleness detection)
/// plus the [`KeyGenerator`] that computes them on a miss.
pub(crate) struct KeyProvider<G: KeyGenerator> {
    /// Path to the on-disk verification key file.
    verification_key_path: PathBuf,
    /// Path to the on-disk proving key file.
    proving_key_path: PathBuf,
    /// Expected verifying-key bytes for staleness detection; an empty slice skips the check and
    /// trusts the cached key (used by the content-keyed test caches, which isolate configurations by
    /// directory).
    expected_verification_key: Vec<u8>,
    /// Key generator that derives the key pair on a cache miss.
    generator: G,
}

impl<G: KeyGenerator> KeyProvider<G> {
    /// Builds a provider rooted at `base_dir / MITHRIL_CIRCUIT_CACHE_FOLDER / circuit_name`. On read,
    /// the cached verifying key is compared against `expected_verification_key` and recomputed on a
    /// mismatch; an empty slice skips the comparison and trusts the cached key. Keys are computed from
    /// `generator` on a miss.
    pub(crate) fn new(
        base_dir: PathBuf,
        circuit_name: &str,
        expected_verification_key: &[u8],
        generator: G,
    ) -> Self {
        let circuit_dir = base_dir.join(MITHRIL_CIRCUIT_CACHE_FOLDER).join(circuit_name);
        Self {
            verification_key_path: circuit_dir.join("verification-key"),
            proving_key_path: circuit_dir.join("proving-key"),
            expected_verification_key: expected_verification_key.to_vec(),
            generator,
        }
    }

    /// The key generator this provider derives keys through.
    pub(crate) fn generator(&self) -> &G {
        &self.generator
    }

    /// Returns the key pair, computing and caching it from `srs` on a miss.
    pub(crate) fn key_pair(
        &self,
        srs: &ParamsKZG<Bls12>,
    ) -> StmResult<(G::VerifyingKey, G::ProvingKey)> {
        match self.cache_state()? {
            CacheState::Valid {
                verification_key,
                proving_key,
            } => Ok((
                G::VerifyingKey::try_from_bytes(&verification_key)?,
                G::ProvingKey::try_from_bytes(&proving_key)?,
            )),
            CacheState::Empty => self.compute_and_store(srs),
        }
    }

    /// Returns the verifying key, computing and caching the pair from `srs` on a miss.
    ///
    /// A cache hit requires the complete pair: a verifying key present without its proving key (an
    /// interrupted store) is treated as a miss and the pair is recomputed, rather than returning the
    /// lone verifying key. This is intentional — "cache hit" always means a complete, consistent pair.
    pub(crate) fn verification_key(&self, srs: &ParamsKZG<Bls12>) -> StmResult<G::VerifyingKey> {
        match self.cache_state()? {
            CacheState::Valid {
                verification_key, ..
            } => G::VerifyingKey::try_from_bytes(&verification_key),
            CacheState::Empty => Ok(self.compute_and_store(srs)?.0),
        }
    }

    /// Reads the cache and returns the fresh key-pair bytes, or [`CacheState::Empty`] when nothing
    /// usable is on disk (absent, partially written, or stale). A stale entry is left in place: the
    /// next store overwrites both key files atomically. The proving key is read only once the
    /// verifying key is present and fresh, so an orphan proving key left by an interrupted store is
    /// reported as `Empty` rather than surfaced as a deserialization error.
    fn cache_state(&self) -> StmResult<CacheState> {
        let Some(verification_key) = Self::read_optional(&self.verification_key_path)? else {
            return Ok(CacheState::Empty);
        };
        if self.is_stale(&verification_key) {
            return Ok(CacheState::Empty);
        }
        let Some(proving_key) = Self::read_optional(&self.proving_key_path)? else {
            return Ok(CacheState::Empty);
        };
        Ok(CacheState::Valid {
            verification_key,
            proving_key,
        })
    }

    /// Derives the key pair from `srs` via the circuit and stores it in the cache.
    fn compute_and_store(
        &self,
        srs: &ParamsKZG<Bls12>,
    ) -> StmResult<(G::VerifyingKey, G::ProvingKey)> {
        let (verification_key, proving_key) = self.generator.generate_key_pair(srs)?;
        self.store(
            &verification_key.to_bytes_vec()?,
            &proving_key.to_bytes_vec()?,
        )?;
        Ok((verification_key, proving_key))
    }

    /// `true` when an expected verifying key is configured and the cached bytes do not match it.
    fn is_stale(&self, verification_key: &[u8]) -> bool {
        !self.expected_verification_key.is_empty()
            && verification_key != self.expected_verification_key.as_slice()
    }

    /// Writes the verifying and proving key bytes to disk as a pair: each to a per-writer-unique
    /// temporary sibling, fsynced, then renamed (the proving key first, the verifying key last), with
    /// a final directory fsync. On a failed verifying-key rename it best-effort removes the
    /// proving-key path it just wrote (which a concurrent lock-free writer may already have replaced);
    /// a crash between the two renames runs no cleanup, so an orphan key can still remain.
    /// [`Self::cache_state`] requires both keys present and recomputes otherwise, so correctness does
    /// not depend on the rename order or on crash durability. Unique temporary names let concurrent
    /// lock-free writers proceed without clobbering each other.
    fn store(&self, verification_key: &[u8], proving_key: &[u8]) -> StmResult<()> {
        if let Some(parent) = self.verification_key_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| "Failed to create the circuit key cache directory")?;
        }

        let proving_key_temp = Self::write_temporary_sibling(&self.proving_key_path, proving_key)?;
        let verification_key_temp =
            match Self::write_temporary_sibling(&self.verification_key_path, verification_key) {
                Ok(path) => path,
                Err(error) => {
                    let _ = fs::remove_file(&proving_key_temp);
                    return Err(error);
                }
            };

        if let Err(error) = fs::rename(&proving_key_temp, &self.proving_key_path) {
            let _ = fs::remove_file(&proving_key_temp);
            let _ = fs::remove_file(&verification_key_temp);
            return Err(error).with_context(|| "Failed to store the proving key in the cache");
        }
        if let Err(error) = fs::rename(&verification_key_temp, &self.verification_key_path) {
            let _ = fs::remove_file(&verification_key_temp);
            // Best-effort removal of the proving key just written, so a failed store does not leave it
            // orphaned (a concurrent lock-free writer may already have replaced the final path).
            let _ = fs::remove_file(&self.proving_key_path);
            return Err(error).with_context(|| "Failed to store the verification key in the cache");
        }
        Self::sync_directory_of(&self.verification_key_path)
    }

    /// Reads the bytes at `path`, returning `None` when the file does not exist.
    fn read_optional(path: &Path) -> StmResult<Option<Vec<u8>>> {
        match fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Writes `bytes` to a uniquely-named temporary sibling of `final_path`, fsyncing before
    /// returning its path so the subsequent rename is atomic.
    fn write_temporary_sibling(final_path: &Path, bytes: &[u8]) -> StmResult<PathBuf> {
        let temp_path = Self::unique_temporary_path(final_path);
        let mut file = fs::File::create(&temp_path)
            .with_context(|| format!("Failed to create the temporary key file at {temp_path:?}"))?;
        file.write_all(bytes)?;
        file.sync_all()
            .with_context(|| "Failed to fsync the temporary key file before rename")?;
        Ok(temp_path)
    }

    /// A temporary sibling path with a random suffix, so concurrent cold-miss writers never collide.
    fn unique_temporary_path(final_path: &Path) -> PathBuf {
        let nonce = OsRng.next_u64();
        let mut file_name = final_path.file_name().unwrap_or_default().to_os_string();
        file_name.push(format!(".{nonce:016x}.temp"));
        final_path.with_file_name(file_name)
    }

    /// Fsyncs the directory containing `path` so the renames are durable.
    fn sync_directory_of(path: &Path) -> StmResult<()> {
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .with_context(|| "Failed to fsync the cache directory after rename")?;
        }
        Ok(())
    }
}

impl KeyProvider<CertificateCircuit> {
    /// Production certificate-circuit provider: builds the circuit from `parameters`, roots the
    /// cache at the temporary directory, and validates against the embedded production verifying key.
    pub(crate) fn for_non_recursive_circuit(
        parameters: &Parameters,
        merkle_tree_depth: u32,
    ) -> StmResult<Self> {
        let circuit = CertificateCircuit::try_new(parameters, merkle_tree_depth)?;
        Ok(Self::new(
            std::env::temp_dir(),
            "non-recursive-keys",
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
            circuit,
        ))
    }
}

impl KeyProvider<RecursiveCircuitKeyGenerator> {
    /// Production recursive-circuit provider: wraps the non-recursive key provider the recursive
    /// circuit is built from, roots the cache at the temporary directory, and validates against the
    /// embedded production verifying key.
    pub(crate) fn for_recursive_circuit(
        non_recursive_key_provider: KeyProvider<CertificateCircuit>,
    ) -> Self {
        Self::new(
            std::env::temp_dir(),
            "recursive-keys",
            RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
            RecursiveCircuitKeyGenerator::new(non_recursive_key_provider),
        )
    }
}

#[cfg(test)]
impl<G: KeyGenerator> KeyProvider<G> {
    pub(crate) fn verification_key_path(&self) -> &Path {
        &self.verification_key_path
    }

    pub(crate) fn proving_key_path(&self) -> &Path {
        &self.proving_key_path
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::{env, fs, path::PathBuf};

    use midnight_curves::Bls12;
    use midnight_proofs::poly::kzg::params::ParamsKZG;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::{CacheState, KeyGenerator, KeyProvider};
    use crate::Parameters;
    use crate::StmResult;
    use crate::circuits::halo2::circuit::CertificateCircuit;
    use crate::codec::{TryFromBytes, TryToBytes};

    /// Key backed by raw bytes, so the provider mechanics can be tested without real keygen.
    #[derive(Clone, Debug, PartialEq)]
    struct ByteKey(Vec<u8>);

    impl TryToBytes for ByteKey {
        fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    impl TryFromBytes for ByteKey {
        fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
            Ok(Self(bytes.to_vec()))
        }
    }

    /// Generator returning fixed key bytes and counting how often it is invoked.
    struct CountingGenerator {
        verification_key: Vec<u8>,
        proving_key: Vec<u8>,
        calls: Cell<u32>,
    }

    impl CountingGenerator {
        fn new(verification_key: &[u8], proving_key: &[u8]) -> Self {
            Self {
                verification_key: verification_key.to_vec(),
                proving_key: proving_key.to_vec(),
                calls: Cell::new(0),
            }
        }
    }

    impl KeyGenerator for CountingGenerator {
        type VerifyingKey = ByteKey;
        type ProvingKey = ByteKey;

        fn generate_key_pair(&self, _srs: &ParamsKZG<Bls12>) -> StmResult<(ByteKey, ByteKey)> {
            self.calls.set(self.calls.get() + 1);
            Ok((
                ByteKey(self.verification_key.clone()),
                ByteKey(self.proving_key.clone()),
            ))
        }
    }

    // The generator ignores the SRS, so the smallest constructible parameters are enough.
    fn negligible_srs() -> ParamsKZG<Bls12> {
        ParamsKZG::unsafe_setup(1, ChaCha20Rng::seed_from_u64(0))
    }

    /// A provider over a fresh temporary directory with a counting generator, returning the base
    /// directory for cleanup.
    fn counting_provider(
        name: &str,
        expected_verification_key: &[u8],
        verification_key: &[u8],
        proving_key: &[u8],
    ) -> (PathBuf, KeyProvider<CountingGenerator>) {
        let base_dir = env::temp_dir().join(name);
        fs::remove_dir_all(&base_dir).ok();
        let provider = KeyProvider::new(
            base_dir.clone(),
            "test-circuit",
            expected_verification_key,
            CountingGenerator::new(verification_key, proving_key),
        );
        (base_dir, provider)
    }

    #[test]
    fn cold_miss_generates_stores_and_returns_the_pair() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");

        let (verification_key, proving_key) = provider.key_pair(&negligible_srs()).unwrap();

        assert_eq!(verification_key, ByteKey(b"vk".to_vec()));
        assert_eq!(proving_key, ByteKey(b"pk".to_vec()));
        assert_eq!(
            provider.generator().calls.get(),
            1,
            "a cold miss must generate exactly once"
        );
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn warm_hit_reads_from_cache_without_regenerating() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");

        provider.key_pair(&negligible_srs()).unwrap();
        let (verification_key, proving_key) = provider.key_pair(&negligible_srs()).unwrap();

        assert_eq!(verification_key, ByteKey(b"vk".to_vec()));
        assert_eq!(proving_key, ByteKey(b"pk".to_vec()));
        assert_eq!(
            provider.generator().calls.get(),
            1,
            "the second call must hit the cache"
        );
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn verification_key_hits_cache_without_recomputing() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");

        provider.key_pair(&negligible_srs()).unwrap();
        let verification_key = provider.verification_key(&negligible_srs()).unwrap();

        assert_eq!(verification_key, ByteKey(b"vk".to_vec()));
        assert_eq!(
            provider.generator().calls.get(),
            1,
            "a warm cache must be reused"
        );
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn verification_key_recomputes_when_the_proving_key_is_missing() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");
        // A present verifying key with no proving key is not a usable cache hit: a hit requires the
        // complete pair, so verification_key recomputes rather than returning the lone verifying key.
        fs::create_dir_all(provider.verification_key_path().parent().unwrap()).unwrap();
        fs::write(provider.verification_key_path(), b"vk").unwrap();

        let verification_key = provider.verification_key(&negligible_srs()).unwrap();

        assert_eq!(verification_key, ByteKey(b"vk".to_vec()));
        assert_eq!(
            provider.generator().calls.get(),
            1,
            "a verifying key with no proving key must recompute the pair"
        );
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn no_expected_key_trusts_the_cached_key() {
        let (base_dir, provider) = counting_provider(current_function!(), b"", b"vk", b"pk");

        provider.key_pair(&negligible_srs()).unwrap();
        provider.key_pair(&negligible_srs()).unwrap();

        assert_eq!(
            provider.generator().calls.get(),
            1,
            "with empty expected bytes a warm cache must be trusted, not recomputed"
        );
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn orphan_proving_key_recomputes_the_pair() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");
        provider.key_pair(&negligible_srs()).unwrap();

        fs::remove_file(provider.verification_key_path()).unwrap();
        provider.key_pair(&negligible_srs()).unwrap();

        assert_eq!(
            provider.generator().calls.get(),
            2,
            "an orphan proving key must trigger a recompute"
        );
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn stale_verification_key_is_recomputed() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");
        fs::create_dir_all(provider.verification_key_path().parent().unwrap()).unwrap();
        fs::write(provider.verification_key_path(), b"stale-vk").unwrap();
        fs::write(provider.proving_key_path(), b"stale-pk").unwrap();

        let (verification_key, proving_key) = provider.key_pair(&negligible_srs()).unwrap();

        assert_eq!(verification_key, ByteKey(b"vk".to_vec()));
        assert_eq!(proving_key, ByteKey(b"pk".to_vec()));
        assert_eq!(
            provider.generator().calls.get(),
            1,
            "a stale cache must be recomputed once"
        );
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn cache_state_is_valid_for_a_fresh_full_cache() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");
        fs::create_dir_all(provider.verification_key_path().parent().unwrap()).unwrap();
        fs::write(provider.verification_key_path(), b"vk").unwrap();
        fs::write(provider.proving_key_path(), b"pk").unwrap();

        let state = provider.cache_state().unwrap();

        assert!(matches!(
            state,
            CacheState::Valid { verification_key, proving_key }
                if verification_key == b"vk" && proving_key == b"pk"
        ));
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn cache_state_reports_empty_for_a_stale_verification_key() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");
        fs::create_dir_all(provider.verification_key_path().parent().unwrap()).unwrap();
        fs::write(provider.verification_key_path(), b"stale-vk").unwrap();
        fs::write(provider.proving_key_path(), b"stale-pk").unwrap();

        let state = provider.cache_state().unwrap();

        assert!(
            matches!(state, CacheState::Empty),
            "a stale cache must be a miss"
        );
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn cache_state_reports_empty_for_an_orphan_proving_key() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");
        fs::create_dir_all(provider.proving_key_path().parent().unwrap()).unwrap();
        fs::write(provider.proving_key_path(), b"orphan-pk").unwrap();

        let state = provider.cache_state().unwrap();

        assert!(matches!(state, CacheState::Empty));
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn store_persists_both_keys() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");

        provider.store(b"vk-bytes", b"pk-bytes").unwrap();

        assert_eq!(
            fs::read(provider.verification_key_path()).unwrap(),
            b"vk-bytes"
        );
        assert_eq!(fs::read(provider.proving_key_path()).unwrap(), b"pk-bytes");
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn store_leaves_no_verification_key_when_proving_key_store_fails() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");
        fs::create_dir_all(provider.proving_key_path()).unwrap();

        let result = provider.store(b"vk-bytes", b"pk-bytes");

        assert!(
            result.is_err(),
            "store should fail when the proving key cannot be written"
        );
        assert!(
            !provider.verification_key_path().exists(),
            "no verification key must be left behind when the proving key store fails"
        );
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn store_rolls_back_the_proving_key_when_the_verifying_key_store_fails() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");
        // A directory at the verifying-key path makes its rename fail; the proving key is renamed
        // first (and succeeds), so it must then be rolled back.
        fs::create_dir_all(provider.verification_key_path()).unwrap();

        let result = provider.store(b"vk-bytes", b"pk-bytes");

        assert!(
            result.is_err(),
            "store should fail when the verifying key cannot be written"
        );
        assert!(
            !provider.proving_key_path().exists(),
            "the committed proving key must be rolled back when the verifying key store fails"
        );
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn key_pair_surfaces_a_deserialization_error_on_a_fresh_corrupt_cache() {
        let parameters = Parameters {
            k: 3,
            m: 10,
            phi_f: 0.2,
        };
        let circuit = CertificateCircuit::try_new(&parameters, 4).unwrap();
        let base_dir = env::temp_dir().join(current_function!());
        fs::remove_dir_all(&base_dir).ok();
        let provider = KeyProvider::new(base_dir.clone(), "non-recursive", b"corrupt-vk", circuit);
        fs::create_dir_all(provider.verification_key_path().parent().unwrap()).unwrap();
        fs::write(provider.verification_key_path(), b"corrupt-vk").unwrap();
        fs::write(provider.proving_key_path(), b"corrupt-pk").unwrap();

        let result = provider.key_pair(&negligible_srs());

        assert!(
            result.is_err(),
            "a fresh but corrupt verifying key must surface a deserialization error"
        );
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn new_roots_cache_paths_under_the_circuit_cache_folder() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");

        assert!(
            provider
                .verification_key_path()
                .ends_with("mithril-circuit/test-circuit/verification-key"),
            "verification key path must be rooted under the circuit cache folder"
        );
        assert!(
            provider
                .proving_key_path()
                .ends_with("mithril-circuit/test-circuit/proving-key"),
            "proving key path must be rooted under the circuit cache folder"
        );
        fs::remove_dir_all(&base_dir).ok();
    }
}
