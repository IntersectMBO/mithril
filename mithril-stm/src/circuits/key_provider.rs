//! Compute-on-miss verification key provider for one key generator.
//!
//! [`KeyProvider`] owns the on-disk key cache (the verifying/proving key file
//! paths and the digest of the expected verifying key for staleness detection) together with a
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
use sha2::{Digest, Sha256};

use crate::codec::{TryFromBytes, TryToBytes};
use crate::{MERKLE_TREE_DEPTH_FOR_SNARK, Parameters, StmResult};

use super::halo2::circuit::CertificateCircuit;
use super::halo2_ivc::keys::RecursiveCircuitKeyGenerator;
use super::key_generator::KeyGenerator;
use super::trusted_setup::MIDNIGHT_SRS_HASH_K22;
use super::{
    CircuitVerificationKeyDigest, MITHRIL_CIRCUIT_CACHE_FOLDER,
    halo2::STM_PARAMETERS_FOR_PRODUCTION,
};

/// Bumped whenever the cache layout or the fingerprint inputs change, so an entry written by an
/// earlier scheme is never reused.
const CACHE_SCHEMA_VERSION: &[u8] = b"v2";

/// Outcome of inspecting the on-disk key cache for a complete, fresh key pair.
enum CacheState<V> {
    /// Both key files are present and the verifying key is fresh; carries the decoded verifying key
    /// and the raw proving-key bytes, decoded only by the caller that needs them.
    Valid {
        /// Verifying key decoded from the cache.
        verification_key: V,
        /// Raw proving-key bytes read from the cache.
        proving_key: Vec<u8>,
    },
    /// Nothing usable on disk: absent, stale, or a partial write.
    Empty,
}

/// Cache identity of a circuit configuration, which the derived keys depend on.
///
/// The production configuration keeps a stable directory and is validated against the embedded
/// production verifying key. Any other configuration derives keys the embedded key would reject, so
/// it gets a directory of its own, keyed by a fingerprint of the configuration, and the entry found
/// there is trusted.
enum CircuitCacheIdentity {
    /// The configuration the embedded production verifying keys were derived from.
    Production,
    /// Any other configuration, identified by the hex digest of its fingerprint.
    Fingerprinted(String),
}

impl CircuitCacheIdentity {
    /// Identifies the configuration made of `parameters` and `merkle_tree_depth`.
    ///
    /// The fingerprint also folds in the cache schema version, the digest of the embedded production
    /// verifying key and the SRS the keys are derived from, so an entry is never reused across a
    /// layout change, a production key change or an SRS change. The digest stands for the circuit,
    /// which a configuration outside production cannot check its keys against: it covers the
    /// constraint system, which the serialized key omits, so it also changes when only the gates do.
    fn for_configuration(parameters: &Parameters, merkle_tree_depth: u32) -> StmResult<Self> {
        if Self::is_production(parameters, merkle_tree_depth) {
            return Ok(Self::Production);
        }

        Self::fingerprinted(
            parameters,
            merkle_tree_depth,
            &CircuitVerificationKeyDigest::for_production_certificate_circuit()?,
            None,
        )
    }

    /// Identifies a configuration of the recursive circuit, additionally bound to that circuit's own
    /// identity.
    ///
    /// The certificate circuit digest alone does not stand for the recursive circuit: the recursive
    /// circuit can change while the certificate circuit does not. A non-production entry is trusted
    /// without comparison, so without this an entry cached for an earlier recursive circuit would be
    /// selected and its fixed and permutation polynomials loaded against the new constraint system.
    /// The certificate circuit digest stays in, as the recursive circuit synthesizes the certificate
    /// circuit gates: a certificate gate change can change the recursive keys while leaving the
    /// certificate key bytes unchanged.
    fn for_recursive_configuration(
        parameters: &Parameters,
        merkle_tree_depth: u32,
    ) -> StmResult<Self> {
        if Self::is_production(parameters, merkle_tree_depth) {
            return Ok(Self::Production);
        }

        Self::fingerprinted(
            parameters,
            merkle_tree_depth,
            &CircuitVerificationKeyDigest::for_production_certificate_circuit()?,
            Some(&CircuitVerificationKeyDigest::for_ivc_circuit()?),
        )
    }

    /// `true` for the configuration the embedded production verifying keys were derived from.
    fn is_production(parameters: &Parameters, merkle_tree_depth: u32) -> bool {
        parameters == &STM_PARAMETERS_FOR_PRODUCTION
            && merkle_tree_depth == MERKLE_TREE_DEPTH_FOR_SNARK
    }

    /// Fingerprints a configuration outside production from the digests of the circuits its keys are
    /// derived from, so a test can vary each digest.
    fn fingerprinted(
        parameters: &Parameters,
        merkle_tree_depth: u32,
        certificate_circuit_digest: &CircuitVerificationKeyDigest,
        recursive_circuit_digest: Option<&CircuitVerificationKeyDigest>,
    ) -> StmResult<Self> {
        let mut hasher = Sha256::new();
        for input in [
            CACHE_SCHEMA_VERSION,
            certificate_circuit_digest.as_bytes(),
            MIDNIGHT_SRS_HASH_K22.as_bytes(),
            parameters.to_bytes()?.as_slice(),
            &merkle_tree_depth.to_le_bytes(),
        ] {
            hasher.update((input.len() as u64).to_le_bytes());
            hasher.update(input);
        }
        // Appended only for the recursive circuit, so certificate entries keep their identity.
        if let Some(digest) = recursive_circuit_digest {
            let digest = digest.as_bytes();
            hasher.update((digest.len() as u64).to_le_bytes());
            hasher.update(digest);
        }

        Ok(Self::Fingerprinted(hex::encode(hasher.finalize())))
    }

    /// Name of the directory holding the keys of `circuit_name` for this configuration.
    fn directory_name(&self, circuit_name: &str) -> String {
        match self {
            Self::Production => circuit_name.to_string(),
            Self::Fingerprinted(fingerprint) => format!("{circuit_name}-{fingerprint}"),
        }
    }

    /// Digest a cached entry is validated against: the embedded production key's digest for the
    /// production configuration, none for the others, which their own directory already isolates.
    fn expected_verification_key_digest(
        &self,
        production_verification_key_digest: impl FnOnce() -> StmResult<CircuitVerificationKeyDigest>,
    ) -> StmResult<Option<CircuitVerificationKeyDigest>> {
        match self {
            Self::Production => Ok(Some(production_verification_key_digest()?)),
            Self::Fingerprinted(_) => Ok(None),
        }
    }
}

/// Provides a key generator's verifying and proving keys: an on-disk cache (with staleness detection)
/// plus the [`KeyGenerator`] that computes them on a miss.
pub(crate) struct KeyProvider<G: KeyGenerator> {
    /// Path to the on-disk verification key file.
    verification_key_path: PathBuf,
    /// Path to the on-disk proving key file.
    proving_key_path: PathBuf,
    /// Digest a cached verifying key must have, for staleness detection; `None` skips the check and
    /// trusts the cached key (used by the content-keyed test caches, which isolate configurations by
    /// directory).
    expected_verification_key_digest: Option<CircuitVerificationKeyDigest>,
    /// Key generator that derives the key pair on a cache miss.
    generator: G,
}

impl<G: KeyGenerator> KeyProvider<G> {
    /// Builds a provider rooted at `base_dir / MITHRIL_CIRCUIT_CACHE_FOLDER / circuit_name`. On read,
    /// the digest of the cached verifying key is compared with `expected_verification_key_digest` and
    /// the pair recomputed on a mismatch; `None` skips the comparison and trusts the cached key. Keys
    /// are computed from `generator` on a miss.
    pub(crate) fn new(
        base_dir: PathBuf,
        circuit_name: &str,
        expected_verification_key_digest: Option<CircuitVerificationKeyDigest>,
        generator: G,
    ) -> Self {
        let circuit_dir = base_dir.join(MITHRIL_CIRCUIT_CACHE_FOLDER).join(circuit_name);
        Self {
            verification_key_path: circuit_dir.join("verification-key"),
            proving_key_path: circuit_dir.join("proving-key"),
            expected_verification_key_digest,
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
                verification_key,
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
            } => Ok(verification_key),
            CacheState::Empty => Ok(self.compute_and_store(srs)?.0),
        }
    }

    /// Reads the cache and returns the fresh key pair, or [`CacheState::Empty`] when nothing usable is
    /// on disk (absent, partially written, or stale). A stale entry is left in place: the next store
    /// overwrites both key files atomically. The proving key is read only once the verifying key is
    /// present and fresh, so an orphan proving key left by an interrupted store is reported as `Empty`
    /// rather than surfaced as a deserialization error.
    ///
    /// With an expected digest, the verifying key is decoded and checked before the proving key is
    /// looked up, so an undecodable or different key is a miss. A trusted key is decoded only once
    /// the pair is complete, so an incomplete pair is a miss whatever its verifying key holds.
    fn cache_state(&self) -> StmResult<CacheState<G::VerifyingKey>> {
        let Some(verification_key_bytes) = Self::read_optional(&self.verification_key_path)? else {
            return Ok(CacheState::Empty);
        };
        let checked_verification_key = match self.expected_verification_key_digest {
            Some(_) => match G::VerifyingKey::try_from_bytes(&verification_key_bytes) {
                Ok(verification_key) if self.is_fresh(&verification_key) => Some(verification_key),
                _ => return Ok(CacheState::Empty),
            },
            None => None,
        };
        let Some(proving_key) = Self::read_optional(&self.proving_key_path)? else {
            return Ok(CacheState::Empty);
        };
        let verification_key = match checked_verification_key {
            Some(verification_key) => verification_key,
            None => G::VerifyingKey::try_from_bytes(&verification_key_bytes)?,
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

    /// `true` when no expected digest is configured, or `verification_key` has the expected digest.
    fn is_fresh(&self, verification_key: &G::VerifyingKey) -> bool {
        self.expected_verification_key_digest.is_none_or(|expected_digest| {
            G::verification_key_digest(verification_key) == expected_digest
        })
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
    /// Certificate-circuit provider: builds the circuit from `parameters`, roots the cache at the
    /// temporary directory, and isolates the entry by [`CircuitCacheIdentity`], so the production
    /// configuration is validated against the embedded production verifying key while any other
    /// configuration caches into a directory of its own.
    pub(crate) fn for_non_recursive_circuit(
        parameters: &Parameters,
        merkle_tree_depth: u32,
    ) -> StmResult<Self> {
        let identity = CircuitCacheIdentity::for_configuration(parameters, merkle_tree_depth)?;
        let circuit = CertificateCircuit::try_new(parameters, merkle_tree_depth)?;

        Ok(Self::new(
            std::env::temp_dir(),
            &identity.directory_name("non-recursive-keys"),
            identity.expected_verification_key_digest(
                CircuitVerificationKeyDigest::for_production_certificate_circuit,
            )?,
            circuit,
        ))
    }
}

impl KeyProvider<RecursiveCircuitKeyGenerator> {
    /// Recursive-circuit provider: wraps the non-recursive key provider the recursive circuit is
    /// built from, roots the cache at the temporary directory, and isolates the entry by the
    /// [`CircuitCacheIdentity`] of the configuration the wrapped provider was built for, the recursive
    /// keys being derived from the non-recursive ones.
    pub(crate) fn for_recursive_circuit(
        non_recursive_key_provider: KeyProvider<CertificateCircuit>,
        parameters: &Parameters,
        merkle_tree_depth: u32,
    ) -> StmResult<Self> {
        let identity =
            CircuitCacheIdentity::for_recursive_configuration(parameters, merkle_tree_depth)?;

        Ok(Self::new(
            std::env::temp_dir(),
            &identity.directory_name("recursive-keys"),
            identity
                .expected_verification_key_digest(CircuitVerificationKeyDigest::for_ivc_circuit)?,
            RecursiveCircuitKeyGenerator::new(non_recursive_key_provider),
        ))
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

    use super::{
        CacheState, CircuitCacheIdentity, CircuitVerificationKeyDigest, KeyGenerator, KeyProvider,
    };
    use sha2::{Digest, Sha256};

    use crate::StmResult;
    use crate::circuits::halo2::{
        NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION, STM_PARAMETERS_FOR_PRODUCTION,
        circuit::CertificateCircuit, keys::NonRecursiveCircuitVerifyingKey,
    };
    use crate::circuits::halo2_ivc::tests::common::asset_readers::load_embedded_verification_context_asset;
    use crate::codec::{TryFromBytes, TryToBytes};
    use crate::{MERKLE_TREE_DEPTH_FOR_SNARK, Parameters};

    // The recursive and certificate circuits change independently, and a non-production entry is
    // trusted without comparison, so the two must not share a cache directory.
    #[test]
    fn recursive_cache_identity_differs_from_the_certificate_one() {
        let parameters = Parameters {
            k: 3,
            m: 10,
            phi_f: 0.2,
        };
        let merkle_tree_depth = 4;

        let certificate = CircuitCacheIdentity::for_configuration(&parameters, merkle_tree_depth)
            .expect("certificate identity should build");
        let recursive =
            CircuitCacheIdentity::for_recursive_configuration(&parameters, merkle_tree_depth)
                .expect("recursive identity should build");

        assert_ne!(
            certificate.directory_name("recursive-keys"),
            recursive.directory_name("recursive-keys"),
            "the recursive cache must not reuse an entry keyed only by the certificate circuit"
        );
    }

    // Binding the recursive circuit into its own fingerprint must leave certificate entries where
    // they were, so a recursive circuit change does not force certificate key generation.
    #[test]
    fn certificate_cache_identity_is_unchanged_by_the_recursive_binding() {
        let parameters = Parameters {
            k: 3,
            m: 10,
            phi_f: 0.2,
        };
        let merkle_tree_depth = 4;

        let certificate = CircuitCacheIdentity::for_configuration(&parameters, merkle_tree_depth)
            .expect("certificate identity should build");

        assert_eq!(
            certificate.directory_name("non-recursive-keys"),
            "non-recursive-keys-e9ec702f7288b8109468ebd7a9b506f98398cc8599cfc064854a50ba5763e24d",
            "certificate cache identity must not move"
        );
    }

    fn circuit_digest(byte: u8) -> CircuitVerificationKeyDigest {
        hex::encode([byte; 32]).parse().unwrap()
    }

    // The serialized key omits the gates, so the circuit enters the identity through its digest.
    #[test]
    fn certificate_cache_identity_follows_the_certificate_circuit_digest() {
        let directory_name = |certificate_circuit_digest| {
            CircuitCacheIdentity::fingerprinted(
                &parameters_outside_production(),
                MERKLE_TREE_DEPTH_FOR_SNARK,
                &certificate_circuit_digest,
                None,
            )
            .unwrap()
            .directory_name("non-recursive-keys")
        };

        assert_ne!(
            directory_name(circuit_digest(1)),
            directory_name(circuit_digest(2)),
            "a certificate circuit change must move the certificate cache directory"
        );
    }

    // The recursive circuit synthesizes the certificate circuit gates, so its keys depend on both
    // circuits.
    #[test]
    fn recursive_cache_identity_follows_both_circuit_digests() {
        let directory_name = |certificate_circuit_digest, recursive_circuit_digest| {
            CircuitCacheIdentity::fingerprinted(
                &parameters_outside_production(),
                MERKLE_TREE_DEPTH_FOR_SNARK,
                &certificate_circuit_digest,
                Some(&recursive_circuit_digest),
            )
            .unwrap()
            .directory_name("recursive-keys")
        };
        let baseline = directory_name(circuit_digest(1), circuit_digest(3));

        assert_ne!(
            baseline,
            directory_name(circuit_digest(2), circuit_digest(3)),
            "a certificate circuit change must move the recursive cache directory"
        );
        assert_ne!(
            baseline,
            directory_name(circuit_digest(1), circuit_digest(4)),
            "a recursive circuit change must move the recursive cache directory"
        );
    }

    /// Key backed by raw bytes, so the provider mechanics can be tested without real keygen.
    #[derive(Clone, Debug, PartialEq)]
    struct ByteKey(Vec<u8>);

    impl TryToBytes for ByteKey {
        fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    /// Bytes the fake key refuses to decode, standing for a corrupt cache file.
    const UNDECODABLE_KEY: &[u8] = b"undecodable";

    const UNDECODABLE_KEY_ERROR: &str = "the fake key does not decode these bytes";

    impl TryFromBytes for ByteKey {
        fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
            if bytes == UNDECODABLE_KEY {
                return Err(anyhow::anyhow!(UNDECODABLE_KEY_ERROR));
            }
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

        fn verification_key_digest(verification_key: &ByteKey) -> CircuitVerificationKeyDigest {
            hex::encode(Sha256::digest(&verification_key.0)).parse().unwrap()
        }
    }

    // The generator ignores the SRS, so the smallest constructible parameters are enough.
    fn negligible_srs() -> ParamsKZG<Bls12> {
        ParamsKZG::unsafe_setup(1, ChaCha20Rng::seed_from_u64(0))
    }

    /// A provider over a fresh temporary directory with a counting generator, returning the base
    /// directory for cleanup. The provider expects the digest of `expected_verification_key`, or
    /// trusts the cache when it is empty.
    fn counting_provider(
        name: &str,
        expected_verification_key: &[u8],
        verification_key: &[u8],
        proving_key: &[u8],
    ) -> (PathBuf, KeyProvider<CountingGenerator>) {
        let base_dir = env::temp_dir().join(name);
        fs::remove_dir_all(&base_dir).ok();
        let expected_verification_key_digest = (!expected_verification_key.is_empty()).then(|| {
            CountingGenerator::verification_key_digest(&ByteKey(expected_verification_key.to_vec()))
        });
        let provider = KeyProvider::new(
            base_dir.clone(),
            "test-circuit",
            expected_verification_key_digest,
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
            "with no expected digest a warm cache must be trusted, not recomputed"
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

    // With an expected digest, an undecodable cached verification key is a cache miss.
    #[test]
    fn an_undecodable_cached_key_differing_from_the_expected_one_is_regenerated() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");
        fs::create_dir_all(provider.verification_key_path().parent().unwrap()).unwrap();
        fs::write(provider.verification_key_path(), UNDECODABLE_KEY).unwrap();
        fs::write(provider.proving_key_path(), b"pk").unwrap();

        let (verification_key, proving_key) = provider.key_pair(&negligible_srs()).unwrap();

        assert_eq!(verification_key, ByteKey(b"vk".to_vec()));
        assert_eq!(proving_key, ByteKey(b"pk".to_vec()));
        assert_eq!(
            provider.generator().calls.get(),
            1,
            "a corrupt cached key that is not the expected one must be regenerated"
        );
        fs::remove_dir_all(&base_dir).ok();
    }

    #[test]
    fn an_undecodable_cached_key_without_an_expected_key_is_an_error() {
        let (base_dir, provider) = counting_provider(current_function!(), b"", b"vk", b"pk");
        fs::create_dir_all(provider.verification_key_path().parent().unwrap()).unwrap();
        fs::write(provider.verification_key_path(), UNDECODABLE_KEY).unwrap();
        fs::write(provider.proving_key_path(), b"pk").unwrap();

        let key_pair_error = provider
            .key_pair(&negligible_srs())
            .expect_err("a trusted but corrupt cached key must surface its decoding error");
        let verification_key_error = provider
            .verification_key(&negligible_srs())
            .expect_err("a trusted but corrupt cached key must surface its decoding error");

        assert!(key_pair_error.to_string().contains(UNDECODABLE_KEY_ERROR));
        assert!(verification_key_error.to_string().contains(UNDECODABLE_KEY_ERROR));
        assert_eq!(provider.generator().calls.get(), 0);
        fs::remove_dir_all(&base_dir).ok();
    }

    // The proving key is looked up before the verifying key is decoded, so an incomplete pair is a
    // miss whatever its verifying key holds.
    #[test]
    fn an_undecodable_cached_key_without_its_proving_key_is_regenerated() {
        let (base_dir, provider) = counting_provider(current_function!(), b"", b"vk", b"pk");
        fs::create_dir_all(provider.verification_key_path().parent().unwrap()).unwrap();
        fs::write(provider.verification_key_path(), UNDECODABLE_KEY).unwrap();

        let (verification_key, proving_key) = provider.key_pair(&negligible_srs()).unwrap();

        assert_eq!(verification_key, ByteKey(b"vk".to_vec()));
        assert_eq!(proving_key, ByteKey(b"pk".to_vec()));
        assert_eq!(
            provider.generator().calls.get(),
            1,
            "an incomplete pair must be regenerated"
        );
        fs::remove_dir_all(&base_dir).ok();
    }

    // The proving key is never compared, so a corrupt one is an error with or without an expected
    // digest.
    #[test]
    fn an_undecodable_cached_proving_key_is_an_error() {
        for (mode, expected_verification_key) in [
            ("an expected digest", b"vk".as_slice()),
            ("no expected digest", b"".as_slice()),
        ] {
            let (base_dir, provider) = counting_provider(
                &format!(
                    "{}-{}",
                    current_function!(),
                    expected_verification_key.len()
                ),
                expected_verification_key,
                b"vk",
                b"pk",
            );
            fs::create_dir_all(provider.verification_key_path().parent().unwrap()).unwrap();
            fs::write(provider.verification_key_path(), b"vk").unwrap();
            fs::write(provider.proving_key_path(), UNDECODABLE_KEY).unwrap();

            let error = provider.key_pair(&negligible_srs()).expect_err(&format!(
                "with {mode}, a corrupt cached proving key must surface its decoding error"
            ));
            let verification_key = provider.verification_key(&negligible_srs()).unwrap();

            assert!(
                error.to_string().contains(UNDECODABLE_KEY_ERROR),
                "with {mode}, expected the decoding error, got: {error}"
            );
            assert_eq!(
                verification_key,
                ByteKey(b"vk".to_vec()),
                "with {mode}, the verifying key alone is served without decoding the proving key"
            );
            assert_eq!(
                provider.generator().calls.get(),
                0,
                "with {mode}, nothing is regenerated"
            );
            fs::remove_dir_all(&base_dir).ok();
        }
    }

    // Only a missing file is a miss; any other read failure surfaces.
    #[test]
    fn an_unreadable_cached_verification_key_is_an_error() {
        let (base_dir, provider) = counting_provider(current_function!(), b"vk", b"vk", b"pk");
        fs::create_dir_all(provider.verification_key_path()).unwrap();

        let error = provider
            .key_pair(&negligible_srs())
            .expect_err("a verifying key path that cannot be read must surface the read error");

        assert!(
            error.downcast_ref::<std::io::Error>().is_some(),
            "expected the read error, got: {error}"
        );
        assert_eq!(provider.generator().calls.get(), 0);
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
                if verification_key == ByteKey(b"vk".to_vec()) && proving_key == b"pk"
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
        let provider = KeyProvider::new(base_dir.clone(), "non-recursive", None, circuit);
        fs::create_dir_all(provider.verification_key_path().parent().unwrap()).unwrap();
        fs::write(provider.verification_key_path(), b"corrupt-vk").unwrap();
        fs::write(provider.proving_key_path(), b"corrupt-pk").unwrap();

        let result = provider.key_pair(&negligible_srs());

        assert!(
            result.is_err(),
            "a trusted but corrupt verifying key must surface a deserialization error"
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

    fn parameters_outside_production() -> Parameters {
        Parameters {
            m: 9,
            k: 5,
            phi_f: 0.95,
        }
    }

    fn certificate_key_provider(
        parameters: &Parameters,
        merkle_tree_depth: u32,
    ) -> KeyProvider<CertificateCircuit> {
        KeyProvider::for_non_recursive_circuit(parameters, merkle_tree_depth).unwrap()
    }

    #[test]
    fn production_configuration_caches_under_the_stable_directory() {
        let provider =
            certificate_key_provider(&STM_PARAMETERS_FOR_PRODUCTION, MERKLE_TREE_DEPTH_FOR_SNARK);

        assert!(
            provider
                .verification_key_path()
                .ends_with("mithril-circuit/non-recursive-keys/verification-key"),
            "the production configuration must keep the stable cache directory, got {:?}",
            provider.verification_key_path()
        );
    }

    #[test]
    fn production_configuration_only_trusts_the_embedded_verification_key() {
        let provider =
            certificate_key_provider(&STM_PARAMETERS_FOR_PRODUCTION, MERKLE_TREE_DEPTH_FOR_SNARK);

        let production_key = NonRecursiveCircuitVerifyingKey::try_from_bytes(
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        )
        .unwrap();
        let another_key = load_embedded_verification_context_asset()
            .unwrap()
            .certificate_verifying_key;

        assert!(
            provider.is_fresh(&production_key),
            "the embedded production verifying key must be accepted"
        );
        assert!(
            !provider.is_fresh(&another_key),
            "a cached key that is not the embedded production one must be recomputed"
        );
    }

    #[test]
    fn configuration_outside_production_caches_under_its_own_directory() {
        let provider = certificate_key_provider(
            &parameters_outside_production(),
            MERKLE_TREE_DEPTH_FOR_SNARK,
        );
        let directory = provider.verification_key_path().parent().unwrap().to_path_buf();

        assert!(
            directory
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("non-recursive-keys-"),
            "a configuration outside production must be fingerprinted, got {directory:?}"
        );
        assert!(
            directory.parent().unwrap().ends_with("mithril-circuit"),
            "the fingerprinted directory must stay under the circuit cache folder, got {directory:?}"
        );
    }

    #[test]
    fn configuration_outside_production_trusts_the_cached_verification_key() {
        let provider = certificate_key_provider(
            &parameters_outside_production(),
            MERKLE_TREE_DEPTH_FOR_SNARK,
        );

        let any_key = load_embedded_verification_context_asset()
            .unwrap()
            .certificate_verifying_key;

        assert!(
            provider.is_fresh(&any_key),
            "a fingerprinted directory isolates the configuration, so its entry must be trusted"
        );
    }

    #[test]
    fn distinct_configurations_outside_production_do_not_share_a_directory() {
        let provider = certificate_key_provider(
            &parameters_outside_production(),
            MERKLE_TREE_DEPTH_FOR_SNARK,
        );
        let other_parameters = certificate_key_provider(
            &Parameters {
                m: 10,
                k: 5,
                phi_f: 0.95,
            },
            MERKLE_TREE_DEPTH_FOR_SNARK,
        );
        let other_depth = certificate_key_provider(
            &parameters_outside_production(),
            MERKLE_TREE_DEPTH_FOR_SNARK + 1,
        );

        assert_ne!(
            provider.verification_key_path(),
            other_parameters.verification_key_path(),
            "distinct protocol parameters must not share a cache directory"
        );
        assert_ne!(
            provider.verification_key_path(),
            other_depth.verification_key_path(),
            "distinct Merkle tree depths must not share a cache directory"
        );
    }

    #[test]
    fn recursive_circuit_follows_the_configuration_of_its_certificate_circuit() {
        let production = KeyProvider::for_recursive_circuit(
            certificate_key_provider(&STM_PARAMETERS_FOR_PRODUCTION, MERKLE_TREE_DEPTH_FOR_SNARK),
            &STM_PARAMETERS_FOR_PRODUCTION,
            MERKLE_TREE_DEPTH_FOR_SNARK,
        )
        .unwrap();
        let outside_production = KeyProvider::for_recursive_circuit(
            certificate_key_provider(
                &parameters_outside_production(),
                MERKLE_TREE_DEPTH_FOR_SNARK,
            ),
            &parameters_outside_production(),
            MERKLE_TREE_DEPTH_FOR_SNARK,
        )
        .unwrap();

        assert!(
            production
                .verification_key_path()
                .ends_with("mithril-circuit/recursive-keys/verification-key"),
            "the production configuration must keep the stable cache directory, got {:?}",
            production.verification_key_path()
        );
        assert_ne!(
            production.verification_key_path(),
            outside_production.verification_key_path(),
            "the recursive keys of a configuration outside production must be isolated"
        );
        let any_key = load_embedded_verification_context_asset()
            .unwrap()
            .recursive_verifying_key;

        assert!(
            outside_production.is_fresh(&any_key),
            "a fingerprinted directory isolates the configuration, so its entry must be trusted"
        );
    }
}
