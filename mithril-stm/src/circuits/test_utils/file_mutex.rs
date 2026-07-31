//! Cross-process file lock over a content-keyed cache directory, used to serialize shared on-disk
//! work across the parallel slow-test processes — chiefly cold-start SNARK keygen into the shared key
//! cache.
//!
//! Mirrors [`std::sync::Mutex`]: build a [`FileMutex`] — either from a lock-file path
//! ([`FileMutex::new`]) or anchored at a content-keyed cache directory
//! ([`FileMutex::for_shared_cache`]) — call [`FileMutex::lock`] to block until this process holds the
//! exclusive lock, and keep the returned [`FileMutexGuard`] alive for as long as the protected work
//! runs; it releases the lock when dropped. [`FileMutex::directory`] returns the cache directory the
//! lock is anchored at, for storing the guarded artifacts.

use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use sha2::{Digest, Sha256};

use crate::StmResult;

/// Bumped whenever the cache layout or the key-derivation inputs change, so a cache written by an
/// earlier scheme is never reused.
const CACHE_SCHEMA_VERSION: &[u8] = b"v1";

/// Root directory name under the Cargo target directory.
const SHARED_CACHE_ROOT: &str = "mithril-circuit-test-cache";

/// Locates the Cargo target directory. `CARGO_MANIFEST_DIR` points at the crate, not the workspace,
/// so the target directory is its parent's `target` unless `CARGO_TARGET_DIR` overrides it.
fn shared_cache_root() -> PathBuf {
    let target_directory = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("the crate manifest directory always has a workspace parent")
                .join("target")
        });
    target_directory.join(SHARED_CACHE_ROOT)
}

/// A cross-process mutex backed by a single lock file: one file per lock id, exclusive across
/// processes.
pub(crate) struct FileMutex {
    lock_file_path: PathBuf,
}

impl FileMutex {
    /// Identifies the mutex by its lock-file path (one file per lock id).
    pub(crate) fn new(lock_file_path: PathBuf) -> Self {
        Self { lock_file_path }
    }

    /// Anchors the mutex at a content-keyed cache directory. `(label, fingerprint)` maps to a stable
    /// directory — a readable label prefix plus a hash of the fingerprint inputs, under the Cargo
    /// target directory — with the lock file at `<directory>/.lock`. Distinct fingerprints map to
    /// distinct directories, so different configurations never reuse one another's cache; store the
    /// guarded artifacts under [`Self::directory`]. The length prefix on each input keeps the
    /// concatenation unambiguous.
    pub(crate) fn for_shared_cache(label: &str, fingerprint: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(CACHE_SCHEMA_VERSION);
        for input in fingerprint {
            hasher.update((input.len() as u64).to_le_bytes());
            hasher.update(input);
        }
        let directory =
            shared_cache_root().join(format!("{label}-{}", hex::encode(hasher.finalize())));
        Self::new(directory.join(".lock"))
    }

    /// The cache directory this mutex is anchored at (the lock file's parent), for storing the
    /// artifacts guarded by the lock.
    pub(crate) fn directory(&self) -> &Path {
        self.lock_file_path
            .parent()
            .expect("a FileMutex lock-file path always has a parent directory")
    }

    /// Blocks until this process holds the exclusive lock, returning a guard that releases it on
    /// drop. Creates the lock file and its parent directory if they are absent.
    pub(crate) fn lock(&self) -> StmResult<FileMutexGuard> {
        if let Some(parent) = self.lock_file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let lock_file = File::create(&self.lock_file_path)?;
        lock_file.lock_exclusive()?;
        Ok(FileMutexGuard { lock_file })
    }
}

/// Holds the exclusive lock until dropped, like a [`std::sync::MutexGuard`].
pub(crate) struct FileMutexGuard {
    lock_file: File,
}

impl Drop for FileMutexGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.lock_file);
    }
}

#[cfg(test)]
mod tests {
    use super::FileMutex;

    #[test]
    fn lock_creates_the_file_and_is_reacquirable_after_the_guard_drops() {
        // Unique per test process so this never contends with another test's lock.
        let directory =
            std::env::temp_dir().join(format!("mithril-file-mutex-test-{}", std::process::id()));
        let lock_path = directory.join(".lock");
        std::fs::remove_dir_all(&directory).ok();

        {
            let guard = FileMutex::new(lock_path.clone())
                .lock()
                .expect("the first lock should be acquired");
            assert!(lock_path.exists(), "lock() must create the lock file");
            drop(guard);
        }

        // Guard dropped → lock released → a fresh lock on the same path succeeds.
        let reacquired = FileMutex::new(lock_path)
            .lock()
            .expect("the lock should be re-acquirable once the previous guard is dropped");
        drop(reacquired);
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn same_inputs_map_to_the_same_directory() {
        let first = FileMutex::for_shared_cache("non-recursive", &[b"parameters", b"depth"]);
        let second = FileMutex::for_shared_cache("non-recursive", &[b"parameters", b"depth"]);
        assert_eq!(first.directory(), second.directory());
    }

    #[test]
    fn a_change_in_any_input_maps_to_a_different_directory() {
        // The certificate-key cache keys on the production certificate verifying key (a
        // circuit-version salt), the protocol parameters, the Merkle-tree depth, and the unsafe seed
        // (no SRS degree); each must change the directory when it changes.
        let baseline = FileMutex::for_shared_cache(
            "non-recursive",
            &[b"circuit-vk-1", b"parameters-a", b"depth-4", b"seed-42"],
        );
        let other_circuit_version = FileMutex::for_shared_cache(
            "non-recursive",
            &[b"circuit-vk-2", b"parameters-a", b"depth-4", b"seed-42"],
        );
        let other_parameters = FileMutex::for_shared_cache(
            "non-recursive",
            &[b"circuit-vk-1", b"parameters-b", b"depth-4", b"seed-42"],
        );
        let other_depth = FileMutex::for_shared_cache(
            "non-recursive",
            &[b"circuit-vk-1", b"parameters-a", b"depth-5", b"seed-42"],
        );
        let other_seed = FileMutex::for_shared_cache(
            "non-recursive",
            &[b"circuit-vk-1", b"parameters-a", b"depth-4", b"seed-7"],
        );
        assert_ne!(baseline.directory(), other_circuit_version.directory());
        assert_ne!(baseline.directory(), other_parameters.directory());
        assert_ne!(baseline.directory(), other_depth.directory());
        assert_ne!(baseline.directory(), other_seed.directory());

        // The IVC setup cache folds in both production verifying keys as a circuit-version salt, like
        // the certificate-key cache and it omits the SRS degree for the same reason.
        let ivc_baseline = FileMutex::for_shared_cache(
            "ivc-setup",
            &[b"parameters-a", b"depth-4", b"circuit-vk-1"],
        );
        let other_circuit_version = FileMutex::for_shared_cache(
            "ivc-setup",
            &[b"parameters-a", b"depth-4", b"circuit-vk-2"],
        );
        assert_ne!(ivc_baseline.directory(), other_circuit_version.directory());
    }
}
