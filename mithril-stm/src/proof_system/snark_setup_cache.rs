//! Process-wide reuse of the SNARK prover setups.
//!
//! Loading a setup reads the SRS from disk, downsizes it to the circuit degree and deserializes the
//! key pair, which the provers would otherwise pay at every aggregation. [`SnarkProverSetupCache`]
//! loads each setup once for the lifetime of the process, at the cost of keeping the SRS and the
//! proving keys resident.
//!
//! A process only ever needs one setup: the circuit is built from the protocol parameters, and
//! changing them changes the embedded circuit verification keys, so it takes a new release of the
//! node rather than a new epoch.

use std::sync::{Arc, Mutex, PoisonError};

use crate::{
    Parameters, StmResult,
    proof_system::{halo2_ivc_snark::IvcProverSetup, halo2_snark::SnarkProverSetup},
};

/// The certificate-circuit setup of this process.
static CERTIFICATE_SETUP: SetupSlot<SnarkProverSetup> = SetupSlot::new();

/// The IVC setup of this process.
static IVC_SETUP: SetupSlot<IvcProverSetup> = SetupSlot::new();

/// A setup, loaded at most once and shared by every caller that asks for it.
struct SetupSlot<T> {
    /// The setup, absent until it has been loaded.
    setup: Mutex<Option<Arc<T>>>,
}

impl<T> SetupSlot<T> {
    /// Builds an empty slot.
    const fn new() -> Self {
        Self {
            setup: Mutex::new(None),
        }
    }

    /// Returns the setup, loading it with `load` if this is the first caller.
    ///
    /// Callers wait for that one load instead of racing through the expensive path. A failed load
    /// leaves the slot empty and is retried by the next caller.
    fn get_or_load(&self, load: impl FnOnce() -> StmResult<T>) -> StmResult<Arc<T>> {
        let mut setup = self.setup.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(setup) = setup.as_ref() {
            return Ok(setup.clone());
        }

        let loaded = Arc::new(load()?);
        *setup = Some(loaded.clone());

        Ok(loaded)
    }
}

/// Whether the prover setups are reused across the aggregations of a process.
///
/// Reuse trades resident memory for the SRS load and the key deserialization that every aggregation
/// would otherwise repeat. Every node reuses them today; the variant is carried by
/// [`NonDeterministicSnarkProverFactory`](super::snark_prover_factory::NonDeterministicSnarkProverFactory)
/// so the behavior can be selected without touching the provers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnarkProverSetupReuse {
    /// Load each setup once per process and share it, keeping it resident.
    Enabled,
    /// Load a setup for every aggregation and release it with the prover, for the callers that ask
    /// about parameters the process does not sign with.
    Disabled,
}

impl SnarkProverSetupReuse {
    /// Certificate-circuit setup for `parameters` and `merkle_tree_depth`, from the process cache
    /// when reuse is enabled and freshly loaded otherwise.
    pub(crate) fn certificate_setup(
        &self,
        parameters: &Parameters,
        merkle_tree_depth: u32,
    ) -> StmResult<Arc<SnarkProverSetup>> {
        match self {
            Self::Enabled => {
                SnarkProverSetupCache::certificate_setup(parameters, merkle_tree_depth)
            }
            Self::Disabled => Ok(Arc::new(SnarkProverSetup::try_new(
                parameters,
                merkle_tree_depth,
            )?)),
        }
    }

    /// IVC setup for `parameters`, from the process cache when reuse is enabled and freshly loaded
    /// otherwise.
    pub(crate) fn ivc_setup(&self, parameters: &Parameters) -> StmResult<Arc<IvcProverSetup>> {
        match self {
            Self::Enabled => SnarkProverSetupCache::ivc_setup(parameters),
            Self::Disabled => Ok(Arc::new(IvcProverSetup::try_new(parameters)?)),
        }
    }
}

/// Reuses the SNARK prover setups across the aggregations of a process.
struct SnarkProverSetupCache;

impl SnarkProverSetupCache {
    /// Certificate-circuit setup for `parameters` and `merkle_tree_depth`, loaded once per process.
    fn certificate_setup(
        parameters: &Parameters,
        merkle_tree_depth: u32,
    ) -> StmResult<Arc<SnarkProverSetup>> {
        CERTIFICATE_SETUP.get_or_load(|| SnarkProverSetup::try_new(parameters, merkle_tree_depth))
    }

    /// IVC setup for `parameters`, loaded once per process.
    fn ivc_setup(parameters: &Parameters) -> StmResult<Arc<IvcProverSetup>> {
        IVC_SETUP.get_or_load(|| IvcProverSetup::try_new(parameters))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use anyhow::anyhow;

    use super::*;

    #[test]
    fn the_setup_is_loaded_once_and_shared_afterwards() {
        let slot = SetupSlot::new();
        let loads = Cell::new(0);
        let load = || {
            loads.set(loads.get() + 1);
            Ok(loads.get())
        };

        let first = slot.get_or_load(load).unwrap();
        let second = slot.get_or_load(load).unwrap();

        assert_eq!(1, loads.get(), "the setup must be loaded once");
        assert!(
            Arc::ptr_eq(&first, &second),
            "both callers must share the same loaded setup"
        );
    }

    #[test]
    fn concurrent_callers_load_it_once_and_share_it() {
        let slot = SetupSlot::new();
        let loads = AtomicUsize::new(0);
        let ready = Barrier::new(4);

        let setups = thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        ready.wait();
                        slot.get_or_load(|| {
                            loads.fetch_add(1, Ordering::SeqCst);
                            thread::sleep(Duration::from_millis(50));
                            Ok(1)
                        })
                        .unwrap()
                    })
                })
                .collect();

            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });

        assert_eq!(
            1,
            loads.load(Ordering::SeqCst),
            "concurrent callers must not race through the expensive load"
        );
        for setup in &setups {
            assert!(
                Arc::ptr_eq(&setups[0], setup),
                "every caller must share the same loaded setup"
            );
        }
    }

    #[test]
    fn a_failed_load_is_not_stored() {
        let slot: SetupSlot<u32> = SetupSlot::new();

        let failure = slot.get_or_load(|| Err(anyhow!("load failed")));
        let retry = slot.get_or_load(|| Ok(1));

        assert!(failure.is_err(), "a failed load must surface its error");
        assert_eq!(
            1,
            *retry.unwrap(),
            "a failed load must leave the slot empty so the next caller retries"
        );
    }
}
