//! Process-wide reuse of the SNARK prover setups.
//!
//! Loading a setup reads the SRS from disk, downsizes it to the circuit degree and deserializes the
//! key pair, which the provers would otherwise pay at every aggregation. [`SnarkProverSetupCache`]
//! loads each setup once for the lifetime of the process, at the cost of keeping the SRS and the
//! proving keys resident.
//!
//! Each slot holds the setup of one configuration at a time. The circuit is built from the protocol
//! parameters, so a caller asking for other parameters is never served a setup derived for the ones
//! it did not ask for: the setup is loaded again and the previous one released.

use std::sync::{Arc, Mutex, PoisonError};

use crate::{
    MERKLE_TREE_DEPTH_FOR_SNARK, Parameters, StmResult,
    proof_system::{halo2_ivc_snark::IvcProverSetup, halo2_snark::SnarkProverSetup},
};

/// The certificate-circuit setup of this process.
static CERTIFICATE_SETUP: SetupSlot<SnarkProverSetup> = SetupSlot::new();

/// The IVC setup of this process.
static IVC_SETUP: SetupSlot<IvcProverSetup> = SetupSlot::new();

/// The configuration a setup was loaded for, which its keys only fit.
#[derive(PartialEq, Eq)]
struct SetupCacheKey {
    /// Serialized protocol parameters.
    parameters: Vec<u8>,
    /// Merkle tree depth of the certificate circuit.
    merkle_tree_depth: u32,
}

impl SetupCacheKey {
    /// Identifies the configuration made of `parameters` and `merkle_tree_depth`.
    fn try_new(parameters: &Parameters, merkle_tree_depth: u32) -> StmResult<Self> {
        Ok(Self {
            parameters: parameters.to_bytes()?,
            merkle_tree_depth,
        })
    }
}

/// A setup and the configuration it was loaded for, shared by every caller asking for that same
/// configuration.
struct SetupSlot<T> {
    /// The setup with its configuration, absent until one has been loaded.
    setup: Mutex<Option<(SetupCacheKey, Arc<T>)>>,
}

impl<T> SetupSlot<T> {
    /// Builds an empty slot.
    const fn new() -> Self {
        Self {
            setup: Mutex::new(None),
        }
    }

    /// Returns the setup of `key`, loading it with `load` when the slot holds another configuration
    /// or none yet.
    ///
    /// Callers of one configuration wait for its single load instead of racing through the expensive
    /// path. A configuration change loads again and releases the previous setup, so a process never
    /// proves with keys derived for other parameters, nor keeps every configuration it has seen
    /// resident. A failed load leaves the slot empty and is retried by the next caller.
    fn get_or_load(
        &self,
        key: SetupCacheKey,
        load: impl FnOnce() -> StmResult<T>,
    ) -> StmResult<Arc<T>> {
        let mut setup = self.setup.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((loaded_for, loaded)) = setup.as_ref()
            && loaded_for == &key
        {
            return Ok(loaded.clone());
        }

        let loaded = Arc::new(load()?);
        *setup = Some((key, loaded.clone()));

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
        CERTIFICATE_SETUP.get_or_load(
            SetupCacheKey::try_new(parameters, merkle_tree_depth)?,
            || SnarkProverSetup::try_new(parameters, merkle_tree_depth),
        )
    }

    /// IVC setup for `parameters`, loaded once per process.
    fn ivc_setup(parameters: &Parameters) -> StmResult<Arc<IvcProverSetup>> {
        IVC_SETUP.get_or_load(
            SetupCacheKey::try_new(parameters, MERKLE_TREE_DEPTH_FOR_SNARK)?,
            || IvcProverSetup::try_new(parameters),
        )
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

    fn key(quorum: u64) -> SetupCacheKey {
        SetupCacheKey::try_new(
            &Parameters {
                m: 9,
                k: quorum,
                phi_f: 0.95,
            },
            MERKLE_TREE_DEPTH_FOR_SNARK,
        )
        .unwrap()
    }

    #[test]
    fn the_setup_of_a_configuration_is_loaded_once_and_shared_afterwards() {
        let slot = SetupSlot::new();
        let loads = Cell::new(0);
        let load = || {
            loads.set(loads.get() + 1);
            Ok(loads.get())
        };

        let first = slot.get_or_load(key(5), load).unwrap();
        let second = slot.get_or_load(key(5), load).unwrap();

        assert_eq!(1, loads.get(), "the setup must be loaded once");
        assert!(
            Arc::ptr_eq(&first, &second),
            "both callers must share the same loaded setup"
        );
    }

    #[test]
    fn another_configuration_is_loaded_instead_of_reusing_the_stored_setup() {
        let slot = SetupSlot::new();
        let loads = Cell::new(0);
        let load = || {
            loads.set(loads.get() + 1);
            Ok(loads.get())
        };

        let first = slot.get_or_load(key(5), load).unwrap();
        let other = slot.get_or_load(key(6), load).unwrap();

        assert_eq!(
            2,
            loads.get(),
            "a configuration change must load its own setup"
        );
        assert!(
            !Arc::ptr_eq(&first, &other),
            "a configuration must never be served the setup of another one"
        );
    }

    #[test]
    fn a_configuration_that_came_back_is_loaded_again() {
        let slot = SetupSlot::new();
        let loads = Cell::new(0);
        let load = || {
            loads.set(loads.get() + 1);
            Ok(loads.get())
        };

        slot.get_or_load(key(5), load).unwrap();
        slot.get_or_load(key(6), load).unwrap();
        let back = slot.get_or_load(key(5), load).unwrap();

        assert_eq!(
            3,
            loads.get(),
            "the slot holds one configuration, so the previous one is loaded again"
        );
        assert_eq!(3, *back);
    }

    #[test]
    fn concurrent_callers_of_a_configuration_load_it_once_and_share_it() {
        let slot = SetupSlot::new();
        let loads = AtomicUsize::new(0);
        let ready = Barrier::new(4);

        let setups = thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        ready.wait();
                        slot.get_or_load(key(5), || {
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

        let failure = slot.get_or_load(key(5), || Err(anyhow!("load failed")));
        let retry = slot.get_or_load(key(5), || Ok(1));

        assert!(failure.is_err(), "a failed load must surface its error");
        assert_eq!(
            1,
            *retry.unwrap(),
            "a failed load must leave the slot empty so the next caller retries"
        );
    }
}
