//! Field-encoding helpers for the recursive Halo2 IVC test infrastructure.
//!
//! The implementation lives in [`crate::circuits::halo2_ivc::embedded_assets`] so it is available
//! to both the tests and the `benchmark-internals` asset layer; it is re-exported here to keep the
//! existing `field_encoding::jubjub_base_from_raw_le_bytes` import paths stable.

pub(crate) use crate::circuits::halo2_ivc::embedded_assets::jubjub_base_from_raw_le_bytes;
