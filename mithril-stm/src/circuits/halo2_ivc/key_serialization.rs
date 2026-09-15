//! [`TryToBytes`] / [`TryFromBytes`] impls for the recursive circuit's raw PLONK keys.
//!
//! The raw PLONK `read` is generic over the circuit type and takes its `Params`, so these impls
//! pin [`IvcCircuitData`] and its `()` params.
//!
//! Note: only the IVC circuit's keys are ever deserialized raw here (the certificate keys
//! round-trip as the high-level `MidnightVK` / `MidnightPK`), so pinning `IvcCircuitData` is
//! correct.

use crate::StmResult;
use crate::circuits::key_serialization::KEY_SERDE_FORMAT;
use crate::codec::{TryFromBytes, TryToBytes};
use anyhow::Context;

use super::{
    KZGCommitmentScheme, NativeField, PairingEngine, ProvingKey, VerifyingKey,
    circuit::IvcCircuitData,
};

// Recursive (IVC) circuit verifying key. The raw PLONK `read` is generic over the circuit and
// takes its `Params`, so it is pinned to `IvcCircuitData` with its `()` params below.
impl TryToBytes for VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>> {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.write(&mut bytes, KEY_SERDE_FORMAT)
            .with_context(|| "Failed to serialize the recursive PLONK verifying key")?;
        Ok(bytes)
    }
}

impl TryFromBytes for VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>> {
    fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
        let mut reader = bytes;
        VerifyingKey::<NativeField, KZGCommitmentScheme<PairingEngine>>::read::<_, IvcCircuitData>(
            &mut reader,
            KEY_SERDE_FORMAT,
            (),
        )
        .with_context(|| "Failed to deserialize the recursive PLONK verifying key")
    }
}

// Recursive (IVC) circuit proving key.
impl TryToBytes for ProvingKey<NativeField, KZGCommitmentScheme<PairingEngine>> {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.write(&mut bytes, KEY_SERDE_FORMAT)
            .with_context(|| "Failed to serialize the recursive PLONK proving key")?;
        Ok(bytes)
    }
}

impl TryFromBytes for ProvingKey<NativeField, KZGCommitmentScheme<PairingEngine>> {
    fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
        let mut reader = bytes;
        ProvingKey::<NativeField, KZGCommitmentScheme<PairingEngine>>::read::<_, IvcCircuitData>(
            &mut reader,
            KEY_SERDE_FORMAT,
            (),
        )
        .with_context(|| "Failed to deserialize the recursive PLONK proving key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::halo2_ivc::RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;

    #[test]
    fn production_verifying_key_serializes_to_the_embedded_bytes() {
        let verifying_key =
            VerifyingKey::<NativeField, KZGCommitmentScheme<PairingEngine>>::try_from_bytes(
                RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
            )
            .expect("production recursive verifying key bytes should deserialize");
        assert_eq!(
            verifying_key.to_bytes_vec().expect("serialize should succeed"),
            RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
            "the embedded production recursive verifying key must be its own canonical serialization"
        );
    }
}
