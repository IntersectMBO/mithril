//! [`TryToBytes`] / [`TryFromBytes`] impls for the certificate circuit's keys — the self-describing
//! Midnight `MidnightVK` / `MidnightPK` wrappers. Production keys use [`SerdeFormat::RawBytes`].

use anyhow::Context;
use midnight_proofs::utils::SerdeFormat;
use midnight_zk_stdlib::{MidnightPK, MidnightVK};

use crate::StmResult;
use crate::codec::{TryFromBytes, TryToBytes};

use super::circuit::CertificateCircuit;

/// Serde format used for the on-disk / in-cache production keys.
const KEY_SERDE_FORMAT: SerdeFormat = SerdeFormat::RawBytes;

// Certificate circuit verifying key. `MidnightVK` is self-describing, so reading needs only the
// serde format (no circuit type), unlike the recursive raw PLONK keys.
impl TryToBytes for MidnightVK {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.write(&mut bytes, KEY_SERDE_FORMAT)
            .with_context(|| "Failed to serialize the certificate verifying key")?;
        Ok(bytes)
    }
}

impl TryFromBytes for MidnightVK {
    fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
        let mut reader = bytes;
        MidnightVK::read(&mut reader, KEY_SERDE_FORMAT)
            .with_context(|| "Failed to deserialize the certificate verifying key")
    }
}

// Certificate circuit proving key.
impl TryToBytes for MidnightPK<CertificateCircuit> {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.write(&mut bytes, KEY_SERDE_FORMAT)
            .with_context(|| "Failed to serialize the certificate proving key")?;
        Ok(bytes)
    }
}

impl TryFromBytes for MidnightPK<CertificateCircuit> {
    fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
        let mut reader = bytes;
        MidnightPK::<CertificateCircuit>::read(&mut reader, KEY_SERDE_FORMAT)
            .with_context(|| "Failed to deserialize the certificate proving key")
    }
}

#[cfg(test)]
mod tests {
    use midnight_proofs::poly::kzg::params::ParamsKZG;
    use midnight_zk_stdlib::{self as zk, MidnightCircuit};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::Parameters;
    use crate::circuits::halo2::NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;

    #[test]
    fn production_verifying_key_serializes_to_the_embedded_bytes() {
        let verifying_key =
            MidnightVK::try_from_bytes(NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION)
                .expect("production verifying key bytes should deserialize");
        assert_eq!(
            verifying_key.to_bytes_vec().expect("serialize should succeed"),
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
            "the embedded production verifying key must be its own canonical serialization"
        );
    }

    // No production proving key is embedded (only the verifying key is), so the proving key is
    // derived from a deterministic test SRS to exercise its serialization round trip.
    #[test]
    fn proving_key_round_trips_through_bytes() {
        let parameters = Parameters {
            k: 3,
            m: 10,
            phi_f: 0.2,
        };
        let merkle_tree_depth = 4;
        let circuit = CertificateCircuit::try_new(&parameters, merkle_tree_depth)
            .expect("certificate circuit should build");
        let circuit_degree = MidnightCircuit::from_relation(&circuit, None).k();
        let srs = ParamsKZG::unsafe_setup(circuit_degree, ChaCha20Rng::seed_from_u64(42));
        let verifying_key = zk::setup_vk(&srs, &circuit);
        let proving_key = zk::setup_pk(&circuit, &verifying_key);

        let first = proving_key.to_bytes_vec().expect("serialize should succeed");
        let restored = MidnightPK::<CertificateCircuit>::try_from_bytes(&first)
            .expect("re-deserialize should succeed");
        let second = restored.to_bytes_vec().expect("re-serialize should succeed");
        assert_eq!(
            first, second,
            "certificate proving key bytes must be stable across a round trip"
        );
    }
}
