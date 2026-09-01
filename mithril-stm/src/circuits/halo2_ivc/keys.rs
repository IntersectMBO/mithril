// Per-circuit key newtypes for the recursive (IVC) circuit, and the circuit's implementation of
// [`KeyGenerator`]. The newtypes wrap the raw PLONK keys and delegate their byte
// (de)serialization to the impls in `key_serialization`; the raw keys stay internal to
// `circuits::halo2_ivc`, where Halo2's keygen APIs require them.
use midnight_curves::Bls12;
use midnight_proofs::plonk::{keygen_pk, keygen_vk_with_k};
use midnight_proofs::poly::commitment::Params;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use serde::{Deserialize, Serialize};

use crate::StmResult;
use crate::circuits::halo2::circuit::CertificateCircuit;
use crate::circuits::halo2::keys::NonRecursiveCircuitVerifyingKey;
use crate::circuits::key_generator::KeyGenerator;
use crate::circuits::key_provider::KeyProvider;
use crate::codec::{TryFromBytes, TryToBytes};

use super::{
    KZGCommitmentScheme, NativeField, PairingEngine, ProvingKey, RECURSIVE_CIRCUIT_DEGREE,
    VerifyingKey, circuit::IvcCircuitData,
};

/// Verifying key of the recursive (IVC) circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RecursiveCircuitVerifyingKey(
    #[serde(with = "recursive_verifying_key_serde")]
    VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>,
);

/// Proving key of the recursive (IVC) circuit.
pub(crate) struct RecursiveCircuitProvingKey(
    ProvingKey<NativeField, KZGCommitmentScheme<PairingEngine>>,
);

impl RecursiveCircuitVerifyingKey {
    /// Wraps a raw recursive verifying key.
    pub(crate) fn new(
        verifying_key: VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>,
    ) -> Self {
        Self(verifying_key)
    }

    /// Borrows the wrapped raw verifying key, for the prover/verifier and fixed-base construction.
    pub(crate) fn verifying_key(
        &self,
    ) -> &VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>> {
        &self.0
    }

    #[cfg(test)]
    /// Returns the circuit degree using the domain of the underlying `VerifyingKey`
    pub(crate) fn circuit_degree(&self) -> u32 {
        self.as_ref().get_domain().k()
    }
}

impl AsRef<VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>>
    for RecursiveCircuitVerifyingKey
{
    fn as_ref(&self) -> &VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>> {
        &self.0
    }
}

impl RecursiveCircuitProvingKey {
    /// Wraps a raw recursive proving key.
    pub(crate) fn new(
        proving_key: ProvingKey<NativeField, KZGCommitmentScheme<PairingEngine>>,
    ) -> Self {
        Self(proving_key)
    }

    /// Borrows the wrapped raw proving key, for proof generation.
    pub(crate) fn proving_key(
        &self,
    ) -> &ProvingKey<NativeField, KZGCommitmentScheme<PairingEngine>> {
        &self.0
    }
}

impl TryToBytes for RecursiveCircuitVerifyingKey {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        self.0.to_bytes_vec()
    }
}

impl TryFromBytes for RecursiveCircuitVerifyingKey {
    fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
        Ok(Self(VerifyingKey::<
            NativeField,
            KZGCommitmentScheme<PairingEngine>,
        >::try_from_bytes(bytes)?))
    }
}

impl TryToBytes for RecursiveCircuitProvingKey {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        self.0.to_bytes_vec()
    }
}

impl TryFromBytes for RecursiveCircuitProvingKey {
    fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
        Ok(Self(ProvingKey::<
            NativeField,
            KZGCommitmentScheme<PairingEngine>,
        >::try_from_bytes(bytes)?))
    }
}

/// Serde for the wrapped raw recursive verifying key: the raw-bytes encoding pinned to the IVC
/// circuit (via the key's byte codec), matching the embedded verifier-data wire format.
mod recursive_verifying_key_serde {
    use serde::{Deserializer, Serializer};

    use super::{KZGCommitmentScheme, NativeField, PairingEngine, VerifyingKey};
    use crate::codec::{TryFromBytes, TryToBytes};

    pub(super) fn serialize<S: Serializer>(
        verifying_key: &VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let bytes = verifying_key.to_bytes_vec().map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>, D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        VerifyingKey::<NativeField, KZGCommitmentScheme<PairingEngine>>::try_from_bytes(&bytes)
            .map_err(serde::de::Error::custom)
    }
}

impl KeyGenerator for IvcCircuitData {
    type VerifyingKey = RecursiveCircuitVerifyingKey;
    type ProvingKey = RecursiveCircuitProvingKey;

    fn generate_key_pair(
        &self,
        srs: &ParamsKZG<Bls12>,
    ) -> StmResult<(Self::VerifyingKey, Self::ProvingKey)> {
        // Keygen needs the SRS at the IVC circuit's degree. The SRS must be at least that large: when
        // it is exactly RECURSIVE_CIRCUIT_DEGREE it is used directly, and when it is larger it is
        // downsized on a clone so the caller's SRS (which may be reused at a different degree) is left
        // untouched.
        anyhow::ensure!(
            srs.max_k() >= RECURSIVE_CIRCUIT_DEGREE,
            "the SRS must be at least the recursive circuit degree"
        );
        let verifying_key = if srs.max_k() == RECURSIVE_CIRCUIT_DEGREE {
            keygen_vk_with_k(srs, self, RECURSIVE_CIRCUIT_DEGREE)?
        } else {
            let mut recursive_srs = srs.clone();
            recursive_srs.downsize(RECURSIVE_CIRCUIT_DEGREE);
            keygen_vk_with_k(&recursive_srs, self, RECURSIVE_CIRCUIT_DEGREE)?
        };
        let proving_key = keygen_pk(verifying_key.clone(), self)?;
        Ok((
            RecursiveCircuitVerifyingKey(verifying_key),
            RecursiveCircuitProvingKey(proving_key),
        ))
    }
}

/// Generates the recursive (IVC) circuit's keys, wrapping the non-recursive key provider it needs. The
/// recursive circuit is built from the certificate verifying key, so its key pair can only be derived
/// once that verifying key is known; wrapping the non-recursive provider lets the recursive keys be
/// derived through the same [`KeyProvider`] machinery (and its on-disk cache) as any other circuit,
/// rather than through a caller-supplied closure.
pub(crate) struct RecursiveCircuitKeyGenerator {
    non_recursive_key_provider: KeyProvider<CertificateCircuit>,
}

impl RecursiveCircuitKeyGenerator {
    /// Wraps the non-recursive key provider the recursive circuit is built from.
    pub(crate) fn new(non_recursive_key_provider: KeyProvider<CertificateCircuit>) -> Self {
        Self {
            non_recursive_key_provider,
        }
    }

    /// Derives the certificate verifying key the recursive circuit verifies, through the wrapped
    /// non-recursive provider (and its cache).
    pub(crate) fn certificate_verifying_key(
        &self,
        srs: &ParamsKZG<Bls12>,
    ) -> StmResult<NonRecursiveCircuitVerifyingKey> {
        self.non_recursive_key_provider.verification_key(srs)
    }
}

impl KeyGenerator for RecursiveCircuitKeyGenerator {
    type VerifyingKey = RecursiveCircuitVerifyingKey;
    type ProvingKey = RecursiveCircuitProvingKey;

    fn generate_key_pair(
        &self,
        srs: &ParamsKZG<Bls12>,
    ) -> StmResult<(Self::VerifyingKey, Self::ProvingKey)> {
        let certificate_verifying_key = self.non_recursive_key_provider.verification_key(srs)?;
        IvcCircuitData::unknown(&certificate_verifying_key)?.generate_key_pair(srs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::halo2_ivc::RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;

    #[test]
    fn recursive_verifying_key_newtype_round_trips_through_bytes() {
        let verifying_key = RecursiveCircuitVerifyingKey::try_from_bytes(
            RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        )
        .expect("production recursive verifying key bytes should deserialize");
        assert_eq!(
            verifying_key.to_bytes_vec().expect("serialize should succeed"),
            RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
            "the recursive verifying key newtype must round-trip to the embedded production bytes"
        );
    }
}
