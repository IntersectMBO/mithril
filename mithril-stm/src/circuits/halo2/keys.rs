// Per-circuit key newtypes for the non-recursive (certificate) circuit, and the circuit's
// implementation of [`KeyGenerator`]. The newtypes wrap Midnight's self-describing
// `MidnightVK` / `MidnightPK` and delegate their byte (de)serialization to the impls in
// `key_serialization`.
use midnight_curves::Bls12;
use midnight_proofs::poly::commitment::Params;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_zk_stdlib::{self as zk, MidnightCircuit, MidnightPK, MidnightVK};
use serde::{Deserialize, Serialize};

use crate::StmResult;
use crate::circuits::halo2_ivc::{KZGCommitmentScheme, NativeField, PairingEngine, VerifyingKey};
use crate::circuits::key_generator::KeyGenerator;
use crate::codec::{TryFromBytes, TryToBytes};

use super::circuit::StmCertificateCircuit;

/// Verifying key of the non-recursive certificate circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct NonRecursiveCircuitVerifyingKey(
    #[serde(with = "midnight_verifying_key_serde")] MidnightVK,
);

/// Proving key of the non-recursive certificate circuit.
#[derive(Clone)]
pub(crate) struct NonRecursiveCircuitProvingKey(MidnightPK<StmCertificateCircuit>);

impl NonRecursiveCircuitVerifyingKey {
    /// Wraps a Midnight verifying key.
    pub(crate) fn new(midnight_vk: MidnightVK) -> Self {
        Self(midnight_vk)
    }

    /// Borrows the wrapped Midnight verifying key.
    pub(crate) fn midnight_vk(&self) -> &MidnightVK {
        &self.0
    }

    #[cfg(test)]
    /// Returns the circuit degree using the underlying `MidnightVK`
    pub(crate) fn circuit_degree(&self) -> u32 {
        self.midnight_vk().vk().get_domain().k()
    }
}

impl AsRef<VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>>
    for NonRecursiveCircuitVerifyingKey
{
    fn as_ref(&self) -> &VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>> {
        self.0.vk()
    }
}

/// Serde for the wrapped Midnight verifying key: delegates to the key's [`TryToBytes`] /
/// [`TryFromBytes`] impl so the raw-bytes encoding is defined in one place.
mod midnight_verifying_key_serde {
    use midnight_zk_stdlib::MidnightVK;
    use serde::{Deserializer, Serializer};

    use crate::codec::{TryFromBytes, TryToBytes};

    pub(super) fn serialize<S: Serializer>(
        verifying_key: &MidnightVK,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let bytes = verifying_key.to_bytes_vec().map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<MidnightVK, D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        MidnightVK::try_from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl NonRecursiveCircuitProvingKey {
    /// Borrows the wrapped Midnight proving key, for proof generation.
    pub(crate) fn midnight_pk(&self) -> &MidnightPK<StmCertificateCircuit> {
        &self.0
    }
}

impl TryToBytes for NonRecursiveCircuitVerifyingKey {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        self.0.to_bytes_vec()
    }
}

impl TryFromBytes for NonRecursiveCircuitVerifyingKey {
    fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
        Ok(Self(MidnightVK::try_from_bytes(bytes)?))
    }
}

impl TryToBytes for NonRecursiveCircuitProvingKey {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        self.0.to_bytes_vec()
    }
}

impl TryFromBytes for NonRecursiveCircuitProvingKey {
    fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
        Ok(Self(MidnightPK::<StmCertificateCircuit>::try_from_bytes(
            bytes,
        )?))
    }
}

impl KeyGenerator for StmCertificateCircuit {
    type VerifyingKey = NonRecursiveCircuitVerifyingKey;
    type ProvingKey = NonRecursiveCircuitProvingKey;

    fn generate_key_pair(
        &self,
        srs: &ParamsKZG<Bls12>,
    ) -> StmResult<(Self::VerifyingKey, Self::ProvingKey)> {
        // Keygen needs the SRS at the circuit's degree. The SRS must be at least that large: when it
        // is exactly the circuit degree it is used directly, and when it is larger it is downsized on
        // a clone so the caller's SRS (which may be reused at a different degree) is left untouched.
        let circuit_degree = MidnightCircuit::from_relation(self, None).k();
        anyhow::ensure!(
            srs.max_k() >= circuit_degree,
            "the SRS must be at least the certificate circuit degree"
        );
        let verifying_key = if srs.max_k() == circuit_degree {
            zk::setup_vk(srs, self)
        } else {
            let mut certificate_srs = srs.clone();
            certificate_srs.downsize(circuit_degree);
            zk::setup_vk(&certificate_srs, self)
        };
        let proving_key = zk::setup_pk(self, &verifying_key);
        Ok((
            NonRecursiveCircuitVerifyingKey(verifying_key),
            NonRecursiveCircuitProvingKey(proving_key),
        ))
    }
}

#[cfg(test)]
mod tests {
    use midnight_proofs::poly::commitment::Params;
    use midnight_proofs::poly::kzg::params::ParamsKZG;
    use midnight_zk_stdlib::MidnightCircuit;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::{NonRecursiveCircuitProvingKey, NonRecursiveCircuitVerifyingKey};
    use crate::Parameters;
    use crate::circuits::halo2::NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
    use crate::circuits::halo2::circuit::StmCertificateCircuit;
    use crate::circuits::key_generator::KeyGenerator;
    use crate::codec::{TryFromBytes, TryToBytes};

    #[test]
    fn verifying_key_serde_round_trips_via_the_byte_codec() {
        // Uses the embedded production verifying key so no keygen is needed (fast).
        let verifying_key = NonRecursiveCircuitVerifyingKey::try_from_bytes(
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        )
        .expect("production verifying key bytes should deserialize");

        // Exercises the `#[serde(with = "midnight_verifying_key_serde")]` serialize + deserialize path.
        let json = serde_json::to_vec(&verifying_key).expect("serde serialize should succeed");
        let restored: NonRecursiveCircuitVerifyingKey =
            serde_json::from_slice(&json).expect("serde deserialize should succeed");

        // The serde path must agree with the byte codec it now delegates to.
        assert_eq!(
            verifying_key.to_bytes_vec().unwrap(),
            restored.to_bytes_vec().unwrap(),
            "serde round trip must preserve the verifying key bytes"
        );
    }

    #[test]
    fn generate_key_pair_downsizes_a_clone_and_round_trips() {
        let parameters = Parameters {
            k: 3,
            m: 10,
            phi_f: 0.2,
        };
        let merkle_tree_depth = 4;
        let circuit = StmCertificateCircuit::try_new(&parameters, merkle_tree_depth)
            .expect("certificate circuit should build");
        // Oversized on purpose: the generator must clone and downsize to the circuit's degree
        // (keygen would otherwise fail), and the caller's SRS must be left untouched.
        let oversized_degree = MidnightCircuit::from_relation(&circuit, None).k() + 1;
        let srs = ParamsKZG::unsafe_setup(oversized_degree, ChaCha20Rng::seed_from_u64(42));

        let (verifying_key, proving_key) = circuit
            .generate_key_pair(&srs)
            .expect("key generation should succeed");

        assert_eq!(
            srs.max_k(),
            oversized_degree,
            "the generator must downsize a clone, leaving the caller's SRS untouched"
        );

        let verifying_key_bytes = verifying_key.to_bytes_vec().expect("serialize should succeed");
        let restored_verifying_key =
            NonRecursiveCircuitVerifyingKey::try_from_bytes(&verifying_key_bytes)
                .expect("deserialize should succeed");
        assert_eq!(
            verifying_key_bytes,
            restored_verifying_key.to_bytes_vec().unwrap(),
            "verifying key bytes must be stable across a round trip"
        );

        let proving_key_bytes = proving_key.to_bytes_vec().expect("serialize should succeed");
        let restored_proving_key =
            NonRecursiveCircuitProvingKey::try_from_bytes(&proving_key_bytes)
                .expect("deserialize should succeed");
        assert_eq!(
            proving_key_bytes,
            restored_proving_key.to_bytes_vec().unwrap(),
            "proving key bytes must be stable across a round trip"
        );
    }

    #[test]
    fn generate_key_pair_yields_identical_keys_for_exact_and_oversized_srs() {
        let parameters = Parameters {
            k: 3,
            m: 10,
            phi_f: 0.2,
        };
        let merkle_tree_depth = 4;
        let circuit = StmCertificateCircuit::try_new(&parameters, merkle_tree_depth)
            .expect("certificate circuit should build");
        let circuit_degree = MidnightCircuit::from_relation(&circuit, None).k();

        // The generator keygens directly from an already-sized SRS and clones+downsizes an oversized
        // one; both paths must produce identical keys (the downsized clone shares the SRS's tau).
        let exact_srs = ParamsKZG::unsafe_setup(circuit_degree, ChaCha20Rng::seed_from_u64(42));
        let oversized_srs =
            ParamsKZG::unsafe_setup(circuit_degree + 1, ChaCha20Rng::seed_from_u64(42));

        let (verifying_key_from_exact, proving_key_from_exact) =
            circuit.generate_key_pair(&exact_srs).unwrap();
        let (verifying_key_from_oversized, proving_key_from_oversized) =
            circuit.generate_key_pair(&oversized_srs).unwrap();

        assert_eq!(
            verifying_key_from_exact.to_bytes_vec().unwrap(),
            verifying_key_from_oversized.to_bytes_vec().unwrap(),
            "the already-sized and oversized paths must produce the same verifying key"
        );
        assert_eq!(
            proving_key_from_exact.to_bytes_vec().unwrap(),
            proving_key_from_oversized.to_bytes_vec().unwrap(),
            "the already-sized and oversized paths must produce the same proving key"
        );
        assert_eq!(
            exact_srs.max_k(),
            circuit_degree,
            "the already-sized SRS must be used directly, untouched"
        );
    }
}
