// Per-circuit key newtypes for the non-recursive (certificate) circuit, and the circuit's
// implementation of [`KeyGenerator`]. The newtypes wrap Midnight's self-describing
// `MidnightVK` / `MidnightPK` and delegate their byte (de)serialization to the impls in
// `key_serialization`.
use std::io::Read;

use anyhow::{Context, anyhow};
use midnight_curves::Bls12;
use midnight_proofs::poly::commitment::Params;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_zk_stdlib::{
    self as zk, MidnightCircuit, MidnightPK, MidnightVK, ZkStdLib, ZkStdLibArch,
};
use serde::{Deserialize, Serialize};

use crate::StmResult;
use crate::circuits::halo2::errors::CertificateCircuitError;
use crate::circuits::halo2_ivc::{
    ConstraintSystem, KZGCommitmentScheme, NativeField, PairingEngine, VerifyingKey,
};
use crate::circuits::key_generator::KeyGenerator;
use crate::circuits::key_serialization::KEY_SERDE_FORMAT;
use crate::circuits::trusted_setup::MIDNIGHT_SRS_DEGREE;
use crate::codec::{TryFromBytes, TryToBytes};

use super::circuit::{CertificateCircuit, certificate_circuit_architecture};

/// Verifying key of the non-recursive certificate circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct NonRecursiveCircuitVerifyingKey(
    #[serde(with = "certificate_verifying_key_serde")] MidnightVK,
);

/// Proving key of the non-recursive certificate circuit.
#[derive(Clone)]
pub(crate) struct NonRecursiveCircuitProvingKey(MidnightPK<CertificateCircuit>);

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

    /// Number of fixed commitments the approved architecture produces at `degree`.
    ///
    /// The reader takes this count from the bytes and reads that many commitments, so a key can
    /// declare fewer than the configured constraint system has columns; later verification indexes
    /// commitments by those columns. The degree comes from the key because certificate degrees vary.
    fn expected_fixed_commitment_count(degree: u32) -> usize {
        let mut constraint_system = ConstraintSystem::<NativeField>::default();
        ZkStdLib::configure(
            &mut constraint_system,
            (certificate_circuit_architecture(), (degree - 1) as u8),
        );
        // Selectors become fixed columns when the key is read.
        constraint_system.num_fixed_columns() + constraint_system.num_selectors()
    }

    /// Checks the header of an encoded certificate verifying key before it is decoded.
    ///
    /// `MidnightVK` takes its architecture and degree from the bytes, so without this any Midnight
    /// circuit's key decodes in the certificate position — including the recursive circuit's, which
    /// this crate now encodes the same way.
    ///
    /// Certificate degrees legitimately vary — production, the full fixture and the small golden
    /// context all differ — so they are bounded by the trusted setup rather than pinned. The key
    /// declares one twice, once in its Midnight envelope and once in the raw key it wraps, and the
    /// reader takes them independently: each reaches a `k - 1` subtraction on a byte, which
    /// underflows at zero, or a domain constructor that asserts.
    pub(crate) fn validate_encoded_header(bytes: &[u8]) -> StmResult<()> {
        let mut reader = bytes;
        let architecture = ZkStdLibArch::read_from_serialized_vk(&mut reader)
            .with_context(|| "Failed to read the certificate verifying key architecture")?;
        if architecture != certificate_circuit_architecture() {
            return Err(anyhow!(
                CertificateCircuitError::VerificationKeyArchitectureMismatch
            ));
        }

        let mut envelope_degree = [0u8; 1];
        reader
            .read_exact(&mut envelope_degree)
            .with_context(|| "Failed to read the certificate verifying key degree")?;

        let mut public_input_count = [0u8; 4];
        reader
            .read_exact(&mut public_input_count)
            .with_context(|| "Failed to read the certificate verifying key public input count")?;

        // The wrapped raw key opens with its own version and degree.
        let mut raw_header = [0u8; 2];
        reader
            .read_exact(&mut raw_header)
            .with_context(|| "Failed to read the wrapped raw certificate key header")?;

        for degree in [envelope_degree[0], raw_header[1]] {
            if degree == 0 || degree > MIDNIGHT_SRS_DEGREE {
                return Err(anyhow!(
                    CertificateCircuitError::VerificationKeyDegreeMismatch {
                        expected: u32::from(MIDNIGHT_SRS_DEGREE),
                        actual: u32::from(degree),
                    }
                ));
            }
        }
        if envelope_degree[0] != raw_header[1] {
            return Err(anyhow!(
                CertificateCircuitError::VerificationKeyDegreeMismatch {
                    expected: u32::from(envelope_degree[0]),
                    actual: u32::from(raw_header[1]),
                }
            ));
        }
        Ok(())
    }
}

impl AsRef<VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>>
    for NonRecursiveCircuitVerifyingKey
{
    fn as_ref(&self) -> &VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>> {
        self.0.vk()
    }
}

impl NonRecursiveCircuitProvingKey {
    /// Borrows the wrapped Midnight proving key, for proof generation.
    pub(crate) fn midnight_pk(&self) -> &MidnightPK<CertificateCircuit> {
        &self.0
    }
}

/// Serde for the wrapped Midnight verifying key, routed through the newtype's guarded byte decoder
/// so the verifier-data envelopes cannot reach the dependency's readers unchecked.
mod certificate_verifying_key_serde {
    use midnight_zk_stdlib::MidnightVK;
    use serde::{Deserializer, Serializer};

    use super::NonRecursiveCircuitVerifyingKey;
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
        NonRecursiveCircuitVerifyingKey::try_from_bytes(&bytes)
            .map(|key| key.0)
            .map_err(serde::de::Error::custom)
    }
}

impl TryToBytes for NonRecursiveCircuitVerifyingKey {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        self.0.to_bytes_vec()
    }
}

impl TryFromBytes for NonRecursiveCircuitVerifyingKey {
    fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
        Self::validate_encoded_header(bytes)?;

        let mut reader = bytes;
        let midnight_vk = MidnightVK::read(&mut reader, KEY_SERDE_FORMAT)
            .with_context(|| "Failed to deserialize the certificate verifying key")?;
        // A standalone encoding holds one key and nothing else; the streaming asset reader, where a
        // fixed-base map follows the key, deliberately does not go through here.
        if !reader.is_empty() {
            return Err(anyhow!(
                CertificateCircuitError::VerificationKeyEncodingHasTrailingBytes {
                    trailing: reader.len(),
                }
            ));
        }

        let actual = midnight_vk.vk().fixed_commitments().len();
        let expected = Self::expected_fixed_commitment_count(midnight_vk.vk().get_domain().k());
        if actual != expected {
            return Err(anyhow!(
                CertificateCircuitError::VerificationKeyCommitmentCountMismatch {
                    expected,
                    actual
                }
            ));
        }

        Ok(Self(midnight_vk))
    }
}

impl TryToBytes for NonRecursiveCircuitProvingKey {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        self.0.to_bytes_vec()
    }
}

impl TryFromBytes for NonRecursiveCircuitProvingKey {
    fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
        Ok(Self(MidnightPK::<CertificateCircuit>::try_from_bytes(
            bytes,
        )?))
    }
}

impl KeyGenerator for CertificateCircuit {
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

    use midnight_proofs::poly::commitment::PolynomialCommitmentScheme;
    use midnight_proofs::utils::helpers::byte_length;
    use midnight_zk_stdlib::ZkStdLibArch;

    use super::{NonRecursiveCircuitProvingKey, NonRecursiveCircuitVerifyingKey};
    use crate::Parameters;
    use crate::circuits::halo2::NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
    use crate::circuits::halo2::circuit::CertificateCircuit;
    use crate::circuits::halo2::errors::CertificateCircuitError;
    use crate::circuits::halo2_ivc::{
        KZGCommitmentScheme, NativeField, PairingEngine,
        RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
    };
    use crate::circuits::key_generator::KeyGenerator;
    use crate::circuits::key_serialization::KEY_SERDE_FORMAT;
    use crate::codec::{TryFromBytes, TryToBytes};

    #[test]
    fn verifying_key_serde_round_trips_via_the_byte_codec() {
        // Uses the embedded production verifying key so no keygen is needed (fast).
        let verifying_key = NonRecursiveCircuitVerifyingKey::try_from_bytes(
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        )
        .expect("production verifying key bytes should deserialize");

        // Exercises the `#[serde(with = "certificate_verifying_key_serde")]` serialize + deserialize path.
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
        let circuit = CertificateCircuit::try_new(&parameters, merkle_tree_depth)
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
        let circuit = CertificateCircuit::try_new(&parameters, merkle_tree_depth)
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

    // Both circuits encode their keys the same way, so only the declared architecture separates
    // them: without the header check the recursive key would decode in the certificate position.
    #[test]
    fn a_recursive_verifying_key_is_rejected_in_the_certificate_position() {
        let error = NonRecursiveCircuitVerifyingKey::try_from_bytes(
            RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        )
        .expect_err("a recursive key must not decode as a certificate one");

        assert!(
            matches!(
                error.downcast_ref::<CertificateCircuitError>(),
                Some(CertificateCircuitError::VerificationKeyArchitectureMismatch)
            ),
            "expected an architecture mismatch, got: {error}"
        );
    }

    // `MidnightVK::read` derives its range bit length as `k - 1` on a byte, so a zero degree would
    // underflow inside the dependency before any check of ours could run.
    #[test]
    fn a_zero_degree_header_is_rejected_before_it_can_underflow() {
        let mut bytes = NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.to_vec();
        // The degree byte follows the encoded architecture.
        let mut reader = NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
        ZkStdLibArch::read_from_serialized_vk(&mut reader).expect("architecture should read");
        let degree_index = bytes.len() - reader.len();
        bytes[degree_index] = 0;

        let error = NonRecursiveCircuitVerifyingKey::try_from_bytes(&bytes)
            .expect_err("a zero degree must be rejected");

        assert!(
            matches!(
                error.downcast_ref::<CertificateCircuitError>(),
                Some(CertificateCircuitError::VerificationKeyDegreeMismatch { actual: 0, .. })
            ),
            "expected a degree mismatch, got: {error}"
        );
    }

    // The envelope and the raw key it wraps each declare a degree, and the reader takes them
    // independently, so an envelope declaring a supported degree can carry a raw key of another.
    #[test]
    fn a_wrapped_raw_key_of_another_degree_is_rejected() {
        let mut bytes = NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.to_vec();
        // Past the architecture, the envelope degree and the public input count lies the raw key's
        // own version byte, and its degree follows.
        let mut reader = NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
        ZkStdLibArch::read_from_serialized_vk(&mut reader).expect("architecture should read");
        let envelope_degree_index = bytes.len() - reader.len();
        let raw_degree_index = envelope_degree_index + 1 + 4 + 1;
        // A degree the trusted setup could have produced, so only the disagreement is under test.
        let other_degree = bytes[envelope_degree_index] - 1;
        bytes[raw_degree_index] = other_degree;

        let error = NonRecursiveCircuitVerifyingKey::try_from_bytes(&bytes)
            .expect_err("a wrapped key of another degree must be rejected");

        assert!(
            matches!(
                error.downcast_ref::<CertificateCircuitError>(),
                Some(CertificateCircuitError::VerificationKeyDegreeMismatch { actual, .. })
                    if *actual == u32::from(other_degree)
            ),
            "expected a degree mismatch, got: {error}"
        );
    }

    // A key whose canonical re-serialization differs from the bytes it was decoded from would break
    // every digest taken over an encoded key.
    #[test]
    fn an_encoding_with_trailing_bytes_is_rejected() {
        let mut bytes = NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.to_vec();
        bytes.push(0);

        let error = NonRecursiveCircuitVerifyingKey::try_from_bytes(&bytes)
            .expect_err("trailing bytes must be rejected");

        assert!(
            matches!(
                error.downcast_ref::<CertificateCircuitError>(),
                Some(
                    CertificateCircuitError::VerificationKeyEncodingHasTrailingBytes {
                        trailing: 1
                    }
                )
            ),
            "expected a trailing-byte rejection, got: {error}"
        );
    }

    // Deriving Deserialize would otherwise reach the dependency's reader without the guard, and
    // that is the path the verifier data envelopes take.
    #[test]
    fn serde_rejects_a_recursive_verifying_key_in_the_certificate_position() {
        let encoded = serde_json::to_vec(&serde_bytes::ByteBuf::from(
            RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.to_vec(),
        ))
        .expect("the recursive key bytes should encode");

        let error = serde_json::from_slice::<NonRecursiveCircuitVerifyingKey>(&encoded)
            .expect_err("a recursive key must not deserialize as a certificate one");

        assert!(
            error.to_string().contains("architecture"),
            "expected an architecture mismatch, got: {error}"
        );
    }

    // The reader takes the commitment count from the bytes and reads that many, so a key can declare
    // fewer than its constraint system has fixed columns; verification then indexes by column.
    #[test]
    fn a_key_declaring_too_few_fixed_commitments_is_rejected() {
        let mut reader = NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
        ZkStdLibArch::read_from_serialized_vk(&mut reader).expect("architecture should read");
        let base = NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.len() - reader.len();
        // envelope degree, public input count, then the raw key's version and degree
        let count_index = base + 1 + 4 + 2;

        let mut bytes = NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.to_vec();
        let declared = u32::from_le_bytes(bytes[count_index..count_index + 4].try_into().unwrap());
        assert_eq!(
            declared as usize,
            NonRecursiveCircuitVerifyingKey::expected_fixed_commitment_count(u32::from(
                bytes[base]
            )),
            "the production key should declare the configured commitment count"
        );

        // Drop one commitment along with the count, so the encoding stays internally consistent and
        // fully consumed: only the cardinality guard can reject it.
        let commitment_length = byte_length::<
            <KZGCommitmentScheme<PairingEngine> as PolynomialCommitmentScheme<NativeField>>::Commitment,
        >(KEY_SERDE_FORMAT);
        let commitments_start = count_index + 4;
        bytes.drain(commitments_start..commitments_start + commitment_length);
        bytes[count_index..count_index + 4].copy_from_slice(&(declared - 1).to_le_bytes());

        let error = NonRecursiveCircuitVerifyingKey::try_from_bytes(&bytes)
            .expect_err("a short commitment count must be rejected");

        assert!(
            matches!(
                error.downcast_ref::<CertificateCircuitError>(),
                Some(CertificateCircuitError::VerificationKeyCommitmentCountMismatch {
                    actual,
                    ..
                }) if *actual as u32 == declared - 1
            ),
            "expected a commitment count mismatch, got: {error}"
        );
    }
}
