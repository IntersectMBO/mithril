// Per-circuit key newtypes for the recursive (IVC) circuit, and the circuit's implementation of
// [`KeyGenerator`]. The newtypes wrap Midnight's self-describing `MidnightVK` / `MidnightPK`, the
// same format the certificate circuit's keys use; the raw verifying key stays reachable for the
// accumulator and verifier code that needs it.
use std::io::Read;

use anyhow::{Context, anyhow};
use midnight_curves::Bls12;
use midnight_proofs::poly::commitment::Params;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_zk_stdlib::{self as zk, MidnightPK, MidnightVK};
use serde::{Deserialize, Serialize};

use crate::StmResult;
use crate::circuits::halo2::circuit::CertificateCircuit;
use crate::circuits::halo2::keys::NonRecursiveCircuitVerifyingKey;
use crate::circuits::key_generator::KeyGenerator;
use crate::circuits::key_provider::KeyProvider;
use crate::circuits::key_serialization::KEY_SERDE_FORMAT;
use crate::circuits::trusted_setup::MIDNIGHT_SRS_DEGREE;
use crate::codec::{TryFromBytes, TryToBytes};

use super::{
    ConstraintSystem, KZGCommitmentScheme, NativeField, PairingEngine, RECURSIVE_CIRCUIT_DEGREE,
    VerifyingKey, ZkStdLib, ZkStdLibArch,
    circuit::{IvcCircuit, recursive_circuit_architecture},
    errors::IvcCircuitError,
};

/// Verifying key of the recursive (IVC) circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RecursiveCircuitVerifyingKey(
    #[serde(with = "recursive_verifying_key_serde")] MidnightVK,
);

/// Proving key of the recursive (IVC) circuit.
#[derive(Clone)]
pub(crate) struct RecursiveCircuitProvingKey(MidnightPK<IvcCircuit>);

impl RecursiveCircuitVerifyingKey {
    /// Wraps a Midnight verifying key.
    pub(crate) fn new(midnight_vk: MidnightVK) -> Self {
        Self(midnight_vk)
    }

    /// Borrows the wrapped Midnight verifying key.
    pub(crate) fn midnight_vk(&self) -> &MidnightVK {
        &self.0
    }

    /// Borrows the raw verifying key, for the prover/verifier and fixed-base construction.
    pub(crate) fn verifying_key(
        &self,
    ) -> &VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>> {
        self.0.vk()
    }

    #[cfg(test)]
    /// Returns the circuit degree using the domain of the underlying `VerifyingKey`
    pub(crate) fn circuit_degree(&self) -> u32 {
        self.as_ref().get_domain().k()
    }

    /// Rejects a declared degree that is not the recursive circuit's.
    ///
    /// Both readers derive a range bit length from their degree as `k - 1` on a byte, which
    /// underflows for a zero degree, and a large degree reaches a domain constructor that asserts.
    /// So every declared degree is checked before the bytes reach the dependency.
    fn validate_declared_degree(degree: u8) -> StmResult<()> {
        if u32::from(degree) != RECURSIVE_CIRCUIT_DEGREE {
            return Err(anyhow!(IvcCircuitError::IvcVerificationKeyDegreeMismatch {
                expected: RECURSIVE_CIRCUIT_DEGREE,
                actual: u32::from(degree),
            }));
        }
        Ok(())
    }

    /// Number of fixed commitments the approved architecture produces.
    ///
    /// The reader takes this count from the bytes and reads that many commitments, so a key can
    /// declare fewer than the configured constraint system has columns; later verification indexes
    /// commitments by those columns.
    fn expected_fixed_commitment_count() -> usize {
        let mut constraint_system = ConstraintSystem::<NativeField>::default();
        ZkStdLib::configure(
            &mut constraint_system,
            (
                recursive_circuit_architecture(),
                (RECURSIVE_CIRCUIT_DEGREE - 1) as u8,
            ),
        );
        // Selectors become fixed columns when the key is read.
        constraint_system.num_fixed_columns() + constraint_system.num_selectors()
    }

    /// Checks every degree an encoded recursive proving key declares, before it is decoded.
    ///
    /// The reader takes four in turn without validating any: its own, the two the relation's
    /// certificate key declares, and the one inside the wrapped raw recursive key. Each reaches a
    /// `k - 1` subtraction on a byte or a domain constructor that asserts, so all four are checked
    /// here.
    fn validate_encoded_proving_key_header(bytes: &[u8]) -> StmResult<()> {
        let mut reader = bytes;

        let mut proving_key_degree = [0u8; 1];
        reader
            .read_exact(&mut proving_key_degree)
            .with_context(|| "Failed to read the recursive proving key degree")?;
        Self::validate_declared_degree(proving_key_degree[0])?;

        // The relation carries the certificate key it was generated against, length prefixed.
        let mut certificate_key_length = [0u8; 4];
        reader
            .read_exact(&mut certificate_key_length)
            .with_context(|| "Failed to read the relation's certificate key length")?;
        let certificate_key_length = u32::from_le_bytes(certificate_key_length) as usize;
        let certificate_key = reader
            .get(..certificate_key_length)
            .ok_or_else(|| anyhow!("The relation's certificate key is truncated"))?;
        validate_certificate_key_declared_degrees(certificate_key)?;
        reader = &reader[certificate_key_length..];

        // The wrapped raw recursive key opens with its own version and degree.
        let mut raw_header = [0u8; 2];
        reader
            .read_exact(&mut raw_header)
            .with_context(|| "Failed to read the wrapped raw proving key header")?;
        Self::validate_declared_degree(raw_header[1])
    }

    /// Checks the header of an encoded recursive verifying key before it is decoded.
    ///
    /// `MidnightVK` takes its architecture and degree from the bytes, so without this any Midnight
    /// circuit's key would decode in the recursive position. Both degrees are checked: the envelope
    /// declares one and the raw key it wraps declares another, and the reader takes them
    /// independently without comparing them, so an envelope claiming the expected degree can carry
    /// a raw key of a different one.
    fn validate_encoded_header(bytes: &[u8]) -> StmResult<()> {
        let mut reader = bytes;
        let architecture = ZkStdLibArch::read_from_serialized_vk(&mut reader)
            .with_context(|| "Failed to read the recursive verifying key architecture")?;
        if architecture != recursive_circuit_architecture() {
            return Err(anyhow!(
                IvcCircuitError::RecursiveVerificationKeyArchitectureMismatch
            ));
        }

        let mut envelope_degree = [0u8; 1];
        reader
            .read_exact(&mut envelope_degree)
            .with_context(|| "Failed to read the recursive verifying key degree")?;
        Self::validate_declared_degree(envelope_degree[0])?;

        let mut public_input_count = [0u8; 4];
        reader
            .read_exact(&mut public_input_count)
            .with_context(|| "Failed to read the recursive verifying key public input count")?;

        // The wrapped raw key opens with its own version and degree.
        let mut raw_header = [0u8; 2];
        reader
            .read_exact(&mut raw_header)
            .with_context(|| "Failed to read the wrapped raw verifying key header")?;
        Self::validate_declared_degree(raw_header[1])
    }
}

impl AsRef<VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>>>
    for RecursiveCircuitVerifyingKey
{
    fn as_ref(&self) -> &VerifyingKey<NativeField, KZGCommitmentScheme<PairingEngine>> {
        self.0.vk()
    }
}

impl RecursiveCircuitProvingKey {
    /// Wraps a Midnight proving key.
    pub(crate) fn new(midnight_pk: MidnightPK<IvcCircuit>) -> Self {
        Self(midnight_pk)
    }

    /// Borrows the wrapped Midnight proving key, for proof generation.
    pub(crate) fn midnight_pk(&self) -> &MidnightPK<IvcCircuit> {
        &self.0
    }
}

/// Serde for the wrapped Midnight verifying key, routed through the newtype's guarded byte decoder
/// so the verifier-data envelopes cannot reach the dependency's readers unchecked.
mod recursive_verifying_key_serde {
    use midnight_zk_stdlib::MidnightVK;
    use serde::{Deserializer, Serializer};

    use super::RecursiveCircuitVerifyingKey;
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
        RecursiveCircuitVerifyingKey::try_from_bytes(&bytes)
            .map(|key| key.0)
            .map_err(serde::de::Error::custom)
    }
}

impl TryToBytes for RecursiveCircuitVerifyingKey {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        self.0.to_bytes_vec()
    }
}

impl TryFromBytes for RecursiveCircuitVerifyingKey {
    fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
        Self::validate_encoded_header(bytes)?;

        let mut reader = bytes;
        let midnight_vk = MidnightVK::read(&mut reader, KEY_SERDE_FORMAT)
            .with_context(|| "Failed to deserialize the recursive verifying key")?;
        // A standalone encoding holds one key and nothing else; the streaming asset reader, where a
        // fixed-base map follows the key, deliberately does not go through here.
        if !reader.is_empty() {
            return Err(anyhow!(
                IvcCircuitError::RecursiveKeyEncodingHasTrailingBytes {
                    trailing: reader.len(),
                }
            ));
        }

        let actual = midnight_vk.vk().fixed_commitments().len();
        let expected = Self::expected_fixed_commitment_count();
        if actual != expected {
            return Err(anyhow!(
                IvcCircuitError::RecursiveVerificationKeyCommitmentCountMismatch {
                    expected,
                    actual
                }
            ));
        }

        Ok(Self(midnight_vk))
    }
}

impl TryToBytes for RecursiveCircuitProvingKey {
    fn to_bytes_vec(&self) -> StmResult<Vec<u8>> {
        let mut bytes = Vec::new();
        self.0
            .write(&mut bytes, KEY_SERDE_FORMAT)
            .with_context(|| "Failed to serialize the recursive proving key")?;
        Ok(bytes)
    }
}

impl TryFromBytes for RecursiveCircuitProvingKey {
    fn try_from_bytes(bytes: &[u8]) -> StmResult<Self> {
        RecursiveCircuitVerifyingKey::validate_encoded_proving_key_header(bytes)?;

        let mut reader = bytes;
        Ok(Self(
            MidnightPK::<IvcCircuit>::read(&mut reader, KEY_SERDE_FORMAT)
                .with_context(|| "Failed to deserialize the recursive proving key")?,
        ))
    }
}

/// Rejects a certificate key whose declared degrees could not belong to any supported certificate
/// circuit.
///
/// A certificate key is generated from the trusted setup, so it cannot exceed that setup's degree.
///
/// Certificate degrees legitimately vary — production, the full fixture and the small golden context
/// all differ — so these are bounded rather than pinned. The key declares a degree twice, once in
/// its Midnight envelope and once in the raw key it wraps, and the reader takes them independently:
/// an envelope declaring a supported degree can wrap a raw key declaring any other, which reaches a
/// domain constructor that asserts.
fn validate_certificate_key_declared_degrees(certificate_key: &[u8]) -> StmResult<()> {
    let mut reader = certificate_key;
    ZkStdLibArch::read_from_serialized_vk(&mut reader)
        .with_context(|| "Failed to read the certificate key architecture")?;

    let mut envelope_degree = [0u8; 1];
    reader
        .read_exact(&mut envelope_degree)
        .with_context(|| "Failed to read the certificate key envelope degree")?;

    let mut public_input_count = [0u8; 4];
    reader
        .read_exact(&mut public_input_count)
        .with_context(|| "Failed to read the certificate key public input count")?;

    // The wrapped raw key opens with its own version and degree.
    let mut raw_header = [0u8; 2];
    reader
        .read_exact(&mut raw_header)
        .with_context(|| "Failed to read the wrapped raw certificate key header")?;

    for degree in [envelope_degree[0], raw_header[1]] {
        if degree == 0 || degree > MIDNIGHT_SRS_DEGREE {
            return Err(anyhow!(IvcCircuitError::IvcVerificationKeyDegreeMismatch {
                expected: u32::from(MIDNIGHT_SRS_DEGREE),
                actual: u32::from(degree),
            }));
        }
    }
    if envelope_degree[0] != raw_header[1] {
        return Err(anyhow!(IvcCircuitError::IvcVerificationKeyDegreeMismatch {
            expected: u32::from(envelope_degree[0]),
            actual: u32::from(raw_header[1]),
        }));
    }
    Ok(())
}

impl KeyGenerator for IvcCircuit {
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
        // `setup_vk` takes the degree from the SRS, so it must be exactly the circuit's.
        let verifying_key = if srs.max_k() == RECURSIVE_CIRCUIT_DEGREE {
            zk::setup_vk(srs, self)
        } else {
            let mut recursive_srs = srs.clone();
            recursive_srs.downsize(RECURSIVE_CIRCUIT_DEGREE);
            zk::setup_vk(&recursive_srs, self)
        };
        let proving_key = zk::setup_pk(self, &verifying_key);
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
        IvcCircuit::for_key_generation(&certificate_verifying_key).generate_key_pair(srs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::halo2::NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
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

    // Both circuits now encode their keys the same way, so only the declared architecture separates
    // them: without the header check the certificate's key would decode in the recursive position.
    #[test]
    fn a_certificate_verifying_key_is_rejected_in_the_recursive_position() {
        let error = RecursiveCircuitVerifyingKey::try_from_bytes(
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION,
        )
        .expect_err("a certificate key must not decode as a recursive one");

        assert!(
            matches!(
                error.downcast_ref::<IvcCircuitError>(),
                Some(IvcCircuitError::RecursiveVerificationKeyArchitectureMismatch)
            ),
            "expected an architecture mismatch, got: {error}"
        );
    }

    // `MidnightVK::read` derives its range bit length as `k - 1` on a byte, so a zero degree would
    // underflow inside the dependency before any check of ours could run.
    #[test]
    fn a_zero_degree_header_is_rejected_before_it_can_underflow() {
        let mut bytes = RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.to_vec();
        // The degree byte follows the encoded architecture.
        let mut reader = RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
        ZkStdLibArch::read_from_serialized_vk(&mut reader).expect("architecture should read");
        let degree_index = bytes.len() - reader.len();
        bytes[degree_index] = 0;

        let error = RecursiveCircuitVerifyingKey::try_from_bytes(&bytes)
            .expect_err("a zero degree must be rejected");

        assert!(
            matches!(
                error.downcast_ref::<IvcCircuitError>(),
                Some(IvcCircuitError::IvcVerificationKeyDegreeMismatch { actual: 0, .. })
            ),
            "expected a degree mismatch, got: {error}"
        );
    }

    // The envelope and the raw key it wraps each declare a degree, and the reader takes them
    // independently, so an envelope claiming the right one can still carry a raw key of another.
    #[test]
    fn a_wrapped_raw_key_of_the_wrong_degree_is_rejected() {
        let mut bytes = RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.to_vec();
        // Past the architecture, the envelope degree and the public input count lies the raw
        // key's own version byte, and its degree follows.
        let mut reader = RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
        ZkStdLibArch::read_from_serialized_vk(&mut reader).expect("architecture should read");
        let raw_degree_index = bytes.len() - reader.len() + 1 + 4 + 1;
        assert_eq!(
            u32::from(bytes[raw_degree_index]),
            RECURSIVE_CIRCUIT_DEGREE,
            "the wrapped raw key should declare the recursive degree before it is mutated"
        );
        bytes[raw_degree_index] = 20;

        let error = RecursiveCircuitVerifyingKey::try_from_bytes(&bytes)
            .expect_err("a wrapped key of another degree must be rejected");

        assert!(
            matches!(
                error.downcast_ref::<IvcCircuitError>(),
                Some(IvcCircuitError::IvcVerificationKeyDegreeMismatch { actual: 20, .. })
            ),
            "expected a degree mismatch, got: {error}"
        );
    }

    // Deriving Deserialize would otherwise reach the dependency's reader without the guard, and
    // that is the path the verifier data envelopes take.
    #[test]
    fn serde_rejects_a_certificate_verifying_key_in_the_recursive_position() {
        let encoded = serde_json::to_vec(&serde_bytes::ByteBuf::from(
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.to_vec(),
        ))
        .expect("the certificate key bytes should encode");

        let error = serde_json::from_slice::<RecursiveCircuitVerifyingKey>(&encoded)
            .expect_err("a certificate key must not deserialize as a recursive one");

        assert!(
            error.to_string().contains("architecture"),
            "expected an architecture mismatch, got: {error}"
        );
    }

    // The proving key opens with its own degree, taken into the same `k - 1` arithmetic.
    #[test]
    fn a_proving_key_of_the_wrong_degree_is_rejected() {
        let error = match RecursiveCircuitProvingKey::try_from_bytes(&[0u8; 8]) {
            Ok(_) => panic!("a zero degree proving key must be rejected"),
            Err(error) => error,
        };

        assert!(
            matches!(
                error.downcast_ref::<IvcCircuitError>(),
                Some(IvcCircuitError::IvcVerificationKeyDegreeMismatch { actual: 0, .. })
            ),
            "expected a degree mismatch, got: {error}"
        );
    }

    // A standalone encoding holds one key and nothing else, so anything appended is a decoder
    // disagreement rather than harmless padding.
    #[test]
    fn a_standalone_encoding_with_trailing_bytes_is_rejected() {
        let mut bytes = RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.to_vec();
        bytes.extend_from_slice(&[0u8; 4]);

        let error = RecursiveCircuitVerifyingKey::try_from_bytes(&bytes)
            .expect_err("trailing bytes must be rejected");

        assert!(
            matches!(
                error.downcast_ref::<IvcCircuitError>(),
                Some(IvcCircuitError::RecursiveKeyEncodingHasTrailingBytes { trailing: 4 })
            ),
            "expected trailing bytes, got: {error}"
        );
    }

    // The reader takes the commitment count from the bytes and reads that many, so a key can
    // declare fewer than the configured constraint system has columns.
    #[test]
    fn a_key_declaring_too_few_fixed_commitments_is_rejected() {
        use midnight_proofs::utils::helpers::byte_length;

        let mut reader = RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
        ZkStdLibArch::read_from_serialized_vk(&mut reader).expect("architecture should read");
        // envelope degree, public input count, then the raw key's version and degree
        let count_index =
            RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.len() - reader.len() + 1 + 4 + 2;

        let mut bytes = RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.to_vec();
        let declared = u32::from_le_bytes(bytes[count_index..count_index + 4].try_into().unwrap());
        assert_eq!(
            declared as usize,
            RecursiveCircuitVerifyingKey::expected_fixed_commitment_count(),
            "the production key should declare the configured commitment count"
        );

        // Drop one commitment along with the count, so the encoding stays internally consistent and
        // fully consumed: only the cardinality guard can reject it.
        let commitment_length = byte_length::<
            <KZGCommitmentScheme<PairingEngine> as midnight_proofs::poly::commitment::PolynomialCommitmentScheme<NativeField>>::Commitment,
        >(KEY_SERDE_FORMAT);
        let commitments_start = count_index + 4;
        bytes.drain(commitments_start..commitments_start + commitment_length);
        bytes[count_index..count_index + 4].copy_from_slice(&(declared - 1).to_le_bytes());

        let error = RecursiveCircuitVerifyingKey::try_from_bytes(&bytes)
            .expect_err("a short commitment count must be rejected");

        assert!(
            matches!(
                error.downcast_ref::<IvcCircuitError>(),
                Some(IvcCircuitError::RecursiveVerificationKeyCommitmentCountMismatch {
                    actual,
                    ..
                }) if *actual as u32 == declared - 1
            ),
            "expected a commitment count mismatch, got: {error}"
        );
    }

    // The relation's certificate key declares a degree twice and the reader takes them
    // independently, so a supported envelope can wrap a raw key of any other degree.
    #[test]
    fn a_proving_key_whose_certificate_inner_degree_disagrees_is_rejected() {
        use crate::circuits::halo2::NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;

        let mut certificate_key = NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.to_vec();
        let mut reader = NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION;
        ZkStdLibArch::read_from_serialized_vk(&mut reader).expect("architecture should read");
        let raw_degree_index =
            NON_RECURSIVE_CIRCUIT_VERIFICATION_KEY_FOR_PRODUCTION.len() - reader.len() + 1 + 4 + 1;
        certificate_key[raw_degree_index] = 32;

        // A proving key encoding: its degree, then the length prefixed relation.
        let mut bytes = vec![RECURSIVE_CIRCUIT_DEGREE as u8];
        bytes.extend_from_slice(&(certificate_key.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&certificate_key);
        bytes.extend_from_slice(&[0u8; 8]);

        let error = match RecursiveCircuitProvingKey::try_from_bytes(&bytes) {
            Ok(_) => panic!("a disagreeing certificate degree must be rejected"),
            Err(error) => error,
        };

        assert!(
            matches!(
                error.downcast_ref::<IvcCircuitError>(),
                Some(IvcCircuitError::IvcVerificationKeyDegreeMismatch { actual: 32, .. })
            ),
            "expected a degree mismatch, got: {error}"
        );
    }
}
