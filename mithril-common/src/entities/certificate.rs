use std::fmt::{Debug, Formatter};

use sha2::{Digest, Sha256};

use mithril_stm::AggregateSignatureType;

#[cfg(feature = "future_snark")]
use crate::crypto_helper::GenesisSchnorrSignature;
#[cfg(feature = "future_snark")]
use crate::crypto_helper::ProtocolAggregateVerificationKeyForSnark;
use crate::crypto_helper::{
    GenesisEd25519Signature, ProtocolAggregateVerificationKey,
    ProtocolAggregateVerificationKeyForConcatenation, ProtocolAncillaryProverData,
    ProtocolAncillaryVerifierData, ProtocolMultiSignature,
};
use crate::entities::{CertificateMetadata, Epoch, ProtocolMessage, SignedEntityType};

/// The signature of a [Certificate]
#[derive(Clone, Debug)]
pub enum CertificateSignature {
    /// Ed25519 genesis signature created from the original stake distribution
    /// aka GENESIS_SIG(AVK(-1))
    GenesisSignature(GenesisEd25519Signature),

    /// Dual genesis signature carrying both the legacy Ed25519 signature (covered by the
    /// certificate hash to preserve chain-walking compatibility) and the SNARK-friendly
    /// Schnorr signature (used for the in-circuit attestation under the Lagrange era).
    ///
    /// The Schnorr part is deliberately excluded from
    /// [CertificateSignature::to_bytes_hex_for_certificate_hash] so a Lagrange genesis cert
    /// hashes byte-identically to a legacy `GenesisSignature(ed)` cert with the same `ed`.
    #[cfg(feature = "future_snark")]
    GenesisDualSignature(GenesisEd25519Signature, GenesisSchnorrSignature),

    /// STM multi signature created from a quorum of single signatures from the signers
    /// aka (BEACON(p,n), MULTI_SIG(H(MSG(p,n) || AVK(n-1))))
    MultiSignature(SignedEntityType, ProtocolMultiSignature),
}

impl CertificateSignature {
    /// Return the aggregate signature type of the certificate signature.
    ///
    /// Returns `None` for genesis certificates as they do not carry a multi-signature.
    pub fn aggregate_signature_type(&self) -> Option<AggregateSignatureType> {
        match self {
            CertificateSignature::GenesisSignature(_) => None,
            #[cfg(feature = "future_snark")]
            CertificateSignature::GenesisDualSignature(_, _) => None,
            CertificateSignature::MultiSignature(_, multi_signature) => {
                Some((&multi_signature.key).into())
            }
        }
    }

    /// Return the bytes-hex of the signature payload that is included in
    /// [Certificate::try_compute_hash]. For the dual-genesis variant this is the Ed25519 bytes only,
    /// keeping the certificate hash byte-identical to today's so legacy clients can keep walking
    /// the chain backwards across the Lagrange boundary.
    pub fn to_bytes_hex_for_certificate_hash(&self) -> crate::StdResult<String> {
        match self {
            CertificateSignature::GenesisSignature(signature) => signature.to_bytes_hex(),
            #[cfg(feature = "future_snark")]
            CertificateSignature::GenesisDualSignature(ed_signature, _schnorr_signature) => {
                ed_signature.to_bytes_hex()
            }
            CertificateSignature::MultiSignature(_, signature) => signature.to_json_hex(),
        }
    }
}

/// Certificate represents a Mithril certificate embedding a Mithril STM multisignature
#[derive(Clone)]
pub struct Certificate {
    /// Hash of the current certificate
    /// Computed from the other fields of the certificate
    /// aka H(Cp,n))
    pub hash: String,

    /// Hash of the previous certificate in the chain
    /// This is either the hash of the first certificate of the epoch in the chain
    /// Or the first certificate of the previous epoch in the chain (if the certificate is the first of its epoch)
    /// aka H(FC(n))
    pub previous_hash: String,

    /// Cardano chain epoch number
    pub epoch: Epoch,

    /// Certificate metadata
    /// aka METADATA(p,n)
    pub metadata: CertificateMetadata,

    /// Structured message that is used to create the signed message
    /// aka MSG(p,n) U AVK(n-1)
    pub protocol_message: ProtocolMessage,

    /// Message that is signed by the signers
    /// aka H(MSG(p,n) || AVK(n-1))
    pub signed_message: String,

    /// Aggregate verification key for Concatenation
    /// The AVK used to sign for Concatenation during the current epoch
    /// aka AVK(n-2)
    pub aggregate_verification_key: ProtocolAggregateVerificationKeyForConcatenation,

    /// Aggregate verification key for SNARK
    /// The AVK used to sign for SNARK during the current epoch
    /// aka AVKS(n-2)
    #[cfg(feature = "future_snark")]
    pub aggregate_verification_key_snark: Option<ProtocolAggregateVerificationKeyForSnark>,

    /// Ancillary data used by the prover to produce the next certificate.
    pub ancillary_prover_data: Option<ProtocolAncillaryProverData>,

    /// Ancillary data used to verify the certificate.
    pub ancillary_verifier_data: Option<ProtocolAncillaryVerifierData>,

    /// Certificate signature
    pub signature: CertificateSignature,
}

impl Certificate {
    /// Builds a certificate and computes its hash, returning an error if hashing fails.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new<T: Into<String>>(
        previous_hash: T,
        epoch: Epoch,
        metadata: CertificateMetadata,
        protocol_message: ProtocolMessage,
        aggregate_verification_key: ProtocolAggregateVerificationKey,
        signature: CertificateSignature,
        ancillary_prover_data: Option<ProtocolAncillaryProverData>,
        ancillary_verifier_data: Option<ProtocolAncillaryVerifierData>,
    ) -> crate::StdResult<Certificate> {
        let signed_message = protocol_message.compute_hash();

        #[cfg(feature = "future_snark")]
        let aggregate_verification_key_snark = aggregate_verification_key
            .to_snark_aggregate_verification_key()
            .map(|avk| avk.to_owned().into());

        let mut certificate = Certificate {
            hash: "".to_string(),
            previous_hash: previous_hash.into(),
            epoch,
            metadata,
            protocol_message,
            signed_message,
            aggregate_verification_key: aggregate_verification_key
                .to_concatenation_aggregate_verification_key()
                .to_owned()
                .into(),
            #[cfg(feature = "future_snark")]
            aggregate_verification_key_snark,
            ancillary_prover_data,
            ancillary_verifier_data,
            signature,
        };
        certificate.hash = certificate.try_compute_hash()?;
        Ok(certificate)
    }

    /// Computes the hash of a Certificate, propagating any serialization failure.
    ///
    /// The signature is fed into the hash via
    /// [CertificateSignature::to_bytes_hex_for_certificate_hash], which deliberately excludes
    /// the Schnorr genesis bytes so the chain hash stays byte-identical for legacy clients.
    ///
    /// Design note (hash invariance between `GenesisSignature` and `GenesisDualSignature`): a
    /// dual-signature Lagrange genesis certificate hashes byte-identically to a legacy
    /// `GenesisSignature(ed)` certificate carrying the same Ed25519 signature. This is
    /// intentional, so legacy clients keep walking the chain across the Lagrange boundary.
    pub fn try_compute_hash(&self) -> crate::StdResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(self.previous_hash.as_bytes());
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.metadata.compute_hash().as_bytes());
        hasher.update(self.protocol_message.compute_hash().as_bytes());
        hasher.update(self.signed_message.as_bytes());
        hasher.update(self.aggregate_verification_key.to_json_hex()?.as_bytes());
        if let CertificateSignature::MultiSignature(signed_entity_type, _) = &self.signature {
            signed_entity_type.feed_hash(&mut hasher);
        }
        hasher.update(self.signature.to_bytes_hex_for_certificate_hash()?);
        if let Some(ancillary_prover_data) = &self.ancillary_prover_data {
            hasher.update(ancillary_prover_data.to_bytes()?);
        }
        if let Some(ancillary_verifier_data) = &self.ancillary_verifier_data {
            hasher.update(ancillary_verifier_data.to_bytes()?);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    /// Tell if the certificate is a genesis certificate (covers both the legacy and the
    /// dual-signature variants).
    pub fn is_genesis(&self) -> bool {
        match self.signature {
            CertificateSignature::GenesisSignature(_) => true,
            #[cfg(feature = "future_snark")]
            CertificateSignature::GenesisDualSignature(_, _) => true,
            CertificateSignature::MultiSignature(_, _) => false,
        }
    }

    /// Tell if a certificate created with the given aggregate signature type can be chained to
    /// this certificate.
    ///
    /// The recursion of a chain certifying signature verifies the genesis certificate with its
    /// Schnorr signature, which a legacy genesis certificate lacks, so only a dual genesis
    /// certificate can base such a chain.
    pub fn has_compatible_aggregate_signature(
        &self,
        aggregate_signature_type: AggregateSignatureType,
    ) -> bool {
        match &self.signature {
            CertificateSignature::GenesisSignature(_) => {
                !aggregate_signature_type.certifies_full_certificate_chain()
            }
            _ => aggregate_signature_type.can_chain_to(self.signature.aggregate_signature_type()),
        }
    }

    /// Return true if the certificate is chaining into itself (meaning that its hash and previous
    /// hash are equal).
    pub fn is_chaining_to_itself(&self) -> bool {
        self.hash == self.previous_hash
    }

    /// Check that the certificate signed message match the given protocol message.
    pub fn match_message(&self, message: &ProtocolMessage) -> bool {
        message.compute_hash() == self.signed_message
    }

    /// Get the certificate signed entity type.
    pub fn signed_entity_type(&self) -> SignedEntityType {
        match &self.signature {
            CertificateSignature::GenesisSignature(_) => SignedEntityType::genesis(self.epoch),
            #[cfg(feature = "future_snark")]
            CertificateSignature::GenesisDualSignature(_, _) => {
                SignedEntityType::genesis(self.epoch)
            }
            CertificateSignature::MultiSignature(entity_type, _) => entity_type.clone(),
        }
    }

    /// Create the aggregate verification key from the certificate.
    pub fn create_aggregate_verification_key(&self) -> ProtocolAggregateVerificationKey {
        let aggregate_verification_key_for_concatenation = &self.aggregate_verification_key;
        #[cfg(feature = "future_snark")]
        let snark_aggregate_verification_key = self
            .aggregate_verification_key_snark
            .as_ref()
            .map(|avk| avk.to_owned().into());
        ProtocolAggregateVerificationKey::new(
            aggregate_verification_key_for_concatenation.to_owned().into(),
            #[cfg(feature = "future_snark")]
            snark_aggregate_verification_key,
        )
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.epoch.eq(&other.epoch) && self.hash.eq(&other.hash)
    }
}

impl Debug for Certificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let should_be_exhaustive = f.alternate();
        let mut debug = f.debug_struct("Certificate");
        debug
            .field("hash", &self.hash)
            .field("previous_hash", &self.previous_hash)
            .field("epoch", &format_args!("{:?}", self.epoch))
            .field("metadata", &format_args!("{:?}", self.metadata))
            .field(
                "protocol_message",
                &format_args!("{:?}", self.protocol_message),
            )
            .field("signed_message", &self.signed_message);

        match should_be_exhaustive {
            true => {
                debug.field(
                    "aggregate_verification_key",
                    &format_args!("{:?}", self.aggregate_verification_key.to_json_hex()),
                );
                #[cfg(feature = "future_snark")]
                debug.field(
                    "aggregate_verification_key_snark",
                    &format_args!(
                        "{:?}",
                        self.aggregate_verification_key_snark
                            .as_ref()
                            .map(|avk| avk.to_bytes_hex())
                    ),
                );
                debug.field("ancillary_prover_data", &self.ancillary_prover_data);
                debug.field("ancillary_verifier_data", &self.ancillary_verifier_data);
                debug
                    .field("signature", &format_args!("{:?}", self.signature))
                    .finish()
            }
            false => debug.finish_non_exhaustive(),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    #[cfg(feature = "future_snark")]
    use rand_chacha::ChaCha20Rng;
    #[cfg(feature = "future_snark")]
    use rand_core::SeedableRng;

    #[cfg(feature = "future_snark")]
    use crate::crypto_helper::GenesisSchnorrSigner;
    use crate::entities::SignedEntityType::CardanoStakeDistribution;
    use crate::{
        entities::{
            ProtocolMessagePartKey, ProtocolParameters,
            certificate_metadata::StakeDistributionParty,
        },
        test::double::{fake_data, fake_keys},
    };

    use super::*;

    fn get_parties() -> Vec<StakeDistributionParty> {
        vec![
            StakeDistributionParty {
                party_id: "1".to_string(),
                stake: 10,
            },
            StakeDistributionParty {
                party_id: "2".to_string(),
                stake: 20,
            },
        ]
    }

    fn get_protocol_message() -> ProtocolMessage {
        let mut protocol_message = ProtocolMessage::new();
        protocol_message.set_message_part(
            ProtocolMessagePartKey::SnapshotDigest,
            "snapshot-digest-123".to_string(),
        );
        protocol_message.set_message_part(
            ProtocolMessagePartKey::NextAggregateVerificationKey,
            fake_keys::aggregate_verification_key_for_concatenation()[1].to_owned(),
        );

        protocol_message
    }

    #[test]
    fn test_certificate_compute_hash() {
        const HASH_EXPECTED: &str =
            "5e341ceeb91cc9957fca96d586e0ff2c66a8d6ec6b90bf84929c060c717094da";

        let initiated_at = DateTime::parse_from_rfc3339("2024-02-12T13:11:47.0123043Z")
            .unwrap()
            .with_timezone(&Utc);
        let sealed_at = initiated_at + Duration::try_seconds(100).unwrap();
        let signed_entity_type = SignedEntityType::MithrilStakeDistribution(Epoch(10));

        let certificate = Certificate::try_new(
            "previous_hash".to_string(),
            Epoch(10),
            CertificateMetadata::new(
                "testnet",
                "0.1.0",
                ProtocolParameters::new(1000, 100, 0.123),
                initiated_at,
                sealed_at,
                get_parties(),
            ),
            get_protocol_message(),
            ProtocolAggregateVerificationKey::new(
                ProtocolAggregateVerificationKeyForConcatenation::try_from(
                    fake_keys::aggregate_verification_key_for_concatenation()[0],
                )
                .unwrap()
                .into(),
                #[cfg(feature = "future_snark")]
                None,
            ),
            CertificateSignature::MultiSignature(
                signed_entity_type.clone(),
                fake_keys::multi_signature()[0].try_into().unwrap(),
            ),
            None,
            None,
        )
        .unwrap();

        assert_eq!(HASH_EXPECTED, certificate.try_compute_hash().unwrap());

        assert_ne!(
            HASH_EXPECTED,
            Certificate {
                previous_hash: "previous_hash-modified".to_string(),
                ..certificate.clone()
            }
            .try_compute_hash()
            .unwrap(),
        );

        assert_ne!(
            HASH_EXPECTED,
            Certificate {
                epoch: certificate.epoch + 10,
                ..certificate.clone()
            }
            .try_compute_hash()
            .unwrap(),
        );

        assert_ne!(
            HASH_EXPECTED,
            Certificate {
                metadata: CertificateMetadata {
                    protocol_version: "0.1.0-modified".to_string(),
                    ..certificate.metadata.clone()
                },
                ..certificate.clone()
            }
            .try_compute_hash()
            .unwrap(),
        );

        assert_ne!(
            HASH_EXPECTED,
            Certificate {
                protocol_message: {
                    let mut protocol_message_modified = certificate.protocol_message.clone();
                    protocol_message_modified.set_message_part(
                        ProtocolMessagePartKey::NextAggregateVerificationKey,
                        fake_keys::aggregate_verification_key_for_concatenation()[2].into(),
                    );

                    protocol_message_modified
                },
                ..certificate.clone()
            }
            .try_compute_hash()
            .unwrap(),
        );

        assert_ne!(
            HASH_EXPECTED,
            Certificate {
                aggregate_verification_key:
                    fake_keys::aggregate_verification_key_for_concatenation()[2]
                        .try_into()
                        .unwrap(),
                ..certificate.clone()
            }
            .try_compute_hash()
            .unwrap(),
        );

        assert_ne!(
            HASH_EXPECTED,
            Certificate {
                signature: CertificateSignature::MultiSignature(
                    CardanoStakeDistribution(Epoch(100)),
                    fake_keys::multi_signature()[0].try_into().unwrap()
                ),
                ..certificate.clone()
            }
            .try_compute_hash()
            .unwrap(),
        );

        assert_ne!(
            HASH_EXPECTED,
            Certificate {
                signature: CertificateSignature::MultiSignature(
                    signed_entity_type,
                    fake_keys::multi_signature()[1].try_into().unwrap()
                ),
                ..certificate.clone()
            }
            .try_compute_hash()
            .unwrap(),
        );
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn snark_aggregate_verification_key_does_not_affect_certificate_hash() {
        use crate::test::builder::MithrilFixtureBuilder;

        let fixture = MithrilFixtureBuilder::default().with_signers(3).build();
        let certificate = fixture.create_genesis_certificate("testnet", Epoch(1));
        let original_hash = certificate.try_compute_hash().unwrap();

        assert!(
            certificate.aggregate_verification_key_snark.is_some(),
            "Certificate should have a SNARK AVK when future_snark is enabled"
        );

        let mut certificate_without_snark_avk = certificate;
        certificate_without_snark_avk.aggregate_verification_key_snark = None;

        assert_eq!(
            original_hash,
            certificate_without_snark_avk.try_compute_hash().unwrap(),
            "SNARK AVK should not affect the certificate hash for backward compatibility"
        );
    }

    #[test]
    fn test_genesis_certificate_compute_hash() {
        const HASH_EXPECTED: &str =
            "6160fca853402c0ea89a0a9ceb5d97462ffd81c558c53feef01dcc0827f5bd19";

        let initiated_at = DateTime::parse_from_rfc3339("2024-02-12T13:11:47.0123043Z")
            .unwrap()
            .with_timezone(&Utc);
        let sealed_at = initiated_at + Duration::try_seconds(100).unwrap();

        let genesis_certificate = Certificate::try_new(
            "previous_hash",
            Epoch(10),
            CertificateMetadata::new(
                "testnet",
                "0.1.0".to_string(),
                ProtocolParameters::new(1000, 100, 0.123),
                initiated_at,
                sealed_at,
                get_parties(),
            ),
            get_protocol_message(),
            ProtocolAggregateVerificationKey::new(
                ProtocolAggregateVerificationKeyForConcatenation::try_from(
                    fake_keys::aggregate_verification_key_for_concatenation()[1],
                )
                .unwrap()
                .into(),
                #[cfg(feature = "future_snark")]
                None,
            ),
            CertificateSignature::GenesisSignature(
                fake_keys::genesis_signature()[0].try_into().unwrap(),
            ),
            None,
            None,
        )
        .unwrap();

        assert_eq!(
            HASH_EXPECTED,
            genesis_certificate.try_compute_hash().unwrap()
        );

        assert_ne!(
            HASH_EXPECTED,
            Certificate {
                signature: CertificateSignature::GenesisSignature(
                    fake_keys::genesis_signature()[1].try_into().unwrap()
                ),
                ..genesis_certificate.clone()
            }
            .try_compute_hash()
            .unwrap(),
        );
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn dual_signature_does_not_change_the_certificate_hash() {
        let initiated_at = DateTime::parse_from_rfc3339("2024-02-12T13:11:47.0123043Z")
            .unwrap()
            .with_timezone(&Utc);
        let sealed_at = initiated_at + Duration::try_seconds(100).unwrap();
        let ed_signature: GenesisEd25519Signature =
            fake_keys::genesis_signature()[0].try_into().unwrap();

        let legacy = Certificate::try_new(
            "previous_hash",
            Epoch(10),
            CertificateMetadata::new(
                "testnet",
                "0.1.0".to_string(),
                ProtocolParameters::new(1000, 100, 0.123),
                initiated_at,
                sealed_at,
                get_parties(),
            ),
            get_protocol_message(),
            ProtocolAggregateVerificationKey::new(
                ProtocolAggregateVerificationKeyForConcatenation::try_from(
                    fake_keys::aggregate_verification_key_for_concatenation()[1],
                )
                .unwrap()
                .into(),
                None,
            ),
            CertificateSignature::GenesisSignature(ed_signature),
            None,
            None,
        )
        .unwrap();

        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let schnorr_signer = GenesisSchnorrSigner::generate(&mut rng);
        let schnorr_signature = schnorr_signer.sign(&[0u8; 32], &mut rng).unwrap();

        let dual = Certificate::try_new(
            "previous_hash",
            Epoch(10),
            CertificateMetadata::new(
                "testnet",
                "0.1.0".to_string(),
                ProtocolParameters::new(1000, 100, 0.123),
                initiated_at,
                sealed_at,
                get_parties(),
            ),
            get_protocol_message(),
            ProtocolAggregateVerificationKey::new(
                ProtocolAggregateVerificationKeyForConcatenation::try_from(
                    fake_keys::aggregate_verification_key_for_concatenation()[1],
                )
                .unwrap()
                .into(),
                None,
            ),
            CertificateSignature::GenesisDualSignature(ed_signature, schnorr_signature),
            None,
            None,
        )
        .unwrap();

        assert_eq!(
            legacy.try_compute_hash().unwrap(),
            dual.try_compute_hash().unwrap(),
            "dual-signature variant must hash identically to the legacy single-Ed25519 variant"
        );
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn certificate_hash_is_independent_of_schnorr_signature_bytes() {
        let initiated_at = DateTime::parse_from_rfc3339("2024-02-12T13:11:47.0123043Z")
            .unwrap()
            .with_timezone(&Utc);
        let sealed_at = initiated_at + Duration::try_seconds(100).unwrap();
        let ed_signature: GenesisEd25519Signature =
            fake_keys::genesis_signature()[0].try_into().unwrap();

        let metadata = CertificateMetadata::new(
            "testnet",
            "0.1.0".to_string(),
            ProtocolParameters::new(1000, 100, 0.123),
            initiated_at,
            sealed_at,
            get_parties(),
        );

        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let schnorr_signer = GenesisSchnorrSigner::generate(&mut rng);
        let mut hashes = std::collections::HashSet::new();
        for seed in 0u8..6 {
            let digest = [seed; 32];
            let schnorr_signature = schnorr_signer.sign(&digest, &mut rng).unwrap();
            let certificate = Certificate::try_new(
                "previous_hash",
                Epoch(10),
                metadata.clone(),
                get_protocol_message(),
                ProtocolAggregateVerificationKey::new(
                    ProtocolAggregateVerificationKeyForConcatenation::try_from(
                        fake_keys::aggregate_verification_key_for_concatenation()[1],
                    )
                    .unwrap()
                    .into(),
                    None,
                ),
                CertificateSignature::GenesisDualSignature(ed_signature, schnorr_signature),
                None,
                None,
            )
            .unwrap();
            hashes.insert(certificate.try_compute_hash().unwrap());
        }
        assert_eq!(
            hashes.len(),
            1,
            "the certificate hash must be invariant when varying only the Schnorr signature",
        );
    }

    #[cfg(feature = "future_snark")]
    fn build_genesis_certificate_for_test(signature: CertificateSignature) -> Certificate {
        let initiated_at = DateTime::parse_from_rfc3339("2024-02-12T13:11:47.0123043Z")
            .unwrap()
            .with_timezone(&Utc);
        let sealed_at = initiated_at + Duration::try_seconds(100).unwrap();
        Certificate::try_new(
            "previous_hash",
            Epoch(10),
            CertificateMetadata::new(
                "testnet",
                "0.1.0".to_string(),
                ProtocolParameters::new(1000, 100, 0.123),
                initiated_at,
                sealed_at,
                get_parties(),
            ),
            get_protocol_message(),
            ProtocolAggregateVerificationKey::new(
                ProtocolAggregateVerificationKeyForConcatenation::try_from(
                    fake_keys::aggregate_verification_key_for_concatenation()[1],
                )
                .unwrap()
                .into(),
                None,
            ),
            signature,
            None,
            None,
        )
        .unwrap()
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn is_genesis_returns_true_for_both_genesis_variants() {
        let ed_signature: GenesisEd25519Signature =
            fake_keys::genesis_signature()[0].try_into().unwrap();
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
        let schnorr_signer = GenesisSchnorrSigner::generate(&mut rng);
        let schnorr_signature = schnorr_signer.sign(&[0u8; 32], &mut rng).unwrap();

        let multi = build_genesis_certificate_for_test(CertificateSignature::MultiSignature(
            CardanoStakeDistribution(Epoch(10)),
            fake_keys::multi_signature()[0].try_into().unwrap(),
        ));
        let legacy = build_genesis_certificate_for_test(CertificateSignature::GenesisSignature(
            ed_signature,
        ));
        let dual = build_genesis_certificate_for_test(CertificateSignature::GenesisDualSignature(
            ed_signature,
            schnorr_signature,
        ));

        assert!(legacy.is_genesis());
        assert!(dual.is_genesis());
        assert!(!multi.is_genesis());

        assert_eq!(
            legacy.signed_entity_type(),
            SignedEntityType::genesis(legacy.epoch)
        );
        assert_eq!(
            dual.signed_entity_type(),
            SignedEntityType::genesis(dual.epoch)
        );
        assert_ne!(
            multi.signed_entity_type(),
            SignedEntityType::genesis(multi.epoch)
        );
    }

    mod has_compatible_aggregate_signature {
        use super::*;

        #[test]
        fn any_certificate_is_compatible_with_concatenation() {
            let genesis = fake_data::genesis_certificate("genesis");
            let certificate = fake_data::certificate("certificate");

            assert!(
                genesis.has_compatible_aggregate_signature(AggregateSignatureType::Concatenation)
            );
            assert!(
                certificate
                    .has_compatible_aggregate_signature(AggregateSignatureType::Concatenation)
            );
        }

        #[cfg(feature = "future_snark")]
        #[test]
        fn only_a_dual_genesis_certificate_is_compatible_with_ivc_snark() {
            let ed_signature: GenesisEd25519Signature =
                fake_keys::genesis_signature()[0].try_into().unwrap();
            let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
            let schnorr_signer = GenesisSchnorrSigner::generate(&mut rng);
            let schnorr_signature = schnorr_signer.sign(&[0u8; 32], &mut rng).unwrap();
            let legacy_genesis = fake_data::genesis_certificate("genesis");
            let dual_genesis = build_genesis_certificate_for_test(
                CertificateSignature::GenesisDualSignature(ed_signature, schnorr_signature),
            );
            let concatenation_certificate = fake_data::certificate("certificate");

            assert!(
                !legacy_genesis
                    .has_compatible_aggregate_signature(AggregateSignatureType::IvcSnark)
            );
            assert!(
                dual_genesis.has_compatible_aggregate_signature(AggregateSignatureType::IvcSnark)
            );
            assert!(
                !concatenation_certificate
                    .has_compatible_aggregate_signature(AggregateSignatureType::IvcSnark)
            );
        }
    }
}
