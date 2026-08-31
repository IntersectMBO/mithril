//! Genesis-signed registry of the circuit verification keys trusted for SNARK certificates.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use thiserror::Error;

use mithril_stm::CircuitVerificationKeyDigest;

use crate::StdResult;
use crate::crypto_helper::{GenesisEd25519Signature, GenesisSigner, GenesisVerifier};
use crate::entities::Epoch;

/// Errors raised when checking circuit verification key digests against a
/// [CircuitVerificationKeyRegistry].
#[derive(Error, Debug, PartialEq, Eq)]
pub enum CircuitVerificationKeyRegistryError {
    /// The digest is covered by a revoked entry for the checked epoch.
    #[error("circuit verification key '{digest}' is revoked for epoch {epoch}")]
    Revoked {
        /// Digest of the revoked circuit verification key.
        digest: CircuitVerificationKeyDigest,
        /// Epoch for which the check was performed.
        epoch: Epoch,
    },

    /// The digest is not covered by any allowed entry for the checked epoch.
    #[error("circuit verification key '{digest}' is not whitelisted for epoch {epoch}")]
    NotWhitelisted {
        /// Digest of the unknown or out-of-range circuit verification key.
        digest: CircuitVerificationKeyDigest,
        /// Epoch for which the check was performed.
        epoch: Epoch,
    },
}

/// Status of a circuit verification key entry over its epoch range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CircuitVerificationKeyStatus {
    /// The key may certify certificates whose epoch falls in the entry's range.
    Allowed,

    /// Certificates produced with this key in the entry's range must be rejected.
    Revoked,
}

/// One statement about a circuit verification key, valid over an inclusive epoch range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitVerificationKeyEntry {
    /// Digest of the circuit verification key the statement is about.
    pub digest: CircuitVerificationKeyDigest,

    /// Human readable label of the circuit, e.g. "certificate-circuit v2".
    pub name: String,

    /// Whether the key is allowed or revoked over the entry's range.
    pub status: CircuitVerificationKeyStatus,

    /// First epoch (inclusive) covered by the statement.
    pub start_epoch: Epoch,

    /// Last epoch (inclusive) covered by the statement, open-ended when absent.
    pub end_epoch: Option<Epoch>,

    /// Audit trail, e.g. the reason of a revocation.
    pub comment: Option<String>,
}

impl CircuitVerificationKeyEntry {
    /// Whether the entry's epoch range contains the given epoch.
    pub fn covers(&self, epoch: Epoch) -> bool {
        self.start_epoch <= epoch && self.end_epoch.is_none_or(|end_epoch| epoch <= end_epoch)
    }
}

/// Registry of the circuit verification keys trusted for SNARK certificates.
///
/// The registry is scoped by the genesis key that signs it: each network publishes its own
/// registry, signed with its own genesis key. A digest absent from the registry is rejected
/// (whitelist semantics); a revoked entry rejects the epochs it covers even when an allowed
/// entry also covers them (revocation wins).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitVerificationKeyRegistry {
    /// Monotonically increasing registry version, used for rollback protection.
    pub version: u64,

    /// Statements about the circuit verification keys.
    pub entries: Vec<CircuitVerificationKeyEntry>,
}

impl CircuitVerificationKeyRegistry {
    /// Check that every digest is whitelisted and not revoked for the given epoch.
    ///
    /// A digest fails with [Revoked](CircuitVerificationKeyRegistryError::Revoked) when any
    /// revoked entry covers the epoch, and with
    /// [NotWhitelisted](CircuitVerificationKeyRegistryError::NotWhitelisted) when no allowed
    /// entry covers it.
    pub fn check(
        &self,
        digests: &[CircuitVerificationKeyDigest],
        epoch: Epoch,
    ) -> Result<(), CircuitVerificationKeyRegistryError> {
        digests.iter().try_for_each(|digest| {
            let is_revoked = self.has_covering_entry_with_status(
                digest,
                epoch,
                CircuitVerificationKeyStatus::Revoked,
            );
            let is_allowed = self.has_covering_entry_with_status(
                digest,
                epoch,
                CircuitVerificationKeyStatus::Allowed,
            );

            match (is_revoked, is_allowed) {
                (true, _) => Err(CircuitVerificationKeyRegistryError::Revoked {
                    digest: *digest,
                    epoch,
                }),
                (false, false) => Err(CircuitVerificationKeyRegistryError::NotWhitelisted {
                    digest: *digest,
                    epoch,
                }),
                (false, true) => Ok(()),
            }
        })
    }

    /// Whether an entry with the given status covers the digest for the epoch.
    fn has_covering_entry_with_status(
        &self,
        digest: &CircuitVerificationKeyDigest,
        epoch: Epoch,
        status: CircuitVerificationKeyStatus,
    ) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.digest == *digest && entry.covers(epoch) && entry.status == status)
    }
}

/// Domain separation prefix of the registry genesis signature, so registry signatures can never
/// be confused with any other artifact signed by the genesis key.
pub const REGISTRY_SIGNATURE_DOMAIN_SEPARATOR: &[u8] =
    b"MITHRIL_CIRCUIT_VERIFICATION_KEY_REGISTRY_V1";

/// A [CircuitVerificationKeyRegistry] together with its Ed25519 genesis signature.
///
/// The registry travels as its exact JSON bytes and the signature covers those bytes (prefixed
/// by [REGISTRY_SIGNATURE_DOMAIN_SEPARATOR]), never a re-serialization: a verifier can then
/// tolerate registry fields added by future schema versions, since unknown fields survive
/// verbatim in the signed bytes and are ignored at parse time.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedCircuitVerificationKeyRegistry {
    /// Exact JSON of the signed registry.
    registry: Box<RawValue>,

    /// Ed25519 genesis signature over the domain separator followed by the exact registry JSON
    /// bytes.
    pub signature: GenesisEd25519Signature,
}

impl SignedCircuitVerificationKeyRegistry {
    /// Sign a registry with the Ed25519 half of the genesis signer.
    pub fn try_new(
        registry: CircuitVerificationKeyRegistry,
        genesis_signer: &GenesisSigner,
    ) -> StdResult<Self> {
        let registry_json = serde_json::to_string_pretty(&registry)?;
        let signature = genesis_signer.ed25519.sign(&Self::signable_bytes(&registry_json));

        Ok(Self {
            registry: RawValue::from_string(registry_json)?,
            signature,
        })
    }

    /// Verify the genesis signature over the exact registry JSON bytes and parse the registry.
    pub fn verify(
        &self,
        genesis_verifier: &GenesisVerifier,
    ) -> StdResult<CircuitVerificationKeyRegistry> {
        genesis_verifier
            .verify_ed25519(&Self::signable_bytes(self.registry.get()), &self.signature)?;

        Ok(serde_json::from_str(self.registry.get())?)
    }

    /// Parse the registry without verifying its signature, for displaying or testing purposes
    /// only: never trust the result.
    pub fn parse_registry_unverified(&self) -> StdResult<CircuitVerificationKeyRegistry> {
        Ok(serde_json::from_str(self.registry.get())?)
    }

    /// Prefix the registry JSON bytes with the domain separator.
    fn signable_bytes(registry_json: &str) -> Vec<u8> {
        [REGISTRY_SIGNATURE_DOMAIN_SEPARATOR, registry_json.as_bytes()].concat()
    }
}

impl Clone for SignedCircuitVerificationKeyRegistry {
    fn clone(&self) -> Self {
        Self {
            registry: self.registry.to_owned(),
            signature: self.signature,
        }
    }
}

impl PartialEq for SignedCircuitVerificationKeyRegistry {
    fn eq(&self, other: &Self) -> bool {
        self.registry.get() == other.registry.get() && self.signature == other.signature
    }
}

impl Eq for SignedCircuitVerificationKeyRegistry {}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::crypto_helper::GenesisEd25519Signer;

    use super::*;

    fn digest(seed: u8) -> CircuitVerificationKeyDigest {
        hex::encode([seed; 32]).parse().unwrap()
    }

    fn entry(
        digest: CircuitVerificationKeyDigest,
        status: CircuitVerificationKeyStatus,
        start_epoch: u64,
        end_epoch: Option<u64>,
    ) -> CircuitVerificationKeyEntry {
        CircuitVerificationKeyEntry {
            digest,
            name: "circuit".to_string(),
            status,
            start_epoch: Epoch(start_epoch),
            end_epoch: end_epoch.map(Epoch),
            comment: None,
        }
    }

    fn registry(entries: Vec<CircuitVerificationKeyEntry>) -> CircuitVerificationKeyRegistry {
        CircuitVerificationKeyRegistry {
            version: 1,
            entries,
        }
    }

    mod entry_coverage {
        use super::*;

        #[test]
        fn covers_inclusive_bounds_of_a_closed_range() {
            let entry = entry(
                digest(1),
                CircuitVerificationKeyStatus::Allowed,
                10,
                Some(20),
            );

            assert!(!entry.covers(Epoch(9)));
            assert!(entry.covers(Epoch(10)));
            assert!(entry.covers(Epoch(20)));
            assert!(!entry.covers(Epoch(21)));
        }

        #[test]
        fn covers_every_epoch_from_start_when_open_ended() {
            let entry = entry(digest(1), CircuitVerificationKeyStatus::Allowed, 10, None);

            assert!(!entry.covers(Epoch(9)));
            assert!(entry.covers(Epoch(10)));
            assert!(entry.covers(Epoch(u64::MAX)));
        }
    }

    mod check {
        use super::*;

        #[test]
        fn accepts_digests_covered_by_an_allowed_entry() {
            let registry = registry(vec![
                entry(
                    digest(1),
                    CircuitVerificationKeyStatus::Allowed,
                    10,
                    Some(20),
                ),
                entry(digest(2), CircuitVerificationKeyStatus::Allowed, 10, None),
            ]);

            registry.check(&[digest(1), digest(2)], Epoch(15)).unwrap();
        }

        #[test]
        fn rejects_an_unknown_digest_as_not_whitelisted() {
            let registry = registry(vec![entry(
                digest(1),
                CircuitVerificationKeyStatus::Allowed,
                10,
                None,
            )]);

            let error = registry.check(&[digest(9)], Epoch(15)).unwrap_err();

            assert_eq!(
                CircuitVerificationKeyRegistryError::NotWhitelisted {
                    digest: digest(9),
                    epoch: Epoch(15),
                },
                error
            );
        }

        #[test]
        fn rejects_an_epoch_outside_the_allowed_range_as_not_whitelisted() {
            let registry = registry(vec![entry(
                digest(1),
                CircuitVerificationKeyStatus::Allowed,
                10,
                Some(20),
            )]);

            let error = registry.check(&[digest(1)], Epoch(21)).unwrap_err();

            assert_eq!(
                CircuitVerificationKeyRegistryError::NotWhitelisted {
                    digest: digest(1),
                    epoch: Epoch(21),
                },
                error
            );
        }

        #[test]
        fn revocation_wins_over_an_allowed_entry_covering_the_same_epoch() {
            let registry = registry(vec![
                entry(digest(1), CircuitVerificationKeyStatus::Allowed, 10, None),
                entry(digest(1), CircuitVerificationKeyStatus::Revoked, 250, None),
            ]);

            registry.check(&[digest(1)], Epoch(249)).unwrap();
            let error = registry.check(&[digest(1)], Epoch(250)).unwrap_err();

            assert_eq!(
                CircuitVerificationKeyRegistryError::Revoked {
                    digest: digest(1),
                    epoch: Epoch(250),
                },
                error
            );
        }

        #[test]
        fn rejects_when_any_digest_of_the_list_fails() {
            let registry = registry(vec![entry(
                digest(1),
                CircuitVerificationKeyStatus::Allowed,
                10,
                None,
            )]);

            registry.check(&[digest(1), digest(2)], Epoch(15)).unwrap_err();
        }

        #[test]
        fn accepts_an_empty_digest_list() {
            let registry = registry(vec![]);

            registry.check(&[], Epoch(15)).unwrap();
        }
    }

    mod signature {
        use super::*;

        #[test]
        fn signed_registry_round_trips_signature_verification() {
            let genesis_signer =
                GenesisSigner::from_ed25519(GenesisEd25519Signer::create_deterministic_signer());
            let signed_registry = SignedCircuitVerificationKeyRegistry::try_new(
                registry(vec![entry(
                    digest(1),
                    CircuitVerificationKeyStatus::Allowed,
                    10,
                    None,
                )]),
                &genesis_signer,
            )
            .unwrap();

            let verified_registry =
                signed_registry.verify(&genesis_signer.create_verifier()).unwrap();

            assert_eq!(
                registry(vec![entry(
                    digest(1),
                    CircuitVerificationKeyStatus::Allowed,
                    10,
                    None,
                )]),
                verified_registry
            );
        }

        #[test]
        fn tampered_registry_fails_signature_verification() {
            let genesis_signer =
                GenesisSigner::from_ed25519(GenesisEd25519Signer::create_deterministic_signer());
            let mut signed_registry = SignedCircuitVerificationKeyRegistry::try_new(
                registry(vec![entry(
                    digest(1),
                    CircuitVerificationKeyStatus::Allowed,
                    10,
                    None,
                )]),
                &genesis_signer,
            )
            .unwrap();
            let mut tampered_registry = signed_registry.parse_registry_unverified().unwrap();
            tampered_registry.version = 2;
            signed_registry.registry =
                RawValue::from_string(serde_json::to_string_pretty(&tampered_registry).unwrap())
                    .unwrap();

            signed_registry
                .verify(&genesis_signer.create_verifier())
                .expect_err("a tampered registry must fail signature verification");
        }

        #[test]
        fn registry_with_unknown_fields_still_verifies_and_parses() {
            let genesis_signer =
                GenesisSigner::from_ed25519(GenesisEd25519Signer::create_deterministic_signer());
            let registry_json_with_unknown_field =
                r#"{ "version": 1, "entries": [], "a-future-field": true }"#.to_string();
            let signature =
                genesis_signer
                    .ed25519
                    .sign(&SignedCircuitVerificationKeyRegistry::signable_bytes(
                        &registry_json_with_unknown_field,
                    ));
            let signed_registry = SignedCircuitVerificationKeyRegistry {
                registry: RawValue::from_string(registry_json_with_unknown_field).unwrap(),
                signature,
            };

            let verified_registry =
                signed_registry.verify(&genesis_signer.create_verifier()).unwrap();

            assert_eq!(1, verified_registry.version);
        }

        #[test]
        fn signature_from_another_genesis_key_is_rejected() {
            let genesis_signer =
                GenesisSigner::from_ed25519(GenesisEd25519Signer::create_deterministic_signer());
            let other_verifier = GenesisSigner::from_ed25519(
                GenesisEd25519Signer::create_test_signer(ChaCha20Rng::from_seed([7u8; 32])),
            )
            .create_verifier();
            let signed_registry =
                SignedCircuitVerificationKeyRegistry::try_new(registry(vec![]), &genesis_signer)
                    .unwrap();

            signed_registry
                .verify(&other_verifier)
                .expect_err("a signature from another genesis key must be rejected");
        }
    }

    mod serialization {
        use super::*;

        #[test]
        fn signed_registry_round_trips_through_json() {
            let genesis_signer =
                GenesisSigner::from_ed25519(GenesisEd25519Signer::create_deterministic_signer());
            let signed_registry = SignedCircuitVerificationKeyRegistry::try_new(
                registry(vec![entry(
                    digest(1),
                    CircuitVerificationKeyStatus::Revoked,
                    10,
                    Some(20),
                )]),
                &genesis_signer,
            )
            .unwrap();

            let json = serde_json::to_string(&signed_registry).unwrap();
            let restored: SignedCircuitVerificationKeyRegistry =
                serde_json::from_str(&json).unwrap();

            assert_eq!(signed_registry, restored);
            restored.verify(&genesis_signer.create_verifier()).unwrap();
        }
    }
}
