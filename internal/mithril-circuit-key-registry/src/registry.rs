//! Genesis-signed registry of the circuit verification keys trusted for SNARK certificates.

use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use thiserror::Error;

use mithril_common::StdResult;
use mithril_common::crypto_helper::{
    CircuitVerificationKeyDigest, GenesisEd25519Signature, GenesisSigner, GenesisVerifier,
};
use mithril_common::entities::Epoch;

/// Errors raised when checking circuit verification key digests against a
/// [CircuitVerificationKeyRegistry].
#[derive(Error, Debug, PartialEq, Eq)]
pub enum CircuitVerificationKeyRegistryError {
    /// Some digests are revoked or not whitelisted for the checked epoch.
    #[error("circuit verification keys rejected for epoch {epoch}: {}", CircuitVerificationKeyRejection::join(.rejections))]
    Rejected {
        /// Epoch for which the check was performed.
        epoch: Epoch,
        /// Rejected digests with their reason, in the checked order.
        rejections: Vec<CircuitVerificationKeyRejection>,
    },
}

/// Reason for which a circuit verification key digest is rejected for an epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitVerificationKeyRejectionReason {
    /// The digest is covered by a revoked entry.
    Revoked,

    /// The digest is not covered by any allowed entry.
    NotWhitelisted,
}

/// A circuit verification key digest rejected by the registry, with the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitVerificationKeyRejection {
    /// Rejected digest.
    pub digest: CircuitVerificationKeyDigest,

    /// Reason of the rejection.
    pub reason: CircuitVerificationKeyRejectionReason,
}

impl CircuitVerificationKeyRejection {
    /// Join the rejections in a single comma separated line.
    fn join(rejections: &[Self]) -> String {
        rejections
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Display for CircuitVerificationKeyRejection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.reason {
            CircuitVerificationKeyRejectionReason::Revoked => {
                write!(f, "'{}' is revoked", self.digest)
            }
            CircuitVerificationKeyRejectionReason::NotWhitelisted => {
                write!(f, "'{}' is not whitelisted", self.digest)
            }
        }
    }
}

/// Status of a circuit verification key entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CircuitVerificationKeyStatus {
    /// The key may certify certificates whose epoch falls in the entry's range.
    Allowed,

    /// The key is rejected for every epoch.
    Revoked,
}

/// The single statement about a circuit verification key: allowed over an inclusive epoch
/// range, or revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitVerificationKeyEntry {
    /// Digest of the circuit verification key the statement is about.
    pub digest: CircuitVerificationKeyDigest,

    /// Human readable label of the circuit, e.g. "certificate-circuit v2".
    pub name: String,

    /// Whether the key is allowed over the entry's range or revoked.
    pub status: CircuitVerificationKeyStatus,

    /// First epoch (inclusive) covered by the statement.
    pub start_epoch: Epoch,

    /// Last epoch (inclusive) covered by an allowed entry, open-ended when absent, or the
    /// revocation epoch of a revoked entry.
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
/// registry, signed with its own genesis key. It holds one entry per circuit verification key
/// digest: a digest absent from the registry is rejected (whitelist semantics), an allowed entry
/// accepts the epochs it covers, and a revoked entry rejects every epoch. A digest listed
/// several times is rejected as soon as one of its entries is revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitVerificationKeyRegistry {
    /// Monotonically increasing registry version, used for rollback protection.
    pub version: u64,

    /// One statement per circuit verification key.
    pub entries: Vec<CircuitVerificationKeyEntry>,
}

impl CircuitVerificationKeyRegistry {
    /// Check that every digest is allowed for the given epoch, reporting every rejected digest
    /// at once.
    ///
    /// A digest is rejected as [Revoked](CircuitVerificationKeyRejectionReason::Revoked) when its
    /// entry is revoked, and as
    /// [NotWhitelisted](CircuitVerificationKeyRejectionReason::NotWhitelisted) when it has no
    /// entry or its allowed entry does not cover the epoch.
    pub fn check(
        &self,
        digests: &[CircuitVerificationKeyDigest],
        epoch: Epoch,
    ) -> Result<(), CircuitVerificationKeyRegistryError> {
        let rejections: Vec<CircuitVerificationKeyRejection> = digests
            .iter()
            .filter_map(|digest| self.find_digest_rejection(digest, epoch))
            .collect();

        if rejections.is_empty() {
            Ok(())
        } else {
            Err(CircuitVerificationKeyRegistryError::Rejected { epoch, rejections })
        }
    }

    /// Find why the digest is rejected for the epoch, if it is: a revoked entry of the digest
    /// wins over any allowed one, so a malformed registry listing a digest twice cannot certify
    /// a revoked key.
    fn find_digest_rejection(
        &self,
        digest: &CircuitVerificationKeyDigest,
        epoch: Epoch,
    ) -> Option<CircuitVerificationKeyRejection> {
        let entries: Vec<&CircuitVerificationKeyEntry> =
            self.entries.iter().filter(|entry| entry.digest == *digest).collect();
        let is_revoked = entries
            .iter()
            .any(|entry| entry.status == CircuitVerificationKeyStatus::Revoked);
        let is_allowed = entries.iter().any(|entry| entry.covers(epoch));
        let reason = match (is_revoked, is_allowed) {
            (true, _) => Some(CircuitVerificationKeyRejectionReason::Revoked),
            (false, false) => Some(CircuitVerificationKeyRejectionReason::NotWhitelisted),
            (false, true) => None,
        };

        reason.map(|reason| CircuitVerificationKeyRejection {
            digest: *digest,
            reason,
        })
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
        Self::try_new_from_json(serde_json::to_string_pretty(&registry)?, genesis_signer)
    }

    /// Sign the exact registry JSON with the Ed25519 half of the genesis signer.
    ///
    /// A tool that edits a published registry signs the JSON document it edited rather than a
    /// re-serialization of the parsed registry, so the fields added by a future schema version
    /// are not silently stripped from the re-signed registry. The whitespace surrounding the
    /// document (e.g. the final newline of a file) is not part of the signed bytes.
    pub fn try_new_from_json(
        registry_json: String,
        genesis_signer: &GenesisSigner,
    ) -> StdResult<Self> {
        let registry = RawValue::from_string(registry_json)?;
        let signature = genesis_signer.ed25519.sign(&Self::signable_bytes(registry.get()));

        Ok(Self {
            registry,
            signature,
        })
    }

    /// Verify the genesis signature over the exact registry JSON bytes and parse the registry.
    pub fn verify(
        &self,
        genesis_verifier: &GenesisVerifier,
    ) -> StdResult<CircuitVerificationKeyRegistry> {
        Ok(serde_json::from_str(
            self.verify_to_json(genesis_verifier)?,
        )?)
    }

    /// Verify the genesis signature and return the exact registry JSON bytes it covers.
    ///
    /// A tool that edits a published registry starts from these bytes rather than from the parsed
    /// registry, so the fields added by a future schema version survive the edit.
    pub fn verify_to_json(&self, genesis_verifier: &GenesisVerifier) -> StdResult<&str> {
        genesis_verifier
            .verify_ed25519(&Self::signable_bytes(self.registry.get()), &self.signature)?;

        Ok(self.registry.get())
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

    use mithril_common::crypto_helper::GenesisEd25519Signer;

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

        fn rejection(
            digest: CircuitVerificationKeyDigest,
            reason: CircuitVerificationKeyRejectionReason,
        ) -> CircuitVerificationKeyRejection {
            CircuitVerificationKeyRejection { digest, reason }
        }

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
                CircuitVerificationKeyRegistryError::Rejected {
                    epoch: Epoch(15),
                    rejections: vec![rejection(
                        digest(9),
                        CircuitVerificationKeyRejectionReason::NotWhitelisted
                    )],
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
                CircuitVerificationKeyRegistryError::Rejected {
                    epoch: Epoch(21),
                    rejections: vec![rejection(
                        digest(1),
                        CircuitVerificationKeyRejectionReason::NotWhitelisted
                    )],
                },
                error
            );
        }

        #[test]
        fn rejects_a_revoked_key_for_every_epoch() {
            let registry = registry(vec![entry(
                digest(1),
                CircuitVerificationKeyStatus::Revoked,
                10,
                Some(250),
            )]);

            for epoch in [Epoch(5), Epoch(100), Epoch(300)] {
                let error = registry.check(&[digest(1)], epoch).unwrap_err();

                assert_eq!(
                    CircuitVerificationKeyRegistryError::Rejected {
                        epoch,
                        rejections: vec![rejection(
                            digest(1),
                            CircuitVerificationKeyRejectionReason::Revoked
                        )],
                    },
                    error
                );
            }
        }

        #[test]
        fn rejects_a_digest_listed_as_allowed_and_revoked() {
            let registry = registry(vec![
                entry(digest(1), CircuitVerificationKeyStatus::Allowed, 10, None),
                entry(
                    digest(1),
                    CircuitVerificationKeyStatus::Revoked,
                    10,
                    Some(20),
                ),
            ]);

            let error = registry.check(&[digest(1)], Epoch(15)).unwrap_err();

            assert_eq!(
                CircuitVerificationKeyRegistryError::Rejected {
                    epoch: Epoch(15),
                    rejections: vec![rejection(
                        digest(1),
                        CircuitVerificationKeyRejectionReason::Revoked
                    )],
                },
                error
            );
        }

        #[test]
        fn reports_every_rejected_digest_of_the_list_with_its_reason() {
            let registry = registry(vec![
                entry(digest(1), CircuitVerificationKeyStatus::Allowed, 10, None),
                entry(digest(2), CircuitVerificationKeyStatus::Revoked, 10, None),
            ]);

            let error = registry
                .check(&[digest(1), digest(2), digest(3)], Epoch(15))
                .unwrap_err();

            assert_eq!(
                CircuitVerificationKeyRegistryError::Rejected {
                    epoch: Epoch(15),
                    rejections: vec![
                        rejection(digest(2), CircuitVerificationKeyRejectionReason::Revoked),
                        rejection(
                            digest(3),
                            CircuitVerificationKeyRejectionReason::NotWhitelisted
                        ),
                    ],
                },
                error
            );
            assert_eq!(
                format!(
                    "circuit verification keys rejected for epoch 15: '{}' is revoked, '{}' is not whitelisted",
                    digest(2),
                    digest(3)
                ),
                error.to_string()
            );
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
        fn signed_registry_json_surrounded_by_whitespace_verifies() {
            let genesis_signer =
                GenesisSigner::from_ed25519(GenesisEd25519Signer::create_deterministic_signer());
            let registry_json = format!(
                "{}\n",
                serde_json::to_string_pretty(&registry(vec![])).unwrap()
            );

            let signed_registry = SignedCircuitVerificationKeyRegistry::try_new_from_json(
                registry_json,
                &genesis_signer,
            )
            .unwrap();

            signed_registry.verify(&genesis_signer.create_verifier()).expect(
                "the signature must cover the registry JSON without its surrounding whitespace",
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
