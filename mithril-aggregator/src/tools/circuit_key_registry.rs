//! Tools for the circuit verification key registry: export the circuit key digests, extend a
//! registry with genesis-signed whitelist and revocation entries, sign and bootstrap it.

use std::{fs::read_to_string, path::Path};

use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};

use mithril_common::{
    StdResult,
    crypto_helper::{
        CircuitVerificationKeyDigest, CircuitVerificationKeyEntry, CircuitVerificationKeyRegistry,
        CircuitVerificationKeyStatus, GenesisSigner, MINIMUM_REGISTRY_VERSION,
        SignedCircuitVerificationKeyRegistry,
    },
    entities::{Epoch, ProtocolParameters},
};

/// Digests of the circuit verification keys a network signs with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitVerificationKeyDigests {
    /// Digest of the certificate circuit verification key.
    pub certificate_circuit: CircuitVerificationKeyDigest,

    /// Digest of the IVC circuit verification key.
    pub ivc_circuit: CircuitVerificationKeyDigest,
}

impl CircuitVerificationKeyDigests {
    /// Compute the digests for the given protocol parameters, deriving the certificate circuit key
    /// from the trusted setup when it is not cached yet, or using the embedded production
    /// certificate circuit key when no parameters are given.
    pub fn compute(protocol_parameters: Option<&ProtocolParameters>) -> StdResult<Self> {
        let certificate_circuit = match protocol_parameters {
            Some(parameters) => CircuitVerificationKeyDigest::compute_for_certificate_circuit(
                &parameters.clone().into(),
            )
            .with_context(|| {
                format!(
                    "Failed to compute the certificate circuit verification key digest for protocol parameters {parameters:?}"
                )
            })?,
            None => CircuitVerificationKeyDigest::for_production_certificate_circuit()
                .with_context(|| {
                    "Failed to compute the production certificate circuit verification key digest"
                })?,
        };
        let ivc_circuit = CircuitVerificationKeyDigest::for_ivc_circuit()
            .with_context(|| "Failed to compute the IVC circuit verification key digest")?;

        Ok(Self {
            certificate_circuit,
            ivc_circuit,
        })
    }
}

/// Circuit verification key registry tools.
pub struct CircuitKeyRegistryTools;

impl CircuitKeyRegistryTools {
    /// Export the circuit verification key digests for the given protocol parameters as a JSON
    /// file.
    pub fn export_digests(
        protocol_parameters: Option<&ProtocolParameters>,
        target_path: &Path,
    ) -> StdResult<CircuitVerificationKeyDigests> {
        let digests = CircuitVerificationKeyDigests::compute(protocol_parameters)?;
        std::fs::write(target_path, serde_json::to_string_pretty(&digests)?).with_context(
            || {
                format!(
                    "Failed to write circuit verification key digests file at '{}'",
                    target_path.display()
                )
            },
        )?;

        Ok(digests)
    }

    /// Add an entry to the signed registry at the given path, creating the registry when the file
    /// does not exist, then sign the incremented version with the genesis secret key and write it
    /// back in place. An existing registry must carry a valid signature of the same genesis key.
    pub fn add_entry(
        registry_path: &Path,
        genesis_secret_key_path: &Path,
        entry: CircuitVerificationKeyEntry,
    ) -> StdResult<CircuitVerificationKeyRegistry> {
        let genesis_signer = GenesisSigner::read_from_file(genesis_secret_key_path)?;
        let mut registry = match Self::read_signed_registry(registry_path, &genesis_signer)? {
            Some(current_registry) => CircuitVerificationKeyRegistry {
                version: current_registry.version + 1,
                entries: current_registry.entries,
            },
            None => CircuitVerificationKeyRegistry {
                version: MINIMUM_REGISTRY_VERSION,
                entries: vec![],
            },
        };
        registry.entries.push(entry);
        Self::check_registry_can_be_signed(&registry)?;
        Self::sign_and_write(&registry, &genesis_signer, registry_path)?;

        Ok(registry)
    }

    /// Sign a circuit verification key registry with the Ed25519 half of the genesis signing key
    /// and write the signed registry JSON, after verifying the produced signature.
    pub fn sign(
        to_sign_registry_path: &Path,
        target_signed_registry_path: &Path,
        genesis_secret_key_path: &Path,
    ) -> StdResult<()> {
        let genesis_signer = GenesisSigner::read_from_file(genesis_secret_key_path)?;
        let registry_json = read_to_string(to_sign_registry_path).with_context(|| {
            format!(
                "Failed to read registry file at '{}'",
                to_sign_registry_path.display()
            )
        })?;
        let registry: CircuitVerificationKeyRegistry = serde_json::from_str(&registry_json)
            .with_context(|| {
                format!(
                    "Failed to parse registry file at '{}'",
                    to_sign_registry_path.display()
                )
            })?;
        Self::check_registry_can_be_signed(&registry)?;

        Self::sign_and_write(&registry, &genesis_signer, target_signed_registry_path)
    }

    /// Create and sign the circuit verification key registry whitelisting the certificate circuit
    /// key of the network protocol parameters and the IVC circuit key from epoch 0, and write the
    /// signed registry JSON. For test only.
    pub fn bootstrap(
        genesis_secret_key: &str,
        protocol_parameters: Option<&ProtocolParameters>,
        target_registry_path: &Path,
    ) -> StdResult<()> {
        let genesis_signer = GenesisSigner::try_from_hex(genesis_secret_key)
            .with_context(|| "hex decode of genesis secret key failure")?;
        let digests = CircuitVerificationKeyDigests::compute(protocol_parameters)?;
        let registry = CircuitVerificationKeyRegistry {
            version: MINIMUM_REGISTRY_VERSION,
            entries: vec![
                Self::allowed_circuit_key_entry(digests.certificate_circuit, "certificate-circuit"),
                Self::allowed_circuit_key_entry(digests.ivc_circuit, "ivc-circuit"),
            ],
        };

        Self::sign_and_write(&registry, &genesis_signer, target_registry_path)
    }

    /// Read and verify the signed registry at the given path with the verifier of the genesis
    /// signer, or return nothing when the file does not exist.
    fn read_signed_registry(
        registry_path: &Path,
        genesis_signer: &GenesisSigner,
    ) -> StdResult<Option<CircuitVerificationKeyRegistry>> {
        if !registry_path.exists() {
            return Ok(None);
        }
        let signed_registry: SignedCircuitVerificationKeyRegistry =
            serde_json::from_str(&read_to_string(registry_path).with_context(|| {
                format!(
                    "Failed to read signed registry file at '{}'",
                    registry_path.display()
                )
            })?)
            .with_context(|| {
                format!(
                    "Failed to parse signed registry file at '{}'",
                    registry_path.display()
                )
            })?;
        let registry = signed_registry
            .verify(&genesis_signer.create_verifier())
            .with_context(|| {
                format!(
                    "The signed registry at '{}' does not verify with the given genesis key",
                    registry_path.display()
                )
            })?;

        Ok(Some(registry))
    }

    /// Check that a registry is well formed before signing it: the version reaches the minimum
    /// accepted by the nodes, and no entry has an inverted epoch range (which would silently
    /// never match).
    fn check_registry_can_be_signed(registry: &CircuitVerificationKeyRegistry) -> StdResult<()> {
        if registry.version < MINIMUM_REGISTRY_VERSION {
            return Err(anyhow!(
                "The registry version {} is below the minimum accepted version {MINIMUM_REGISTRY_VERSION}",
                registry.version
            ));
        }
        for entry in &registry.entries {
            if let Some(end_epoch) = entry.end_epoch
                && entry.start_epoch > end_epoch
            {
                return Err(anyhow!(
                    "The entry '{}' has an inverted epoch range ({} > {}), it would never match",
                    entry.name,
                    entry.start_epoch,
                    end_epoch
                ));
            }
        }

        Ok(())
    }

    /// Sign the registry with the genesis signer, verify the produced signature and write the
    /// signed registry JSON at the given path.
    fn sign_and_write(
        registry: &CircuitVerificationKeyRegistry,
        genesis_signer: &GenesisSigner,
        target_path: &Path,
    ) -> StdResult<()> {
        let signed_registry =
            SignedCircuitVerificationKeyRegistry::try_new(registry.clone(), genesis_signer)?;
        signed_registry
            .verify(&genesis_signer.create_verifier())
            .with_context(|| "The produced registry signature does not verify")?;
        std::fs::write(target_path, serde_json::to_string_pretty(&signed_registry)?).with_context(
            || {
                format!(
                    "Failed to write signed registry file at '{}'",
                    target_path.display()
                )
            },
        )?;

        Ok(())
    }

    /// Build a registry entry allowing the given circuit verification key digest from epoch 0.
    fn allowed_circuit_key_entry(
        digest: CircuitVerificationKeyDigest,
        name: &str,
    ) -> CircuitVerificationKeyEntry {
        CircuitVerificationKeyEntry {
            digest,
            name: name.to_string(),
            status: CircuitVerificationKeyStatus::Allowed,
            start_epoch: Epoch(0),
            end_epoch: None,
            comment: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use mithril_common::{crypto_helper::GenesisEd25519Signer, test::TempDir};

    use super::*;

    fn get_temp_dir(dir_name: &str) -> PathBuf {
        TempDir::create("circuit_key_registry", dir_name)
    }

    fn write_genesis_secret_key(temp_dir: &Path) -> (PathBuf, GenesisSigner) {
        let genesis_signer = GenesisSigner::create_deterministic_signer();
        let genesis_secret_key_path = temp_dir.join("genesis.sk");
        genesis_signer.write_to_file(&genesis_secret_key_path).unwrap();

        (genesis_secret_key_path, genesis_signer)
    }

    fn read_signed_registry(path: &Path) -> SignedCircuitVerificationKeyRegistry {
        serde_json::from_str(&read_to_string(path).unwrap()).unwrap()
    }

    fn entry(digest_byte: u8, status: CircuitVerificationKeyStatus) -> CircuitVerificationKeyEntry {
        CircuitVerificationKeyEntry {
            digest: hex::encode([digest_byte; 32]).parse().unwrap(),
            name: format!("circuit-{digest_byte}"),
            status,
            start_epoch: Epoch(10),
            end_epoch: None,
            comment: Some("a comment".to_string()),
        }
    }

    mod export_digests {
        use super::*;

        #[test]
        fn exports_the_production_digests_without_protocol_parameters() {
            let temp_dir = get_temp_dir("export_digests_production");
            let target_path = temp_dir.join("digests.json");

            let digests = CircuitKeyRegistryTools::export_digests(None, &target_path).unwrap();

            let expected = CircuitVerificationKeyDigests {
                certificate_circuit:
                    CircuitVerificationKeyDigest::for_production_certificate_circuit().unwrap(),
                ivc_circuit: CircuitVerificationKeyDigest::for_ivc_circuit().unwrap(),
            };
            assert_eq!(expected, digests);
            let exported: CircuitVerificationKeyDigests =
                serde_json::from_str(&read_to_string(&target_path).unwrap()).unwrap();
            assert_eq!(expected, exported);
        }
    }

    mod add_entry {
        use super::*;

        #[test]
        fn creates_a_signed_registry_at_the_minimum_version_when_the_file_is_missing() {
            let temp_dir = get_temp_dir("add_entry_creates_registry");
            let (genesis_secret_key_path, genesis_signer) = write_genesis_secret_key(&temp_dir);
            let registry_path = temp_dir.join("registry.json");
            let added_entry = entry(1, CircuitVerificationKeyStatus::Allowed);

            let registry = CircuitKeyRegistryTools::add_entry(
                &registry_path,
                &genesis_secret_key_path,
                added_entry.clone(),
            )
            .unwrap();

            assert_eq!(MINIMUM_REGISTRY_VERSION, registry.version);
            assert_eq!(vec![added_entry], registry.entries);
            let verified_registry = read_signed_registry(&registry_path)
                .verify(&genesis_signer.create_verifier())
                .expect("the written registry must carry a valid genesis signature");
            assert_eq!(registry, verified_registry);
        }

        #[test]
        fn appends_the_entry_and_increments_the_version_of_an_existing_registry() {
            let temp_dir = get_temp_dir("add_entry_appends");
            let (genesis_secret_key_path, genesis_signer) = write_genesis_secret_key(&temp_dir);
            let registry_path = temp_dir.join("registry.json");
            let first_entry = entry(1, CircuitVerificationKeyStatus::Allowed);
            let second_entry = entry(1, CircuitVerificationKeyStatus::Revoked);
            CircuitKeyRegistryTools::add_entry(
                &registry_path,
                &genesis_secret_key_path,
                first_entry.clone(),
            )
            .unwrap();

            let registry = CircuitKeyRegistryTools::add_entry(
                &registry_path,
                &genesis_secret_key_path,
                second_entry.clone(),
            )
            .unwrap();

            assert_eq!(MINIMUM_REGISTRY_VERSION + 1, registry.version);
            assert_eq!(vec![first_entry, second_entry], registry.entries);
            let verified_registry = read_signed_registry(&registry_path)
                .verify(&genesis_signer.create_verifier())
                .expect("the written registry must carry a valid genesis signature");
            assert_eq!(registry, verified_registry);
        }

        #[test]
        fn fails_on_an_existing_registry_signed_by_another_genesis_key() {
            let temp_dir = get_temp_dir("add_entry_rejects_other_key");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry_path = temp_dir.join("registry.json");
            let other_genesis_signer = GenesisSigner::from_ed25519(
                GenesisEd25519Signer::create_non_deterministic_signer(),
            );
            let other_signed_registry = SignedCircuitVerificationKeyRegistry::try_new(
                CircuitVerificationKeyRegistry {
                    version: MINIMUM_REGISTRY_VERSION,
                    entries: vec![],
                },
                &other_genesis_signer,
            )
            .unwrap();
            std::fs::write(
                &registry_path,
                serde_json::to_string(&other_signed_registry).unwrap(),
            )
            .unwrap();

            CircuitKeyRegistryTools::add_entry(
                &registry_path,
                &genesis_secret_key_path,
                entry(1, CircuitVerificationKeyStatus::Allowed),
            )
            .expect_err("a registry signed by another genesis key must not be extended");

            assert_eq!(
                other_signed_registry,
                read_signed_registry(&registry_path),
                "the registry file must be left untouched"
            );
        }

        #[test]
        fn fails_on_an_entry_with_an_inverted_epoch_range() {
            let temp_dir = get_temp_dir("add_entry_inverted_range");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry_path = temp_dir.join("registry.json");

            CircuitKeyRegistryTools::add_entry(
                &registry_path,
                &genesis_secret_key_path,
                CircuitVerificationKeyEntry {
                    start_epoch: Epoch(20),
                    end_epoch: Some(Epoch(10)),
                    ..entry(1, CircuitVerificationKeyStatus::Allowed)
                },
            )
            .expect_err("an entry with an inverted epoch range must be rejected");

            assert!(!registry_path.exists());
        }
    }

    mod sign {
        use super::*;

        #[test]
        fn signs_a_registry_and_writes_a_verifiable_signed_registry() {
            let temp_dir = get_temp_dir("sign");
            let (genesis_secret_key_path, genesis_signer) = write_genesis_secret_key(&temp_dir);
            let registry = CircuitVerificationKeyRegistry {
                version: 1,
                entries: vec![],
            };
            let to_sign_registry_path = temp_dir.join("registry.json");
            let target_signed_registry_path = temp_dir.join("signed-registry.json");
            std::fs::write(
                &to_sign_registry_path,
                serde_json::to_string(&registry).unwrap(),
            )
            .unwrap();

            CircuitKeyRegistryTools::sign(
                &to_sign_registry_path,
                &target_signed_registry_path,
                &genesis_secret_key_path,
            )
            .unwrap();

            let verified_registry = read_signed_registry(&target_signed_registry_path)
                .verify(&genesis_signer.create_verifier())
                .expect("the written signed registry must carry a valid genesis signature");
            assert_eq!(registry, verified_registry);
        }

        #[test]
        fn fails_on_a_registry_with_an_inverted_epoch_range() {
            let temp_dir = get_temp_dir("sign_inverted");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry = CircuitVerificationKeyRegistry {
                version: 1,
                entries: vec![CircuitVerificationKeyEntry {
                    start_epoch: Epoch(20),
                    end_epoch: Some(Epoch(10)),
                    ..entry(1, CircuitVerificationKeyStatus::Allowed)
                }],
            };
            let to_sign_registry_path = temp_dir.join("registry.json");
            std::fs::write(
                &to_sign_registry_path,
                serde_json::to_string(&registry).unwrap(),
            )
            .unwrap();

            CircuitKeyRegistryTools::sign(
                &to_sign_registry_path,
                &temp_dir.join("signed-registry.json"),
                &genesis_secret_key_path,
            )
            .expect_err("a registry with an inverted epoch range must fail signing");
        }

        #[test]
        fn fails_on_a_registry_version_below_the_minimum() {
            let temp_dir = get_temp_dir("sign_version");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry = CircuitVerificationKeyRegistry {
                version: MINIMUM_REGISTRY_VERSION - 1,
                entries: vec![],
            };
            let to_sign_registry_path = temp_dir.join("registry.json");
            std::fs::write(
                &to_sign_registry_path,
                serde_json::to_string(&registry).unwrap(),
            )
            .unwrap();

            CircuitKeyRegistryTools::sign(
                &to_sign_registry_path,
                &temp_dir.join("signed-registry.json"),
                &genesis_secret_key_path,
            )
            .expect_err("a registry version below the minimum must fail signing");
        }

        #[test]
        fn fails_on_an_invalid_registry_file() {
            let temp_dir = get_temp_dir("sign_invalid");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let to_sign_registry_path = temp_dir.join("registry.json");
            std::fs::write(&to_sign_registry_path, "not a registry").unwrap();

            CircuitKeyRegistryTools::sign(
                &to_sign_registry_path,
                &temp_dir.join("signed-registry.json"),
                &genesis_secret_key_path,
            )
            .expect_err("an invalid registry file must fail signing");
        }
    }

    mod bootstrap {
        use super::*;

        #[test]
        fn bootstraps_a_verifiable_registry_whitelisting_the_production_circuit_keys_without_protocol_parameters()
         {
            let temp_dir = get_temp_dir("bootstrap");
            let genesis_secret_key_hex = GenesisEd25519Signer::create_deterministic_signer()
                .secret_key()
                .to_json_hex()
                .unwrap();
            let target_registry_path = temp_dir.join("registry.json");

            CircuitKeyRegistryTools::bootstrap(
                &genesis_secret_key_hex,
                None,
                &target_registry_path,
            )
            .unwrap();

            let verified_registry = read_signed_registry(&target_registry_path)
                .verify(
                    &GenesisSigner::from_ed25519(
                        GenesisEd25519Signer::create_deterministic_signer(),
                    )
                    .create_verifier(),
                )
                .expect("the bootstrapped registry must carry a valid genesis signature");
            assert_eq!(MINIMUM_REGISTRY_VERSION, verified_registry.version);
            assert_eq!(
                vec![
                    (
                        "certificate-circuit",
                        CircuitVerificationKeyDigest::for_production_certificate_circuit().unwrap()
                    ),
                    (
                        "ivc-circuit",
                        CircuitVerificationKeyDigest::for_ivc_circuit().unwrap()
                    ),
                ],
                verified_registry
                    .entries
                    .iter()
                    .map(|entry| (entry.name.as_str(), entry.digest))
                    .collect::<Vec<_>>()
            );
            assert!(verified_registry.entries.iter().all(|entry| {
                entry.status == CircuitVerificationKeyStatus::Allowed
                    && entry.start_epoch == Epoch(0)
                    && entry.end_epoch.is_none()
            }));
        }
    }
}
