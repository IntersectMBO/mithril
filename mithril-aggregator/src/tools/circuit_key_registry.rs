//! Tools for the circuit verification key registry: export the circuit key digests, whitelist,
//! expire and revoke circuit keys in a genesis-signed registry, sign and bootstrap it.

use std::{
    fs::{File, read_to_string, rename},
    io::Write,
    path::Path,
};

use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use mithril_circuit_key_registry::{
    CircuitVerificationKeyEntry, CircuitVerificationKeyRegistry, CircuitVerificationKeyStatus,
    SignedCircuitVerificationKeyRegistry,
};
use mithril_common::{
    StdResult,
    crypto_helper::{CircuitVerificationKeyDigest, GenesisSigner},
    entities::{Epoch, ProtocolParameters},
};

/// Version of the first registry of a Mithril network.
const INITIAL_REGISTRY_VERSION: u64 = 1;

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

    /// Add an entry to the signed registry at the given path, then sign the incremented version
    /// with the genesis secret key and write it back in place. An existing registry must carry a
    /// valid signature of the same genesis key, a missing one is created at the initial version.
    pub fn add_entry(
        registry_path: &Path,
        genesis_secret_key_path: &Path,
        entry: CircuitVerificationKeyEntry,
    ) -> StdResult<CircuitVerificationKeyRegistry> {
        let genesis_signer = GenesisSigner::read_from_file(genesis_secret_key_path)?;
        let registry_json = match Self::read_signed_registry_json(registry_path, &genesis_signer)? {
            Some(current_registry_json) => {
                Self::extended_registry_json(&current_registry_json, &entry)?
            }
            None => serde_json::to_string_pretty(&CircuitVerificationKeyRegistry {
                version: INITIAL_REGISTRY_VERSION,
                entries: vec![entry],
            })?,
        };

        Self::check_sign_and_write_json(&registry_json, &genesis_signer, registry_path)
    }

    /// Revoke the allowed circuit verification key with the given digest in the signed registry
    /// at the given path: its entry becomes revoked at the given epoch with the given comment,
    /// then the incremented version is signed with the genesis secret key and written back in
    /// place.
    pub fn revoke(
        registry_path: &Path,
        genesis_secret_key_path: &Path,
        digest: &CircuitVerificationKeyDigest,
        revocation_epoch: Epoch,
        comment: &str,
    ) -> StdResult<CircuitVerificationKeyRegistry> {
        Self::edit_allowed_entry(registry_path, genesis_secret_key_path, digest, |entry| {
            entry.insert(
                "status".to_string(),
                json!(CircuitVerificationKeyStatus::Revoked),
            );
            entry.insert("end_epoch".to_string(), json!(revocation_epoch));
            entry.insert("comment".to_string(), json!(comment));
        })
    }

    /// Expire the allowed circuit verification key with the given digest in the signed registry
    /// at the given path: its entry ends at the given epoch, with the given comment when
    /// provided, then the incremented version is signed with the genesis secret key and written
    /// back in place.
    pub fn expire(
        registry_path: &Path,
        genesis_secret_key_path: &Path,
        digest: &CircuitVerificationKeyDigest,
        end_epoch: Epoch,
        comment: Option<&str>,
    ) -> StdResult<CircuitVerificationKeyRegistry> {
        Self::edit_allowed_entry(registry_path, genesis_secret_key_path, digest, |entry| {
            entry.insert("end_epoch".to_string(), json!(end_epoch));
            if let Some(comment) = comment {
                entry.insert("comment".to_string(), json!(comment));
            }
        })
    }

    /// Apply the edit to the allowed entry of the digest in the signed registry at the given
    /// path, then sign the incremented version with the genesis secret key and write it back in
    /// place.
    fn edit_allowed_entry(
        registry_path: &Path,
        genesis_secret_key_path: &Path,
        digest: &CircuitVerificationKeyDigest,
        edit: impl FnOnce(&mut Map<String, Value>),
    ) -> StdResult<CircuitVerificationKeyRegistry> {
        let genesis_signer = GenesisSigner::read_from_file(genesis_secret_key_path)?;
        let current_registry_json =
            Self::read_signed_registry_json(registry_path, &genesis_signer)?.ok_or_else(|| {
                anyhow!(
                    "No signed registry at '{}': check the path",
                    registry_path.display()
                )
            })?;
        let registry_json = Self::edited_registry_json(&current_registry_json, digest, edit)?;

        Self::check_sign_and_write_json(&registry_json, &genesis_signer, registry_path)
    }

    /// Append the entry to the registry JSON, refusing a digest already listed, and increment
    /// the version.
    ///
    /// The entry is appended to the JSON document rather than to the parsed registry, so the
    /// fields added by a future schema version survive an entry added by an older binary.
    fn extended_registry_json(
        current_registry_json: &str,
        entry: &CircuitVerificationKeyEntry,
    ) -> StdResult<String> {
        let mut registry_value: Value = serde_json::from_str(current_registry_json)?;
        let entries = Self::entries_mut(&mut registry_value)?;
        if entries.iter().any(|listed| Self::has_digest(listed, &entry.digest)) {
            return Err(anyhow!(
                "The circuit verification key '{}' already has an entry in the registry",
                entry.digest
            ));
        }
        entries.push(serde_json::to_value(entry)?);
        Self::increment_version(&mut registry_value)?;

        Ok(serde_json::to_string_pretty(&registry_value)?)
    }

    /// Apply the edit to the allowed entry of the digest in the registry JSON and increment the
    /// version.
    fn edited_registry_json(
        current_registry_json: &str,
        digest: &CircuitVerificationKeyDigest,
        edit: impl FnOnce(&mut Map<String, Value>),
    ) -> StdResult<String> {
        let mut registry_value: Value = serde_json::from_str(current_registry_json)?;
        let entry = Self::entries_mut(&mut registry_value)?
            .iter_mut()
            .find(|listed| Self::has_digest(listed, digest))
            .ok_or_else(|| {
                anyhow!("The circuit verification key '{digest}' has no entry in the registry")
            })?;
        if entry.get("status") != Some(&json!(CircuitVerificationKeyStatus::Allowed)) {
            return Err(anyhow!(
                "The circuit verification key '{digest}' is not allowed in the registry"
            ));
        }
        let entry_object = entry
            .as_object_mut()
            .ok_or_else(|| anyhow!("The registry entry of '{digest}' is not an object"))?;
        edit(entry_object);
        Self::increment_version(&mut registry_value)?;

        Ok(serde_json::to_string_pretty(&registry_value)?)
    }

    /// Increment the version of the registry JSON.
    fn increment_version(registry_value: &mut Value) -> StdResult<()> {
        let registry_object = registry_value
            .as_object_mut()
            .ok_or_else(|| anyhow!("The signed registry JSON is not an object"))?;
        let version = registry_object
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("The signed registry JSON has no 'version' number"))?;
        let incremented_version = version
            .checked_add(1)
            .ok_or_else(|| anyhow!("The registry version {version} cannot be incremented"))?;
        registry_object.insert("version".to_string(), json!(incremented_version));

        Ok(())
    }

    /// The entries array of the registry JSON.
    fn entries_mut(registry_value: &mut Value) -> StdResult<&mut Vec<Value>> {
        registry_value
            .get_mut("entries")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| anyhow!("The signed registry JSON has no 'entries' array"))
    }

    /// Whether the entry JSON is about the given digest.
    fn has_digest(entry: &Value, digest: &CircuitVerificationKeyDigest) -> bool {
        entry.get("digest") == Some(&json!(digest))
    }

    /// Sign a circuit verification key registry with the Ed25519 half of the genesis signing key
    /// and write the signed registry JSON, after verifying the produced signature. The registry
    /// version must follow the version of the signed registry found at the target path, or be
    /// the initial version when there is none, so a hand-authored registry cannot be published
    /// with a version the running nodes would refuse, or keep over the later publications.
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
        Self::check_registry_version_follows_signed(
            &registry,
            target_signed_registry_path,
            &genesis_signer,
        )?;

        Self::sign_and_write_json(&registry_json, &genesis_signer, target_signed_registry_path)
    }

    /// Check that the registry version follows the version of the signed registry at the given
    /// path, or is the initial version when no registry is signed there yet.
    fn check_registry_version_follows_signed(
        registry: &CircuitVerificationKeyRegistry,
        signed_registry_path: &Path,
        genesis_signer: &GenesisSigner,
    ) -> StdResult<()> {
        let expected_version =
            match Self::read_signed_registry_json(signed_registry_path, genesis_signer)? {
                Some(signed_registry_json) => {
                    let signed_registry: CircuitVerificationKeyRegistry =
                        serde_json::from_str(&signed_registry_json)?;
                    signed_registry.version.checked_add(1).ok_or_else(|| {
                        anyhow!(
                            "The registry version {} cannot be incremented",
                            signed_registry.version
                        )
                    })?
                }
                None => INITIAL_REGISTRY_VERSION,
            };
        if registry.version != expected_version {
            return Err(anyhow!(
                "The registry version {} must be {expected_version}: the version following the signed registry at '{}', or {INITIAL_REGISTRY_VERSION} when there is none",
                registry.version,
                signed_registry_path.display()
            ));
        }

        Ok(())
    }

    /// Create and sign the circuit verification key registry, whitelisting from epoch 0 the
    /// certificate circuit key of every given protocol parameter set (or of the production
    /// parameters when none is given) and the IVC circuit key, and write the signed registry
    /// JSON. For test only.
    pub fn bootstrap(
        genesis_secret_key: &str,
        protocol_parameters: &[ProtocolParameters],
        target_registry_path: &Path,
    ) -> StdResult<()> {
        let genesis_signer = GenesisSigner::try_from_hex(genesis_secret_key)
            .with_context(|| "hex decode of genesis secret key failure")?;
        let registry = CircuitVerificationKeyRegistry {
            version: INITIAL_REGISTRY_VERSION,
            entries: Self::bootstrap_entries(&Self::compute_bootstrap_digests(
                protocol_parameters,
            )?),
        };

        Self::sign_and_write_json(
            &serde_json::to_string_pretty(&registry)?,
            &genesis_signer,
            target_registry_path,
        )
    }

    /// Compute the named circuit verification key digests of each protocol parameter set, or of
    /// the production parameters when none is given.
    fn compute_bootstrap_digests(
        protocol_parameters: &[ProtocolParameters],
    ) -> StdResult<Vec<(String, CircuitVerificationKeyDigests)>> {
        if protocol_parameters.is_empty() {
            return Ok(vec![(
                "certificate-circuit".to_string(),
                CircuitVerificationKeyDigests::compute(None)?,
            )]);
        }

        protocol_parameters
            .iter()
            .map(|parameters| {
                Ok((
                    format!("certificate-circuit k={} m={}", parameters.k, parameters.m),
                    CircuitVerificationKeyDigests::compute(Some(parameters))?,
                ))
            })
            .collect()
    }

    /// Build the entries allowing from epoch 0 each distinct certificate circuit key digest under
    /// its name, then the IVC circuit key digest, which does not depend on the parameters.
    fn bootstrap_entries(
        named_digests: &[(String, CircuitVerificationKeyDigests)],
    ) -> Vec<CircuitVerificationKeyEntry> {
        let mut entries: Vec<CircuitVerificationKeyEntry> = Vec::new();
        for (name, digests) in named_digests {
            if !entries
                .iter()
                .any(|entry| entry.digest == digests.certificate_circuit)
            {
                entries.push(Self::allowed_circuit_key_entry(
                    digests.certificate_circuit,
                    name,
                ));
            }
        }
        if let Some((_, digests)) = named_digests.first() {
            entries.push(Self::allowed_circuit_key_entry(
                digests.ivc_circuit,
                "ivc-circuit",
            ));
        }

        entries
    }

    /// Read the signed registry at the given path, verify it with the verifier of the genesis
    /// signer and return the exact registry JSON bytes the signature covers, or return nothing
    /// when the file does not exist.
    fn read_signed_registry_json(
        registry_path: &Path,
        genesis_signer: &GenesisSigner,
    ) -> StdResult<Option<String>> {
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
        let registry_json = signed_registry
            .verify_to_json(&genesis_signer.create_verifier())
            .with_context(|| {
                format!(
                    "The signed registry at '{}' does not verify with the given genesis key",
                    registry_path.display()
                )
            })?;

        Ok(Some(registry_json.to_string()))
    }

    /// Check that a registry is well formed before signing it: each circuit verification key has
    /// a single entry, and no allowed entry has an inverted epoch range (which would silently
    /// never match).
    fn check_registry_can_be_signed(registry: &CircuitVerificationKeyRegistry) -> StdResult<()> {
        for (index, entry) in registry.entries.iter().enumerate() {
            if registry.entries[..index]
                .iter()
                .any(|listed| listed.digest == entry.digest)
            {
                return Err(anyhow!(
                    "The circuit verification key '{}' has several entries",
                    entry.digest
                ));
            }
        }
        for entry in &registry.entries {
            if entry.status == CircuitVerificationKeyStatus::Allowed
                && let Some(end_epoch) = entry.end_epoch
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

    /// Check that the registry JSON can be signed, sign it with the genesis signer, write the
    /// signed registry JSON at the given path and return the registry.
    fn check_sign_and_write_json(
        registry_json: &str,
        genesis_signer: &GenesisSigner,
        target_path: &Path,
    ) -> StdResult<CircuitVerificationKeyRegistry> {
        let registry: CircuitVerificationKeyRegistry = serde_json::from_str(registry_json)?;
        Self::check_registry_can_be_signed(&registry)?;
        Self::sign_and_write_json(registry_json, genesis_signer, target_path)?;

        Ok(registry)
    }

    /// Sign the exact registry JSON with the genesis signer, verify the produced signature and
    /// write the signed registry JSON at the given path.
    fn sign_and_write_json(
        registry_json: &str,
        genesis_signer: &GenesisSigner,
        target_path: &Path,
    ) -> StdResult<()> {
        let signed_registry = SignedCircuitVerificationKeyRegistry::try_new_from_json(
            registry_json.to_string(),
            genesis_signer,
        )?;
        signed_registry
            .verify(&genesis_signer.create_verifier())
            .with_context(|| "The produced registry signature does not verify")?;
        Self::write_atomically(
            target_path,
            &serde_json::to_string_pretty(&signed_registry)?,
        )
        .with_context(|| {
            format!(
                "Failed to write signed registry file at '{}'",
                target_path.display()
            )
        })
    }

    /// Write the contents at the given path atomically: a temporary file in the same directory is
    /// filled and flushed to disk, then renamed over the target and the directory entry is
    /// flushed too.
    ///
    /// The registry is updated in place on an air-gapped machine, so a crash during a plain
    /// truncating write would destroy the only copy of the signed registry.
    fn write_atomically(target_path: &Path, contents: &str) -> StdResult<()> {
        let directory = match target_path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let temporary_path = target_path.with_extension("tmp");

        let mut temporary_file = File::create(&temporary_path).with_context(|| {
            format!(
                "Failed to create temporary file at '{}'",
                temporary_path.display()
            )
        })?;
        temporary_file.write_all(contents.as_bytes())?;
        temporary_file.sync_all()?;
        rename(&temporary_path, target_path).with_context(|| {
            format!(
                "Failed to rename '{}' to '{}'",
                temporary_path.display(),
                target_path.display()
            )
        })?;
        File::open(directory)?.sync_all()?;

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

    fn registry_with_allowed_keys(
        temp_dir: &Path,
        genesis_secret_key_path: &Path,
        digest_bytes: &[u8],
    ) -> PathBuf {
        let registry_path = temp_dir.join("registry.json");
        for digest_byte in digest_bytes {
            CircuitKeyRegistryTools::add_entry(
                &registry_path,
                genesis_secret_key_path,
                entry(*digest_byte, CircuitVerificationKeyStatus::Allowed),
            )
            .unwrap();
        }

        registry_path
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
        fn creates_a_signed_registry_at_the_initial_version_when_missing() {
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

            assert_eq!(INITIAL_REGISTRY_VERSION, registry.version);
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
            let second_entry = entry(2, CircuitVerificationKeyStatus::Allowed);
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

            assert_eq!(INITIAL_REGISTRY_VERSION + 1, registry.version);
            assert_eq!(vec![first_entry, second_entry], registry.entries);
            let verified_registry = read_signed_registry(&registry_path)
                .verify(&genesis_signer.create_verifier())
                .expect("the written registry must carry a valid genesis signature");
            assert_eq!(registry, verified_registry);
        }

        #[test]
        fn preserves_the_fields_of_a_future_registry_schema() {
            let temp_dir = get_temp_dir("add_entry_preserves_future_fields");
            let (genesis_secret_key_path, genesis_signer) = write_genesis_secret_key(&temp_dir);
            let registry_path = temp_dir.join("registry.json");
            let future_registry_json = json!({
                "version": INITIAL_REGISTRY_VERSION,
                "network": "release-preprod",
                "entries": [{
                    "digest": hex::encode([1; 32]),
                    "name": "circuit-1",
                    "status": "allowed",
                    "start_epoch": 10,
                    "end_epoch": null,
                    "comment": null,
                    "issued_by": "a future entry field"
                }]
            })
            .to_string();
            let signed_registry = SignedCircuitVerificationKeyRegistry::try_new_from_json(
                future_registry_json,
                &genesis_signer,
            )
            .unwrap();
            std::fs::write(
                &registry_path,
                serde_json::to_string(&signed_registry).unwrap(),
            )
            .unwrap();

            CircuitKeyRegistryTools::add_entry(
                &registry_path,
                &genesis_secret_key_path,
                entry(2, CircuitVerificationKeyStatus::Allowed),
            )
            .unwrap();

            let re_signed_registry = read_signed_registry(&registry_path);
            let registry_json = re_signed_registry
                .verify_to_json(&genesis_signer.create_verifier())
                .expect("the re-signed registry must carry a valid genesis signature");
            let registry_value: Value = serde_json::from_str(registry_json).unwrap();
            assert_eq!(
                Some("release-preprod"),
                registry_value["network"].as_str(),
                "a registry field of a future schema must survive the edit"
            );
            assert_eq!(
                Some("a future entry field"),
                registry_value["entries"][0]["issued_by"].as_str(),
                "an entry field of a future schema must survive the edit"
            );
            assert_eq!(
                Some(INITIAL_REGISTRY_VERSION + 1),
                registry_value["version"].as_u64()
            );
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
                    version: INITIAL_REGISTRY_VERSION,
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
        fn fails_on_a_registry_version_that_cannot_be_incremented() {
            let temp_dir = get_temp_dir("add_entry_version_overflow");
            let (genesis_secret_key_path, genesis_signer) = write_genesis_secret_key(&temp_dir);
            let registry_path = temp_dir.join("registry.json");
            let signed_registry = SignedCircuitVerificationKeyRegistry::try_new(
                CircuitVerificationKeyRegistry {
                    version: u64::MAX,
                    entries: vec![],
                },
                &genesis_signer,
            )
            .unwrap();
            std::fs::write(
                &registry_path,
                serde_json::to_string(&signed_registry).unwrap(),
            )
            .unwrap();

            CircuitKeyRegistryTools::add_entry(
                &registry_path,
                &genesis_secret_key_path,
                entry(1, CircuitVerificationKeyStatus::Allowed),
            )
            .expect_err("a registry version that cannot be incremented must be refused");

            assert_eq!(signed_registry, read_signed_registry(&registry_path));
        }

        #[test]
        fn fails_on_a_digest_already_listed() {
            let temp_dir = get_temp_dir("add_entry_duplicate");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry_path = temp_dir.join("registry.json");
            CircuitKeyRegistryTools::add_entry(
                &registry_path,
                &genesis_secret_key_path,
                entry(1, CircuitVerificationKeyStatus::Allowed),
            )
            .unwrap();
            let registry_before = read_signed_registry(&registry_path);

            CircuitKeyRegistryTools::add_entry(
                &registry_path,
                &genesis_secret_key_path,
                entry(1, CircuitVerificationKeyStatus::Allowed),
            )
            .expect_err("a digest already listed must be refused");

            assert_eq!(registry_before, read_signed_registry(&registry_path));
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

    mod expire {
        use super::*;

        #[test]
        fn expires_an_allowed_key_in_place_and_increments_the_version() {
            let temp_dir = get_temp_dir("expire");
            let (genesis_secret_key_path, genesis_signer) = write_genesis_secret_key(&temp_dir);
            let registry_path =
                registry_with_allowed_keys(&temp_dir, &genesis_secret_key_path, &[1, 2]);

            let registry = CircuitKeyRegistryTools::expire(
                &registry_path,
                &genesis_secret_key_path,
                &entry(2, CircuitVerificationKeyStatus::Allowed).digest,
                Epoch(42),
                Some("rotated to circuit-3"),
            )
            .unwrap();

            assert_eq!(INITIAL_REGISTRY_VERSION + 2, registry.version);
            assert_eq!(
                vec![
                    entry(1, CircuitVerificationKeyStatus::Allowed),
                    CircuitVerificationKeyEntry {
                        end_epoch: Some(Epoch(42)),
                        comment: Some("rotated to circuit-3".to_string()),
                        ..entry(2, CircuitVerificationKeyStatus::Allowed)
                    },
                ],
                registry.entries
            );
            let verified_registry = read_signed_registry(&registry_path)
                .verify(&genesis_signer.create_verifier())
                .expect("the written registry must carry a valid genesis signature");
            assert_eq!(registry, verified_registry);
        }

        #[test]
        fn keeps_the_comment_of_the_entry_when_none_is_given() {
            let temp_dir = get_temp_dir("expire_keeps_comment");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry_path =
                registry_with_allowed_keys(&temp_dir, &genesis_secret_key_path, &[1]);

            let registry = CircuitKeyRegistryTools::expire(
                &registry_path,
                &genesis_secret_key_path,
                &entry(1, CircuitVerificationKeyStatus::Allowed).digest,
                Epoch(42),
                None,
            )
            .unwrap();

            assert_eq!(
                vec![CircuitVerificationKeyEntry {
                    end_epoch: Some(Epoch(42)),
                    ..entry(1, CircuitVerificationKeyStatus::Allowed)
                }],
                registry.entries
            );
        }

        #[test]
        fn fails_on_an_end_epoch_before_the_start_epoch() {
            let temp_dir = get_temp_dir("expire_before_start");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry_path =
                registry_with_allowed_keys(&temp_dir, &genesis_secret_key_path, &[1]);
            let registry_before = read_signed_registry(&registry_path);

            CircuitKeyRegistryTools::expire(
                &registry_path,
                &genesis_secret_key_path,
                &entry(1, CircuitVerificationKeyStatus::Allowed).digest,
                Epoch(5),
                None,
            )
            .expect_err("an end epoch before the start epoch must be refused");

            assert_eq!(registry_before, read_signed_registry(&registry_path));
        }

        #[test]
        fn fails_on_a_key_already_revoked() {
            let temp_dir = get_temp_dir("expire_revoked");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry_path =
                registry_with_allowed_keys(&temp_dir, &genesis_secret_key_path, &[1]);
            let digest = entry(1, CircuitVerificationKeyStatus::Allowed).digest;
            CircuitKeyRegistryTools::revoke(
                &registry_path,
                &genesis_secret_key_path,
                &digest,
                Epoch(42),
                "soundness issue",
            )
            .unwrap();
            let registry_before = read_signed_registry(&registry_path);

            CircuitKeyRegistryTools::expire(
                &registry_path,
                &genesis_secret_key_path,
                &digest,
                Epoch(43),
                None,
            )
            .expect_err("a revoked key must not be expired");

            assert_eq!(registry_before, read_signed_registry(&registry_path));
        }
    }

    mod revoke {
        use super::*;

        #[test]
        fn revokes_an_allowed_key_in_place_and_increments_the_version() {
            let temp_dir = get_temp_dir("revoke");
            let (genesis_secret_key_path, genesis_signer) = write_genesis_secret_key(&temp_dir);
            let registry_path =
                registry_with_allowed_keys(&temp_dir, &genesis_secret_key_path, &[1, 2]);

            let registry = CircuitKeyRegistryTools::revoke(
                &registry_path,
                &genesis_secret_key_path,
                &entry(2, CircuitVerificationKeyStatus::Allowed).digest,
                Epoch(42),
                "soundness issue",
            )
            .unwrap();

            assert_eq!(INITIAL_REGISTRY_VERSION + 2, registry.version);
            assert_eq!(
                vec![
                    entry(1, CircuitVerificationKeyStatus::Allowed),
                    CircuitVerificationKeyEntry {
                        end_epoch: Some(Epoch(42)),
                        comment: Some("soundness issue".to_string()),
                        ..entry(2, CircuitVerificationKeyStatus::Revoked)
                    },
                ],
                registry.entries
            );
            let verified_registry = read_signed_registry(&registry_path)
                .verify(&genesis_signer.create_verifier())
                .expect("the written registry must carry a valid genesis signature");
            assert_eq!(registry, verified_registry);
        }

        #[test]
        fn revokes_a_key_before_its_start_epoch() {
            let temp_dir = get_temp_dir("revoke_before_start");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry_path =
                registry_with_allowed_keys(&temp_dir, &genesis_secret_key_path, &[1]);

            let registry = CircuitKeyRegistryTools::revoke(
                &registry_path,
                &genesis_secret_key_path,
                &entry(1, CircuitVerificationKeyStatus::Allowed).digest,
                Epoch(5),
                "revoked before use",
            )
            .expect("a key must be revocable before its start epoch");

            assert_eq!(Some(Epoch(5)), registry.entries[0].end_epoch);
        }

        #[test]
        fn fails_on_a_digest_without_entry() {
            let temp_dir = get_temp_dir("revoke_unknown");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry_path =
                registry_with_allowed_keys(&temp_dir, &genesis_secret_key_path, &[1]);
            let registry_before = read_signed_registry(&registry_path);

            CircuitKeyRegistryTools::revoke(
                &registry_path,
                &genesis_secret_key_path,
                &entry(9, CircuitVerificationKeyStatus::Allowed).digest,
                Epoch(42),
                "soundness issue",
            )
            .expect_err("a digest without entry must not be revoked");

            assert_eq!(registry_before, read_signed_registry(&registry_path));
        }

        #[test]
        fn fails_on_a_key_already_revoked() {
            let temp_dir = get_temp_dir("revoke_twice");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry_path =
                registry_with_allowed_keys(&temp_dir, &genesis_secret_key_path, &[1]);
            let digest = entry(1, CircuitVerificationKeyStatus::Allowed).digest;
            CircuitKeyRegistryTools::revoke(
                &registry_path,
                &genesis_secret_key_path,
                &digest,
                Epoch(42),
                "soundness issue",
            )
            .unwrap();
            let registry_before = read_signed_registry(&registry_path);

            CircuitKeyRegistryTools::revoke(
                &registry_path,
                &genesis_secret_key_path,
                &digest,
                Epoch(43),
                "again",
            )
            .expect_err("a key already revoked must not be revoked again");

            assert_eq!(registry_before, read_signed_registry(&registry_path));
        }

        #[test]
        fn fails_on_a_missing_registry() {
            let temp_dir = get_temp_dir("revoke_missing_registry");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry_path = temp_dir.join("registry.json");

            CircuitKeyRegistryTools::revoke(
                &registry_path,
                &genesis_secret_key_path,
                &entry(1, CircuitVerificationKeyStatus::Allowed).digest,
                Epoch(42),
                "soundness issue",
            )
            .expect_err("a missing registry must not be created by a revocation");

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
        fn signs_the_authored_bytes_without_dropping_the_fields_of_a_future_schema() {
            let temp_dir = get_temp_dir("sign_preserves_future_fields");
            let (genesis_secret_key_path, genesis_signer) = write_genesis_secret_key(&temp_dir);
            let to_sign_registry_path = temp_dir.join("registry.json");
            let target_signed_registry_path = temp_dir.join("signed-registry.json");
            let authored_registry_json = json!({
                "version": INITIAL_REGISTRY_VERSION,
                "network": "release-preprod",
                "entries": []
            })
            .to_string();
            std::fs::write(&to_sign_registry_path, &authored_registry_json).unwrap();

            CircuitKeyRegistryTools::sign(
                &to_sign_registry_path,
                &target_signed_registry_path,
                &genesis_secret_key_path,
            )
            .unwrap();

            let registry_json = read_signed_registry(&target_signed_registry_path)
                .verify_to_json(&genesis_signer.create_verifier())
                .expect("the signed registry must carry a valid genesis signature")
                .to_string();
            assert_eq!(authored_registry_json, registry_json);
        }

        #[test]
        fn signs_a_registry_file_ending_with_a_newline() {
            let temp_dir = get_temp_dir("sign_trailing_newline");
            let (genesis_secret_key_path, genesis_signer) = write_genesis_secret_key(&temp_dir);
            let to_sign_registry_path = temp_dir.join("registry.json");
            let target_signed_registry_path = temp_dir.join("signed-registry.json");
            let authored_registry_json = json!({
                "version": INITIAL_REGISTRY_VERSION,
                "entries": []
            })
            .to_string();
            std::fs::write(
                &to_sign_registry_path,
                format!("{authored_registry_json}\n"),
            )
            .unwrap();

            CircuitKeyRegistryTools::sign(
                &to_sign_registry_path,
                &target_signed_registry_path,
                &genesis_secret_key_path,
            )
            .expect("a registry file ending with a newline must be signed");

            let registry_json = read_signed_registry(&target_signed_registry_path)
                .verify_to_json(&genesis_signer.create_verifier())
                .expect("the signed registry must carry a valid genesis signature")
                .to_string();
            assert_eq!(authored_registry_json, registry_json);
        }

        #[test]
        fn signs_the_version_following_the_signed_registry_at_the_target_path() {
            let temp_dir = get_temp_dir("sign_next_version");
            let (genesis_secret_key_path, genesis_signer) = write_genesis_secret_key(&temp_dir);
            let target_signed_registry_path =
                registry_with_allowed_keys(&temp_dir, &genesis_secret_key_path, &[1]);
            let registry = CircuitVerificationKeyRegistry {
                version: INITIAL_REGISTRY_VERSION + 1,
                entries: vec![entry(2, CircuitVerificationKeyStatus::Allowed)],
            };
            let to_sign_registry_path = temp_dir.join("registry-to-sign.json");
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
            .expect("the version following the signed registry must be signed");

            let verified_registry = read_signed_registry(&target_signed_registry_path)
                .verify(&genesis_signer.create_verifier())
                .expect("the written signed registry must carry a valid genesis signature");
            assert_eq!(registry, verified_registry);
        }

        #[test]
        fn fails_on_a_version_not_following_the_signed_registry_at_the_target_path() {
            let temp_dir = get_temp_dir("sign_wrong_version");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let target_signed_registry_path =
                registry_with_allowed_keys(&temp_dir, &genesis_secret_key_path, &[1]);
            let registry_before = read_signed_registry(&target_signed_registry_path);
            let to_sign_registry_path = temp_dir.join("registry-to-sign.json");

            for version in [INITIAL_REGISTRY_VERSION, INITIAL_REGISTRY_VERSION + 2] {
                let registry = CircuitVerificationKeyRegistry {
                    version,
                    entries: vec![],
                };
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
                .expect_err("a version not following the signed registry must fail signing");

                assert_eq!(
                    registry_before,
                    read_signed_registry(&target_signed_registry_path)
                );
            }
        }

        #[test]
        fn fails_on_a_first_registry_not_at_the_initial_version() {
            let temp_dir = get_temp_dir("sign_first_version");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry = CircuitVerificationKeyRegistry {
                version: INITIAL_REGISTRY_VERSION + 1,
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
            .expect_err("a first registry not at the initial version must fail signing");

            assert!(!target_signed_registry_path.exists());
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

    mod write_atomically {
        use super::*;

        #[test]
        fn leaves_no_temporary_file_behind() {
            let temp_dir = get_temp_dir("write_atomically_no_leftover");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry_path = temp_dir.join("registry.json");

            CircuitKeyRegistryTools::add_entry(
                &registry_path,
                &genesis_secret_key_path,
                entry(1, CircuitVerificationKeyStatus::Allowed),
            )
            .unwrap();

            assert!(!registry_path.with_extension("tmp").exists());
        }

        #[test]
        fn replaces_the_content_of_an_existing_registry() {
            let temp_dir = get_temp_dir("write_atomically_replaces");
            let genesis_signer =
                GenesisSigner::from_ed25519(GenesisEd25519Signer::create_deterministic_signer());
            let registry_path = temp_dir.join("registry.json");
            std::fs::write(&registry_path, "a much longer previous content").unwrap();

            CircuitKeyRegistryTools::bootstrap(
                &GenesisEd25519Signer::create_deterministic_signer()
                    .secret_key()
                    .to_json_hex()
                    .unwrap(),
                &[],
                &registry_path,
            )
            .unwrap();

            read_signed_registry(&registry_path)
                .verify(&genesis_signer.create_verifier())
                .expect("the replaced registry must carry a valid genesis signature");
        }
    }

    mod bootstrap {
        use super::*;

        fn named_digests(
            name: &str,
            certificate_circuit_byte: u8,
        ) -> (String, CircuitVerificationKeyDigests) {
            (
                name.to_string(),
                CircuitVerificationKeyDigests {
                    certificate_circuit: hex::encode([certificate_circuit_byte; 32])
                        .parse()
                        .unwrap(),
                    ivc_circuit: hex::encode([9; 32]).parse().unwrap(),
                },
            )
        }

        #[test]
        fn entries_allow_each_distinct_certificate_circuit_key_then_the_ivc_circuit_key() {
            let entries = CircuitKeyRegistryTools::bootstrap_entries(&[
                named_digests("certificate-circuit k=5 m=9", 1),
                named_digests("certificate-circuit k=7 m=10", 2),
                named_digests("certificate-circuit k=5 m=9 again", 1),
            ]);

            assert_eq!(
                vec![
                    ("certificate-circuit k=5 m=9", [1; 32]),
                    ("certificate-circuit k=7 m=10", [2; 32]),
                    ("ivc-circuit", [9; 32]),
                ],
                entries
                    .iter()
                    .map(|entry| (entry.name.as_str(), *entry.digest.as_bytes()))
                    .collect::<Vec<_>>()
            );
            assert!(entries.iter().all(|entry| {
                entry.status == CircuitVerificationKeyStatus::Allowed
                    && entry.start_epoch == Epoch(0)
                    && entry.end_epoch.is_none()
            }));
        }

        #[test]
        fn bootstraps_a_verifiable_registry_whitelisting_the_production_circuit_keys_without_protocol_parameters()
         {
            let temp_dir = get_temp_dir("bootstrap");
            let genesis_secret_key_hex = GenesisEd25519Signer::create_deterministic_signer()
                .secret_key()
                .to_json_hex()
                .unwrap();
            let target_registry_path = temp_dir.join("registry.json");

            CircuitKeyRegistryTools::bootstrap(&genesis_secret_key_hex, &[], &target_registry_path)
                .unwrap();

            let verified_registry = read_signed_registry(&target_registry_path)
                .verify(
                    &GenesisSigner::from_ed25519(
                        GenesisEd25519Signer::create_deterministic_signer(),
                    )
                    .create_verifier(),
                )
                .expect("the bootstrapped registry must carry a valid genesis signature");
            assert_eq!(INITIAL_REGISTRY_VERSION, verified_registry.version);
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
