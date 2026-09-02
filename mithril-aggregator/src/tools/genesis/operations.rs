use std::{
    fs::File,
    io::{Write, prelude::*},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, anyhow};
use slog::Logger;

use mithril_common::{
    CardanoNetwork, StdResult,
    certificate_chain::{
        CertificateGenesisProducer, CertificateVerifier, MithrilCertificateVerifier,
    },
    crypto_helper::{
        GenesisEd25519Signature, GenesisEd25519Signer, GenesisSigner, GenesisVerifier,
        ProtocolAggregateVerificationKey,
    },
    entities::{CertificateSignature, Epoch, ProtocolParameters, SupportedEra},
    protocol::SignerBuilder,
};

#[cfg(feature = "future_snark")]
use crate::tools::GenesisSignedPayload;
use crate::{
    database::repository::CertificateRepository,
    dependency_injection::GenesisCommandDependenciesContainer,
};
#[cfg(feature = "future_snark")]
use mithril_common::crypto_helper::{
    CircuitVerificationKeyDigest, CircuitVerificationKeyEntry, CircuitVerificationKeyRegistry,
    CircuitVerificationKeyStatus, GenesisBundleError, GenesisEd25519SecretKey,
    GenesisSchnorrSigner, GenesisSigningKeyBundle, GenesisVerificationKeyBundle,
    MINIMUM_REGISTRY_VERSION, ProtocolKey, SignedCircuitVerificationKeyRegistry, sha256_digest,
    signed_message_from_digest,
};

/// Configuration for the genesis tools.
pub struct GenesisToolsConfiguration {
    /// Cardano network.
    pub network: CardanoNetwork,

    /// Current epoch.
    pub epoch: Epoch,

    /// Aggregate verification key for the genesis stake distribution.
    pub genesis_avk: ProtocolAggregateVerificationKey,

    /// Protocol parameters for the genesis stake distribution.
    pub genesis_protocol_parameters: ProtocolParameters,

    /// Mithril era to use for the genesis certificate.
    pub mithril_era: SupportedEra,
}

/// Genesis tools for creating and managing genesis certificates.
pub struct GenesisTools {
    configuration: GenesisToolsConfiguration,
    certificate_repository: Arc<CertificateRepository>,
    logger: Logger,
}

impl GenesisTools {
    /// GenesisTools factory
    pub fn new(
        configuration: GenesisToolsConfiguration,
        certificate_repository: Arc<CertificateRepository>,
        logger: Logger,
    ) -> Self {
        Self {
            configuration,
            certificate_repository,
            logger,
        }
    }

    /// Build a certificate verifier that checks genesis certificates against the supplied genesis
    /// verifier.
    fn build_certificate_verifier(
        &self,
        genesis_verifier: &GenesisVerifier,
    ) -> MithrilCertificateVerifier {
        MithrilCertificateVerifier::new(
            self.logger.clone(),
            self.certificate_repository.clone(),
            Arc::new(genesis_verifier.clone()),
            #[cfg(feature = "future_snark")]
            None,
        )
    }

    pub async fn from_dependencies(
        dependencies: GenesisCommandDependenciesContainer,
    ) -> StdResult<Self> {
        let epoch = dependencies
            .chain_observer
            .get_current_epoch()
            .await?
            .with_context(|| "Chain observer can not retrieve current epoch")?;
        let certificate_repository = dependencies.certificate_repository.clone();
        let protocol_parameters_retriever = dependencies.protocol_parameters_retriever.clone();
        let genesis_avk_epoch = epoch.offset_to_next_signer_retrieval_epoch();
        let genesis_protocol_parameters = protocol_parameters_retriever
            .get_protocol_parameters(epoch.offset_to_signer_retrieval_epoch()?)
            .await?
            .with_context(|| {
                format!("Missing protocol parameters for epoch {genesis_avk_epoch}")
            })?;
        let genesis_signers = dependencies
            .verification_key_store
            .get_signers(genesis_avk_epoch)
            .await?
            .with_context(|| format!("Missing signers for epoch {genesis_avk_epoch}"))?;

        let protocol_multi_signer =
            SignerBuilder::new(&genesis_signers, &genesis_protocol_parameters)
                .with_context(|| "Could not build a multi signer to compute the genesis avk")?
                .build_multi_signer();
        let genesis_avk = protocol_multi_signer.compute_aggregate_verification_key();

        let configuration = GenesisToolsConfiguration {
            network: dependencies.network,
            epoch,
            genesis_avk,
            genesis_protocol_parameters,
            mithril_era: dependencies.mithril_era,
        };

        Ok(Self::new(
            configuration,
            certificate_repository,
            dependencies.logger,
        ))
    }

    /// Export AVK of the genesis stake distribution to a payload file.
    ///
    /// Pythagoras writes the canonical protocol-message hash bytes (hex string); Lagrange writes
    /// the rigid protocol-message preimage so the offline sign tool can produce both the legacy
    /// Ed25519 signature and the SNARK-friendly Schnorr signature.
    pub fn export_payload_to_sign(&self, target_path: &Path) -> StdResult<()> {
        let mut target_file = File::create(target_path)?;
        let genesis_producer = CertificateGenesisProducer::new().with_logger(self.logger.clone());
        let protocol_message = genesis_producer.create_genesis_protocol_message(
            &self.configuration.genesis_protocol_parameters,
            &self.configuration.genesis_avk,
            &self.configuration.epoch,
            self.configuration.mithril_era,
        )?;
        match self.configuration.mithril_era {
            #[cfg(feature = "future_snark")]
            SupportedEra::Lagrange => {
                target_file.write_all(&protocol_message.rigid_preimage())?;
            }
            _ => {
                target_file.write_all(protocol_message.compute_hash().as_bytes())?;
            }
        }
        Ok(())
    }

    /// Import a Pythagoras-era Ed25519 signed payload and persist the genesis certificate.
    pub async fn import_payload_signature(
        &self,
        signed_payload_path: &Path,
        genesis_verifier: &GenesisVerifier,
    ) -> StdResult<()> {
        let signed_payload_buffer = std::fs::read(signed_payload_path)?;
        let genesis_signature = GenesisEd25519Signature::from_bytes(&signed_payload_buffer)?;
        self.create_and_save_genesis_certificate(genesis_signature, genesis_verifier)
            .await
    }

    /// Import a Lagrange-era dual signed-payload envelope and persist the dual genesis certificate.
    ///
    /// Decodes the [`crate::tools::GenesisSignedPayload`] envelope, reconstructs the certificate
    /// from the pre-computed Ed25519 + Schnorr signatures, then verifies both the Ed25519
    /// (ed25519) and the Schnorr (SNARK) signatures against it before saving.
    #[cfg(feature = "future_snark")]
    pub async fn import_dual_payload_signature(
        &self,
        signed_payload_path: &Path,
        genesis_verifier: &GenesisVerifier,
    ) -> StdResult<()> {
        let signed_payload_buffer = std::fs::read(signed_payload_path)?;
        let envelope = GenesisSignedPayload::try_from_bytes(&signed_payload_buffer)?;
        let genesis_producer = CertificateGenesisProducer::new().with_logger(self.logger.clone());
        let certificate = genesis_producer.create_genesis_certificate(
            self.configuration.genesis_protocol_parameters.clone(),
            self.configuration.network,
            self.configuration.epoch,
            self.configuration.genesis_avk.clone(),
            envelope.ed25519,
            envelope.schnorr,
            SupportedEra::Lagrange,
        )?;
        self.build_certificate_verifier(genesis_verifier)
            .verify_genesis_certificate(&certificate)
            .await?;
        let digest = sha256_digest(&certificate.protocol_message.rigid_preimage());
        genesis_verifier.verify_schnorr(&digest, &envelope.schnorr)?;
        self.certificate_repository
            .create_certificate(certificate)
            .await
            .with_context(|| "Genesis tool can not save imported dual genesis certificate")?;
        Ok(())
    }

    /// Automatic bootstrap of the genesis certificate (test only).
    ///
    /// Pythagoras runs a single Ed25519 ceremony; Lagrange runs the dual ceremony and requires a
    /// dual signing key, erroring on a legacy single-Ed25519 key.
    pub async fn bootstrap_test_genesis_certificate(
        &self,
        genesis_signer: GenesisSigner,
    ) -> StdResult<()> {
        #[cfg(feature = "future_snark")]
        if matches!(self.configuration.mithril_era, SupportedEra::Lagrange)
            && genesis_signer.schnorr.is_none()
        {
            return Err(anyhow!(
                "Lagrange genesis bootstrap requires a dual signing key (Ed25519 + Schnorr), but the provided `GENESIS_SECRET_KEY` is a legacy single-Ed25519 key; generate a dual keypair with `mithril-aggregator genesis generate-keypair --mithril-era lagrange`"
            ));
        }
        let ed25519_verification_key = genesis_signer.ed25519.verification_key();
        #[cfg(feature = "future_snark")]
        let schnorr_verification_key =
            genesis_signer.schnorr.as_ref().map(|s| s.verification_key());
        let genesis_producer = CertificateGenesisProducer::new().with_logger(self.logger.clone());
        let genesis_protocol_message = genesis_producer.create_genesis_protocol_message(
            &self.configuration.genesis_protocol_parameters,
            &self.configuration.genesis_avk,
            &self.configuration.epoch,
            self.configuration.mithril_era,
        )?;
        let signature = genesis_signer
            .sign_non_deterministic(&genesis_protocol_message, self.configuration.mithril_era)?;
        let genesis_certificate = match signature {
            CertificateSignature::GenesisSignature(genesis_signature) => genesis_producer
                .create_legacy_genesis_certificate(
                    self.configuration.genesis_protocol_parameters.clone(),
                    self.configuration.network,
                    self.configuration.epoch,
                    self.configuration.genesis_avk.clone(),
                    genesis_signature,
                    self.configuration.mithril_era,
                )?,
            #[cfg(feature = "future_snark")]
            CertificateSignature::GenesisDualSignature(
                genesis_signature,
                genesis_signature_snark,
            ) => genesis_producer.create_genesis_certificate(
                self.configuration.genesis_protocol_parameters.clone(),
                self.configuration.network,
                self.configuration.epoch,
                self.configuration.genesis_avk.clone(),
                genesis_signature,
                genesis_signature_snark,
                self.configuration.mithril_era,
            )?,
            CertificateSignature::MultiSignature(..) => {
                unreachable!("the genesis signer never produces a multi-signature")
            }
        };
        #[cfg(not(feature = "future_snark"))]
        let genesis_verifier = GenesisVerifier::from_ed25519(ed25519_verification_key);
        #[cfg(feature = "future_snark")]
        let genesis_verifier = match schnorr_verification_key {
            Some(schnorr) => GenesisVerifier::from_bundle(GenesisVerificationKeyBundle::new(
                ed25519_verification_key,
                schnorr,
            )),
            None => GenesisVerifier::from_ed25519(ed25519_verification_key),
        };
        self.build_certificate_verifier(&genesis_verifier)
            .verify_genesis_certificate(&genesis_certificate)
            .await?;
        self.certificate_repository
            .create_certificate(genesis_certificate)
            .await
            .with_context(|| "Genesis tool can not save bootstrap genesis certificate")?;
        Ok(())
    }

    /// Sign the genesis certificate offline.
    ///
    /// Pythagoras signs the payload bytes with the ed25519 signer and writes the raw
    /// Ed25519 signature. Lagrange hashes the rigid preimage with SHA-256, signs the
    /// hex-encoded digest with the ed25519 signer (matching the `signed_message` bytes),
    /// signs the raw digest with the SNARK signer, and writes a versioned dual-signature
    /// envelope ([`crate::tools::GenesisSignedPayload`]).
    pub async fn sign_genesis_certificate(
        to_sign_payload_path: &Path,
        target_signed_payload_path: &Path,
        genesis_secret_key_path: &Path,
        mithril_era: SupportedEra,
    ) -> StdResult<()> {
        let genesis_signer = GenesisSigner::read_from_file(genesis_secret_key_path)?;

        let mut to_sign_payload_file = File::open(to_sign_payload_path)?;
        let mut to_sign_payload_buffer = Vec::new();
        to_sign_payload_file.read_to_end(&mut to_sign_payload_buffer)?;

        let signed_payload = match mithril_era {
            #[cfg(feature = "future_snark")]
            SupportedEra::Lagrange => {
                let digest = sha256_digest(&to_sign_payload_buffer);
                let signed_message = signed_message_from_digest(&digest);
                let ed25519 = genesis_signer.ed25519.sign(signed_message.as_bytes());
                let schnorr = genesis_signer
                    .schnorr
                    .as_ref()
                    .ok_or(GenesisBundleError::LegacySigningKey)?
                    .sign_non_deterministic(&digest)?;
                GenesisSignedPayload::new(ed25519, schnorr).to_bytes()?
            }
            _ => genesis_signer
                .ed25519
                .sign(&to_sign_payload_buffer)
                .to_bytes()
                .to_vec(),
        };

        let mut target_signed_payload_file = File::create(target_signed_payload_path)?;
        target_signed_payload_file.write_all(&signed_payload)?;

        Ok(())
    }

    /// Create and sign the circuit verification key registry whitelisting the production circuit
    /// keys from epoch 0, and write the signed registry JSON. For test only.
    #[cfg(feature = "future_snark")]
    pub fn bootstrap_circuit_verification_key_registry(
        genesis_secret_key: &str,
        target_registry_path: &Path,
    ) -> StdResult<()> {
        let genesis_signer = GenesisSigner::try_from_hex(genesis_secret_key)
            .with_context(|| "hex decode of genesis secret key failure")?;
        let (certificate_circuit_digest, ivc_circuit_digest) =
            CircuitVerificationKeyDigest::compute_for_production_circuits();
        let registry = CircuitVerificationKeyRegistry {
            version: 1,
            entries: vec![
                Self::allowed_circuit_key_entry(certificate_circuit_digest, "certificate-circuit"),
                Self::allowed_circuit_key_entry(ivc_circuit_digest, "ivc-circuit"),
            ],
        };

        let signed_registry =
            SignedCircuitVerificationKeyRegistry::try_new(registry, &genesis_signer)?;
        signed_registry
            .verify(&genesis_signer.create_verifier())
            .with_context(|| "The produced registry signature does not verify")?;

        std::fs::write(
            target_registry_path,
            serde_json::to_string_pretty(&signed_registry)?,
        )
        .with_context(|| {
            format!(
                "Failed to write signed registry file at '{}'",
                target_registry_path.display()
            )
        })?;

        Ok(())
    }

    /// Check that a registry is well formed before signing it: the version reaches the minimum
    /// accepted by the nodes, and no entry has an inverted epoch range (which would silently
    /// never match).
    #[cfg(feature = "future_snark")]
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

    /// Build a registry entry allowing the given circuit verification key digest from epoch 0.
    #[cfg(feature = "future_snark")]
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

    /// Sign a circuit verification key registry with the Ed25519 half of the genesis signing key
    /// and write the signed registry JSON, after verifying the produced signature.
    #[cfg(feature = "future_snark")]
    pub fn sign_circuit_verification_key_registry(
        to_sign_registry_path: &Path,
        target_signed_registry_path: &Path,
        genesis_secret_key_path: &Path,
    ) -> StdResult<()> {
        let genesis_signer = GenesisSigner::read_from_file(genesis_secret_key_path)?;

        let registry_json = std::fs::read_to_string(to_sign_registry_path).with_context(|| {
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

        let signed_registry =
            SignedCircuitVerificationKeyRegistry::try_new(registry, &genesis_signer)?;
        signed_registry
            .verify(&genesis_signer.create_verifier())
            .with_context(|| "The produced registry signature does not verify")?;

        std::fs::write(
            target_signed_registry_path,
            serde_json::to_string_pretty(&signed_registry)?,
        )
        .with_context(|| {
            format!(
                "Failed to write signed registry file at '{}'",
                target_signed_registry_path.display()
            )
        })?;

        Ok(())
    }

    async fn create_and_save_genesis_certificate(
        &self,
        genesis_signature: GenesisEd25519Signature,
        genesis_verifier: &GenesisVerifier,
    ) -> StdResult<()> {
        let genesis_producer = CertificateGenesisProducer::new().with_logger(self.logger.clone());
        let genesis_certificate = genesis_producer.create_legacy_genesis_certificate(
            self.configuration.genesis_protocol_parameters.clone(),
            self.configuration.network,
            self.configuration.epoch,
            self.configuration.genesis_avk.clone(),
            genesis_signature,
            self.configuration.mithril_era,
        )?;
        self.build_certificate_verifier(genesis_verifier)
            .verify_genesis_certificate(&genesis_certificate)
            .await?;
        self.certificate_repository
            .create_certificate(genesis_certificate.clone())
            .await
            .with_context(|| {
                format!(
                    "Genesis tool can not create certificate with genesis signature: '{genesis_signature:?}'"
                )
            })?;
        Ok(())
    }

    /// Export the genesis keypair to a folder and return the paths to the files (secret key, verification key).
    ///
    /// Pythagoras writes the legacy single-Ed25519 JSON-hex layout; Lagrange writes a dual signing
    /// bundle plus its matching verification bundle as bytes-hex.
    pub fn create_and_save_genesis_keypair(
        keypair_path: &Path,
        mithril_era: SupportedEra,
    ) -> StdResult<(PathBuf, PathBuf)> {
        let genesis_secret_key_path = keypair_path.join("genesis.sk");
        let genesis_verification_key_path = keypair_path.join("genesis.vk");
        match mithril_era {
            SupportedEra::Pythagoras => {
                let signer = GenesisEd25519Signer::create_non_deterministic_signer();
                signer.secret_key().write_json_hex_to_file(&genesis_secret_key_path)?;
                signer
                    .verification_key()
                    .write_json_hex_to_file(&genesis_verification_key_path)?;
            }
            #[cfg(feature = "future_snark")]
            SupportedEra::Lagrange => {
                let ed25519 = GenesisEd25519Signer::create_non_deterministic_signer();
                let schnorr = GenesisSchnorrSigner::create_non_deterministic_signer();

                let signing_bundle =
                    GenesisSigningKeyBundle::new(ed25519.secret_key(), schnorr.secret_key());
                let verification_bundle = GenesisVerificationKeyBundle::new(
                    ed25519.verification_key(),
                    schnorr.verification_key(),
                );

                std::fs::write(
                    &genesis_secret_key_path,
                    ProtocolKey::new(signing_bundle).to_bytes_hex()?,
                )?;
                std::fs::write(
                    &genesis_verification_key_path,
                    ProtocolKey::new(verification_bundle).to_bytes_hex()?,
                )?;
            }
            #[cfg(not(feature = "future_snark"))]
            SupportedEra::Lagrange => {
                return Err(anyhow!(
                    "Lagrange genesis keypair generation requires the 'future_snark' build feature"
                ));
            }
        }
        Ok((genesis_secret_key_path, genesis_verification_key_path))
    }

    /// Upgrade a legacy single-Ed25519 genesis keypair into a dual signing/verification bundle.
    ///
    /// Reads the legacy secret key, generates a fresh Schnorr keypair from the OS CSPRNG, and
    /// writes the two bundles to `<target-path>/genesis.sk` and `<target-path>/genesis.vk`. The
    /// existing legacy secret bytes are preserved as the ed25519 half of the dual bundle.
    ///
    /// Refuses to run if either target file already exists, to prevent accidentally overwriting
    /// an in-use genesis key.
    #[cfg(feature = "future_snark")]
    pub fn upgrade_legacy_keypair_to_dual(
        legacy_secret_key_path: &Path,
        target_path: &Path,
    ) -> StdResult<(PathBuf, PathBuf)> {
        let target_secret_key_path = target_path.join("genesis.sk");
        let target_verification_key_path = target_path.join("genesis.vk");
        for path in [&target_secret_key_path, &target_verification_key_path] {
            if path.exists() {
                return Err(anyhow!(
                    "refusing to overwrite existing genesis key file at {}; choose an empty target directory",
                    path.display()
                ));
            }
        }

        let legacy_secret_key =
            GenesisEd25519SecretKey::read_json_hex_from_file(legacy_secret_key_path)?;
        let legacy_signer = GenesisEd25519Signer::from_secret_key(legacy_secret_key);
        let schnorr_signer = GenesisSchnorrSigner::create_non_deterministic_signer();
        let signing_bundle =
            GenesisSigningKeyBundle::new(legacy_signer.secret_key(), schnorr_signer.secret_key());
        let verification_bundle = GenesisVerificationKeyBundle::new(
            legacy_signer.verification_key(),
            schnorr_signer.verification_key(),
        );

        std::fs::write(
            &target_secret_key_path,
            ProtocolKey::new(signing_bundle).to_bytes_hex()?,
        )?;
        std::fs::write(
            &target_verification_key_path,
            ProtocolKey::new(verification_bundle).to_bytes_hex()?,
        )?;

        Ok((target_secret_key_path, target_verification_key_path))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::read_to_string, path::PathBuf};

    #[cfg(feature = "future_snark")]
    use mithril_common::crypto_helper::{
        BUNDLE_FIRST_HEX_CHAR, GenesisSchnorrSigner, GenesisSigningKeyBundle,
    };
    #[cfg(feature = "future_snark")]
    use mithril_common::entities::Certificate;
    use mithril_common::{
        certificate_chain::MithrilCertificateVerifier,
        crypto_helper::{
            GenesisEd25519SecretKey, GenesisEd25519Signer, GenesisEd25519VerificationKey,
        },
        test::{TempDir, builder::MithrilFixtureBuilder, double::fake_data},
    };

    use crate::database::test_helper::main_db_connection;
    use crate::test::TestLogger;

    use super::*;

    fn get_temp_dir(dir_name: &str) -> PathBuf {
        TempDir::create("genesis", dir_name)
    }

    fn create_fake_genesis_avk() -> ProtocolAggregateVerificationKey {
        let fixture = MithrilFixtureBuilder::default().with_signers(5).build();

        fixture.compute_aggregate_verification_key()
    }

    #[cfg(not(feature = "future_snark"))]
    fn build_tools(
        genesis_signer: &GenesisEd25519Signer,
    ) -> (
        GenesisTools,
        Arc<CertificateRepository>,
        Arc<GenesisVerifier>,
        Arc<dyn CertificateVerifier>,
    ) {
        build_tools_for_era(genesis_signer, SupportedEra::Pythagoras)
    }

    fn build_tools_for_era(
        genesis_signer: &GenesisEd25519Signer,
        mithril_era: SupportedEra,
    ) -> (
        GenesisTools,
        Arc<CertificateRepository>,
        Arc<GenesisVerifier>,
        Arc<dyn CertificateVerifier>,
    ) {
        let connection = main_db_connection().unwrap();
        let certificate_store = Arc::new(CertificateRepository::new(Arc::new(connection)));
        let genesis_avk = create_fake_genesis_avk();
        let genesis_verifier = Arc::new(GenesisVerifier::from_ed25519(
            genesis_signer.verification_key(),
        ));
        let certificate_verifier = Arc::new(MithrilCertificateVerifier::new(
            TestLogger::stdout(),
            certificate_store.clone(),
            genesis_verifier.clone(),
            #[cfg(feature = "future_snark")]
            None,
        ));
        let configuration = GenesisToolsConfiguration {
            network: fake_data::network(),
            epoch: Epoch(10),
            genesis_avk,
            genesis_protocol_parameters: fake_data::protocol_parameters(),
            mithril_era,
        };
        let genesis_tools = GenesisTools::new(
            configuration,
            certificate_store.clone(),
            TestLogger::stdout(),
        );

        (
            genesis_tools,
            certificate_store,
            genesis_verifier,
            certificate_verifier,
        )
    }

    #[cfg(not(feature = "future_snark"))]
    #[tokio::test]
    async fn export_sign_then_import_genesis_payload() {
        let test_dir = get_temp_dir("export_payload_to_sign");
        let payload_path = test_dir.join("payload.txt");
        let signed_payload_path = test_dir.join("payload-signed.txt");
        let (genesis_secret_key_path, _) =
            GenesisTools::create_and_save_genesis_keypair(&test_dir, SupportedEra::Pythagoras)
                .expect("exporting the keypair should not fail");
        let genesis_secret_key = GenesisEd25519SecretKey::from_json_hex(
            &read_to_string(&genesis_secret_key_path)
                .expect("reading genesis secret key file should not fail"),
        )
        .expect("parsing genesis secret key should not fail");
        let genesis_signer = GenesisEd25519Signer::from_secret_key(genesis_secret_key);
        let (genesis_tools, certificate_store, genesis_verifier, certificate_verifier) =
            build_tools(&genesis_signer);

        genesis_tools
            .export_payload_to_sign(&payload_path)
            .expect("export_payload_to_sign should not fail");
        GenesisTools::sign_genesis_certificate(
            &payload_path,
            &signed_payload_path,
            &genesis_secret_key_path,
            SupportedEra::Pythagoras,
        )
        .await
        .expect("sign_genesis_certificate should not fail");
        genesis_tools
            .import_payload_signature(&signed_payload_path, &genesis_verifier)
            .await
            .expect("import_payload_signature should not fail");

        let last_certificates = certificate_store.get_latest_certificates(10).await.unwrap();

        assert_eq!(1, last_certificates.len());
        certificate_verifier
            .verify_genesis_certificate(&last_certificates[0])
            .await
            .expect(
                "verify_genesis_certificate should successfully validate the genesis certificate",
            );
    }

    #[cfg(not(feature = "future_snark"))]
    #[tokio::test]
    async fn bootstrap_test_genesis_certificate_works() {
        let ed25519_signer = GenesisEd25519Signer::create_deterministic_signer();
        let (genesis_tools, certificate_store, _genesis_verifier, certificate_verifier) =
            build_tools(&ed25519_signer);

        genesis_tools
            .bootstrap_test_genesis_certificate(GenesisSigner::from_ed25519(ed25519_signer))
            .await
            .expect("bootstrap test genesis certificate should not fail");

        let last_certificates = certificate_store.get_latest_certificates(10).await.unwrap();

        assert_eq!(1, last_certificates.len());
        certificate_verifier
            .verify_genesis_certificate(&last_certificates[0])
            .await
            .expect(
                "verify_genesis_certificate should successfully validate the genesis certificate",
            );
    }

    #[test]
    fn create_and_save_genesis_keypair_pythagoras() {
        let temp_dir = get_temp_dir("create_and_save_genesis_keypair_pythagoras");
        let (genesis_secret_key_path, genesis_verification_key_path) =
            GenesisTools::create_and_save_genesis_keypair(&temp_dir, SupportedEra::Pythagoras)
                .expect("Failed to create and save genesis keypair");
        let genesis_secret_key = GenesisEd25519SecretKey::from_json_hex(
            &read_to_string(&genesis_secret_key_path)
                .expect("Failed to read genesis secret key file"),
        )
        .expect("Failed to parse genesis secret key");
        let genesis_verification_key = GenesisEd25519VerificationKey::from_json_hex(
            &read_to_string(&genesis_verification_key_path)
                .expect("Failed to read genesis verification key file"),
        )
        .expect("Failed to parse genesis verification key");
        let genesis_verifier =
            GenesisEd25519Signer::from_secret_key(genesis_secret_key).create_verifier();

        let expected_genesis_verification_key = genesis_verifier.to_verification_key();
        assert_eq!(expected_genesis_verification_key, genesis_verification_key);
    }

    #[cfg(feature = "future_snark")]
    #[test]
    fn create_and_save_genesis_keypair_lagrange() {
        let temp_dir = get_temp_dir("create_and_save_genesis_keypair_lagrange");
        let (genesis_secret_key_path, genesis_verification_key_path) =
            GenesisTools::create_and_save_genesis_keypair(&temp_dir, SupportedEra::Lagrange)
                .expect("Failed to create and save genesis keypair");

        let signing_hex = read_to_string(&genesis_secret_key_path).unwrap();
        let verification_hex = read_to_string(&genesis_verification_key_path).unwrap();

        assert_eq!(signing_hex.as_bytes()[0], BUNDLE_FIRST_HEX_CHAR);
        assert_eq!(verification_hex.as_bytes()[0], BUNDLE_FIRST_HEX_CHAR);

        let signing_bundle = GenesisSigningKeyBundle::try_from_hex(&signing_hex)
            .expect("signing bundle hex must round-trip");
        let verification_bundle = GenesisVerificationKeyBundle::try_from_hex(&verification_hex)
            .expect("verification bundle hex must round-trip");
        let expected_schnorr_verification_key =
            GenesisSchnorrSigner::from_secret_key(signing_bundle.schnorr).verification_key();

        assert_eq!(
            verification_bundle.schnorr.to_bytes(),
            expected_schnorr_verification_key.to_bytes()
        );
    }

    #[cfg(feature = "future_snark")]
    mod bootstrap {
        use mithril_common::crypto_helper::{GenesisSchnorrSigner, GenesisSigningKeyBundle};

        use super::*;

        fn build_dual_signer() -> (GenesisEd25519Signer, GenesisSigner) {
            let ed25519 = GenesisEd25519Signer::create_deterministic_signer();
            let schnorr = GenesisSchnorrSigner::create_non_deterministic_signer();
            let bundle = GenesisSigningKeyBundle::new(ed25519.secret_key(), schnorr.secret_key());
            (ed25519.clone(), GenesisSigner::from_bundle(bundle))
        }

        #[tokio::test]
        async fn pythagoras_accepts_dual_signing_bundle() {
            let (ed25519_signer, signer) = build_dual_signer();
            let (genesis_tools, certificate_store, _genesis_verifier, certificate_verifier) =
                build_tools_for_era(&ed25519_signer, SupportedEra::Pythagoras);
            genesis_tools
                .bootstrap_test_genesis_certificate(signer)
                .await
                .expect("Pythagoras must accept a dual bundle");

            let last = certificate_store.get_latest_certificates(10).await.unwrap();
            assert_eq!(1, last.len());
            certificate_verifier
                .verify_genesis_certificate(&last[0])
                .await
                .expect("Ed25519 verification must pass");
        }

        #[tokio::test]
        async fn lagrange_runs_dual_ceremony() {
            let (ed25519_signer, signer) = build_dual_signer();
            let (genesis_tools, certificate_store, _genesis_verifier, certificate_verifier) =
                build_tools_for_era(&ed25519_signer, SupportedEra::Lagrange);
            genesis_tools
                .bootstrap_test_genesis_certificate(signer)
                .await
                .expect("Lagrange dual bootstrap must succeed");

            let last = certificate_store.get_latest_certificates(10).await.unwrap();
            assert_eq!(1, last.len());
            certificate_verifier
                .verify_genesis_certificate(&last[0])
                .await
                .expect("Ed25519 verification must pass on the dual variant");
        }

        #[tokio::test]
        async fn lagrange_rejects_a_legacy_signer() {
            let ed25519_signer = GenesisEd25519Signer::create_deterministic_signer();
            let (genesis_tools, certificate_store, _, _) =
                build_tools_for_era(&ed25519_signer, SupportedEra::Lagrange);

            genesis_tools
                .bootstrap_test_genesis_certificate(GenesisSigner::from_ed25519(ed25519_signer))
                .await
                .expect_err("Lagrange bootstrap must reject a legacy single-Ed25519 signer");

            let last: Vec<Certificate> =
                certificate_store.get_latest_certificates(10).await.unwrap();
            assert!(last.is_empty());
        }
    }

    #[cfg(feature = "future_snark")]
    mod sign {
        use std::fs;

        use mithril_common::crypto_helper::{
            GenesisSchnorrVerifier, GenesisSigner, sha256_digest, signed_message_from_digest,
        };

        use crate::tools::GenesisSignedPayload;

        use super::*;

        fn write_signing_key(target_dir: &Path, era: SupportedEra) -> PathBuf {
            let (signing_key_path, _) =
                GenesisTools::create_and_save_genesis_keypair(target_dir, era)
                    .expect("keypair generation should not fail");
            signing_key_path
        }

        #[tokio::test]
        async fn lagrange_writes_dual_envelope_that_verifies_both_signatures() {
            let temp = get_temp_dir("lagrange_sign_writes_envelope");
            let preimage_path = temp.join("preimage.bin");
            let signed_path = temp.join("signed.bin");
            let signing_key_path = write_signing_key(&temp, SupportedEra::Lagrange);

            let preimage = vec![0x42u8; 190];
            fs::write(&preimage_path, &preimage).unwrap();

            GenesisTools::sign_genesis_certificate(
                &preimage_path,
                &signed_path,
                &signing_key_path,
                SupportedEra::Lagrange,
            )
            .await
            .expect("Lagrange sign should not fail");

            let envelope_bytes = fs::read(&signed_path).unwrap();
            let envelope = GenesisSignedPayload::try_from_bytes(&envelope_bytes)
                .expect("envelope must round-trip");

            let signer = GenesisSigner::read_from_file(&signing_key_path).unwrap();
            let digest = sha256_digest(&preimage);
            signer
                .ed25519
                .create_verifier()
                .verify(
                    signed_message_from_digest(&digest).as_bytes(),
                    &envelope.ed25519,
                )
                .expect("Ed25519 signature must verify");
            GenesisSchnorrVerifier::from_verification_key(
                signer.schnorr.as_ref().unwrap().verification_key(),
            )
            .verify(&digest, &envelope.schnorr)
            .expect("Schnorr signature must verify");
        }

        #[tokio::test]
        async fn lagrange_rejects_legacy_signing_key() {
            let temp = get_temp_dir("lagrange_sign_rejects_legacy_key");
            let preimage_path = temp.join("preimage.bin");
            let signed_path = temp.join("signed.bin");
            let signing_key_path = write_signing_key(&temp, SupportedEra::Pythagoras);
            fs::write(&preimage_path, vec![0xAAu8; 190]).unwrap();

            let error = GenesisTools::sign_genesis_certificate(
                &preimage_path,
                &signed_path,
                &signing_key_path,
                SupportedEra::Lagrange,
            )
            .await
            .unwrap_err();

            assert!(matches!(
                error.downcast_ref::<mithril_common::crypto_helper::GenesisBundleError>(),
                Some(mithril_common::crypto_helper::GenesisBundleError::LegacySigningKey)
            ));
        }

        #[tokio::test]
        async fn pythagoras_accepts_dual_signing_bundle() {
            let temp = get_temp_dir("pythagoras_sign_accepts_dual_bundle");
            let payload_path = temp.join("payload.txt");
            let signed_path = temp.join("signed.bin");
            let signing_key_path = write_signing_key(&temp, SupportedEra::Lagrange);

            let payload = b"protocol-message-hash";
            fs::write(&payload_path, payload).unwrap();

            GenesisTools::sign_genesis_certificate(
                &payload_path,
                &signed_path,
                &signing_key_path,
                SupportedEra::Pythagoras,
            )
            .await
            .expect("Pythagoras sign with a dual bundle should succeed");

            let signature_bytes = fs::read(&signed_path).unwrap();
            assert_eq!(signature_bytes.len(), 64);

            let signer = GenesisSigner::read_from_file(&signing_key_path).unwrap();
            let signature = GenesisEd25519Signature::from_bytes(&signature_bytes).unwrap();
            signer
                .ed25519
                .create_verifier()
                .verify(payload, &signature)
                .expect("Ed25519 signature must verify");
        }
    }

    #[cfg(feature = "future_snark")]
    mod import {
        use std::fs;

        use mithril_common::crypto_helper::{
            GenesisSchnorrSigner, GenesisSigningKeyBundle, GenesisVerificationKeyBundle,
        };

        use super::*;

        #[tokio::test]
        async fn lagrange_round_trip_through_dual_envelope() {
            let temp = get_temp_dir("import_lagrange_round_trip");
            let preimage_path = temp.join("preimage.bin");
            let signed_path = temp.join("signed.bin");

            let ed25519_signer = GenesisEd25519Signer::create_deterministic_signer();
            let schnorr_signer = GenesisSchnorrSigner::create_non_deterministic_signer();
            let bundle = GenesisVerificationKeyBundle::new(
                ed25519_signer.verification_key(),
                schnorr_signer.verification_key(),
            );
            let signer = GenesisSigner::from_bundle(GenesisSigningKeyBundle::new(
                ed25519_signer.secret_key(),
                schnorr_signer.secret_key(),
            ));
            let signing_key_path = temp.join("genesis.sk");
            signer.write_to_file(&signing_key_path).unwrap();

            let (genesis_tools, certificate_store, _, _) =
                build_tools_for_era(&ed25519_signer, SupportedEra::Lagrange);

            genesis_tools
                .export_payload_to_sign(&preimage_path)
                .expect("export should not fail");
            let preimage_bytes = fs::read(&preimage_path).unwrap();
            assert_eq!(preimage_bytes.len(), 190);

            GenesisTools::sign_genesis_certificate(
                &preimage_path,
                &signed_path,
                &signing_key_path,
                SupportedEra::Lagrange,
            )
            .await
            .expect("sign should not fail");

            genesis_tools
                .import_dual_payload_signature(&signed_path, &GenesisVerifier::from_bundle(bundle))
                .await
                .expect("import should not fail");

            let last: Vec<Certificate> =
                certificate_store.get_latest_certificates(10).await.unwrap();
            assert_eq!(1, last.len());
        }

        #[tokio::test]
        async fn lagrange_rejects_tampered_schnorr_signature() {
            let temp = get_temp_dir("import_lagrange_rejects_tampered_schnorr");
            let preimage_path = temp.join("preimage.bin");
            let signed_path = temp.join("signed.bin");

            let ed25519_signer = GenesisEd25519Signer::create_deterministic_signer();
            let schnorr_signer = GenesisSchnorrSigner::create_non_deterministic_signer();
            let signer = GenesisSigner::from_bundle(GenesisSigningKeyBundle::new(
                ed25519_signer.secret_key(),
                schnorr_signer.secret_key(),
            ));
            let signing_key_path = temp.join("genesis.sk");
            signer.write_to_file(&signing_key_path).unwrap();

            let (genesis_tools, certificate_store, _, _) =
                build_tools_for_era(&ed25519_signer, SupportedEra::Lagrange);

            genesis_tools
                .export_payload_to_sign(&preimage_path)
                .expect("export should not fail");
            GenesisTools::sign_genesis_certificate(
                &preimage_path,
                &signed_path,
                &signing_key_path,
                SupportedEra::Lagrange,
            )
            .await
            .expect("sign should not fail");

            let mismatched_schnorr_signer = GenesisSchnorrSigner::create_non_deterministic_signer();
            let tampered_bundle = GenesisVerificationKeyBundle::new(
                ed25519_signer.verification_key(),
                mismatched_schnorr_signer.verification_key(),
            );

            let error = genesis_tools
                .import_dual_payload_signature(
                    &signed_path,
                    &GenesisVerifier::from_bundle(tampered_bundle),
                )
                .await
                .unwrap_err();

            assert!(
                format!("{error:?}").contains("SNARK genesis verifier failed"),
                "expected a SNARK verification failure, got: {error:?}"
            );
            let saved: Vec<Certificate> =
                certificate_store.get_latest_certificates(10).await.unwrap();
            assert!(
                saved.is_empty(),
                "no certificate must be saved when the SNARK signature is invalid"
            );
        }
    }

    #[cfg(feature = "future_snark")]
    mod upgrade_key_to_dual {
        use std::fs;

        use mithril_common::crypto_helper::{
            BUNDLE_FIRST_HEX_CHAR, GenesisSchnorrSigner, GenesisSigningKeyBundle,
            GenesisVerificationKeyBundle, LEGACY_FIRST_HEX_CHAR,
        };

        use super::*;

        fn write_legacy_secret_key(target_dir: &Path) -> (PathBuf, GenesisEd25519Signer) {
            let signer = GenesisEd25519Signer::create_non_deterministic_signer();
            let path = target_dir.join("genesis.sk");
            signer.secret_key().write_json_hex_to_file(&path).unwrap();
            (path, signer)
        }

        #[test]
        fn upgrade_preserves_ed25519_half() {
            let temp = get_temp_dir("upgrade_preserves_ed25519_half");
            let target = temp.join("out");
            fs::create_dir_all(&target).unwrap();
            let (legacy_path, legacy_signer) = write_legacy_secret_key(&temp);

            let (signing_key_path, verification_key_path) =
                GenesisTools::upgrade_legacy_keypair_to_dual(&legacy_path, &target)
                    .expect("upgrade should not fail");

            let signing_hex = fs::read_to_string(&signing_key_path).unwrap();
            let verification_hex = fs::read_to_string(&verification_key_path).unwrap();
            assert_eq!(signing_hex.as_bytes()[0], BUNDLE_FIRST_HEX_CHAR);
            assert_eq!(verification_hex.as_bytes()[0], BUNDLE_FIRST_HEX_CHAR);

            let signing_bundle = GenesisSigningKeyBundle::try_from_hex(&signing_hex).unwrap();
            let verification_bundle =
                GenesisVerificationKeyBundle::try_from_hex(&verification_hex).unwrap();

            assert_eq!(
                signing_bundle.ed25519.to_bytes(),
                legacy_signer.secret_key().to_bytes()
            );
            assert_eq!(
                verification_bundle.ed25519.as_bytes(),
                legacy_signer.verification_key().as_bytes()
            );
            let derived_schnorr_vk =
                GenesisSchnorrSigner::from_secret_key(signing_bundle.schnorr).verification_key();
            assert_eq!(
                verification_bundle.schnorr.to_bytes(),
                derived_schnorr_vk.to_bytes()
            );
        }

        #[test]
        fn two_consecutive_upgrades_produce_distinct_schnorr_secrets() {
            let temp = get_temp_dir("upgrade_schnorr_rng_distinct_outputs");
            let target_a = temp.join("a");
            let target_b = temp.join("b");
            fs::create_dir_all(&target_a).unwrap();
            fs::create_dir_all(&target_b).unwrap();
            let (legacy_path, _) = write_legacy_secret_key(&temp);

            let (sk_a, _) =
                GenesisTools::upgrade_legacy_keypair_to_dual(&legacy_path, &target_a).unwrap();
            let (sk_b, _) =
                GenesisTools::upgrade_legacy_keypair_to_dual(&legacy_path, &target_b).unwrap();

            let bundle_a =
                GenesisSigningKeyBundle::try_from_hex(&fs::read_to_string(&sk_a).unwrap()).unwrap();
            let bundle_b =
                GenesisSigningKeyBundle::try_from_hex(&fs::read_to_string(&sk_b).unwrap()).unwrap();
            assert_ne!(bundle_a.schnorr.to_bytes(), bundle_b.schnorr.to_bytes());
        }

        #[test]
        fn upgrade_does_not_create_any_certificate() {
            let temp = get_temp_dir("upgrade_writes_only_two_files");
            let target = temp.join("out");
            fs::create_dir_all(&target).unwrap();
            let (legacy_path, _) = write_legacy_secret_key(&temp);

            GenesisTools::upgrade_legacy_keypair_to_dual(&legacy_path, &target).unwrap();

            let entries: Vec<_> = fs::read_dir(&target).unwrap().collect();
            assert_eq!(entries.len(), 2);
        }

        #[test]
        fn legacy_input_is_recognised_as_legacy_format() {
            let temp = get_temp_dir("upgrade_legacy_input_first_char");
            let (legacy_path, _) = write_legacy_secret_key(&temp);

            let legacy_hex = fs::read_to_string(&legacy_path).unwrap();
            assert_eq!(legacy_hex.as_bytes()[0], LEGACY_FIRST_HEX_CHAR);
        }

        #[test]
        fn upgrade_refuses_to_overwrite_existing_target_files() {
            let temp = get_temp_dir("upgrade_refuses_overwrite");
            let target = temp.join("out");
            fs::create_dir_all(&target).unwrap();
            let (legacy_path, _) = write_legacy_secret_key(&temp);

            GenesisTools::upgrade_legacy_keypair_to_dual(&legacy_path, &target)
                .expect("first upgrade should succeed");

            let error = GenesisTools::upgrade_legacy_keypair_to_dual(&legacy_path, &target)
                .expect_err("second upgrade must refuse to overwrite");
            assert!(
                error.to_string().contains("refusing to overwrite"),
                "unexpected error: {error}"
            );
        }

        #[test]
        fn upgrade_preserves_signature_compatibility_with_original_legacy_key() {
            use mithril_common::crypto_helper::GenesisEd25519Verifier;

            let temp = get_temp_dir("upgrade_signature_compatibility");
            let target = temp.join("out");
            fs::create_dir_all(&target).unwrap();
            let (legacy_path, legacy_signer) = write_legacy_secret_key(&temp);

            let (signing_key_path, verification_key_path) =
                GenesisTools::upgrade_legacy_keypair_to_dual(&legacy_path, &target)
                    .expect("upgrade should not fail");

            let payload = b"upgrade-key-drift-canary";
            let legacy_signature = legacy_signer.sign(payload);

            let upgraded_verification_bundle = GenesisVerificationKeyBundle::try_from_hex(
                &fs::read_to_string(&verification_key_path).unwrap(),
            )
            .unwrap();
            GenesisEd25519Verifier::from_verification_key(
                upgraded_verification_bundle.ed25519,
            )
            .verify(payload, &legacy_signature)
            .expect(
                "upgraded verification key must verify a signature produced by the original legacy signing key",
            );

            let upgraded_signing_bundle = GenesisSigningKeyBundle::try_from_hex(
                &fs::read_to_string(&signing_key_path).unwrap(),
            )
            .unwrap();
            let upgraded_signer =
                GenesisEd25519Signer::from_secret_key(upgraded_signing_bundle.ed25519);
            let upgraded_signature = upgraded_signer.sign(payload);
            legacy_signer
                .create_verifier()
                .verify(payload, &upgraded_signature)
                .expect(
                    "original verification key must verify a signature produced by the upgraded signing key",
                );
        }
    }

    #[cfg(feature = "future_snark")]
    mod bootstrap_circuit_verification_key_registry {
        use super::*;

        #[test]
        fn bootstraps_a_verifiable_registry_whitelisting_the_production_circuit_keys() {
            let temp_dir = get_temp_dir("bootstrap_circuit_verification_key_registry");
            let genesis_secret_key_hex = GenesisEd25519Signer::create_deterministic_signer()
                .secret_key()
                .to_json_hex()
                .unwrap();
            let target_registry_path = temp_dir.join("registry.json");

            GenesisTools::bootstrap_circuit_verification_key_registry(
                &genesis_secret_key_hex,
                &target_registry_path,
            )
            .unwrap();

            let signed_registry: SignedCircuitVerificationKeyRegistry =
                serde_json::from_str(&read_to_string(&target_registry_path).unwrap()).unwrap();
            let (certificate_circuit_digest, ivc_circuit_digest) =
                CircuitVerificationKeyDigest::compute_for_production_circuits();
            let verified_registry = signed_registry
                .verify(
                    &GenesisSigner::from_ed25519(
                        GenesisEd25519Signer::create_deterministic_signer(),
                    )
                    .create_verifier(),
                )
                .expect("the bootstrapped registry must carry a valid genesis signature");
            assert_eq!(1, verified_registry.version);
            assert_eq!(
                vec![certificate_circuit_digest, ivc_circuit_digest],
                verified_registry
                    .entries
                    .iter()
                    .map(|entry| entry.digest)
                    .collect::<Vec<_>>()
            );
        }
    }

    #[cfg(feature = "future_snark")]
    mod sign_circuit_verification_key_registry {
        use super::*;

        fn write_genesis_secret_key(temp_dir: &Path) -> (PathBuf, GenesisSigner) {
            let genesis_signer = GenesisSigner::create_deterministic_signer();
            let genesis_secret_key_path = temp_dir.join("genesis.sk");
            genesis_signer.write_to_file(&genesis_secret_key_path).unwrap();

            (genesis_secret_key_path, genesis_signer)
        }

        #[test]
        fn signs_a_registry_and_writes_a_verifiable_signed_registry() {
            let temp_dir = get_temp_dir("sign_circuit_verification_key_registry");
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

            GenesisTools::sign_circuit_verification_key_registry(
                &to_sign_registry_path,
                &target_signed_registry_path,
                &genesis_secret_key_path,
            )
            .unwrap();

            let signed_registry: SignedCircuitVerificationKeyRegistry =
                serde_json::from_str(&read_to_string(&target_signed_registry_path).unwrap())
                    .unwrap();
            let verified_registry = signed_registry
                .verify(&genesis_signer.create_verifier())
                .expect("the written signed registry must carry a valid genesis signature");
            assert_eq!(registry, verified_registry);
        }

        #[test]
        fn fails_on_a_registry_with_an_inverted_epoch_range() {
            let temp_dir = get_temp_dir("sign_circuit_verification_key_registry_inverted");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let registry = CircuitVerificationKeyRegistry {
                version: 1,
                entries: vec![CircuitVerificationKeyEntry {
                    digest: hex::encode([1u8; 32]).parse().unwrap(),
                    name: "circuit".to_string(),
                    status: CircuitVerificationKeyStatus::Allowed,
                    start_epoch: Epoch(20),
                    end_epoch: Some(Epoch(10)),
                    comment: None,
                }],
            };
            let to_sign_registry_path = temp_dir.join("registry.json");
            std::fs::write(
                &to_sign_registry_path,
                serde_json::to_string(&registry).unwrap(),
            )
            .unwrap();

            GenesisTools::sign_circuit_verification_key_registry(
                &to_sign_registry_path,
                &temp_dir.join("signed-registry.json"),
                &genesis_secret_key_path,
            )
            .expect_err("a registry with an inverted epoch range must fail signing");
        }

        #[test]
        fn fails_on_a_registry_version_below_the_minimum() {
            let temp_dir = get_temp_dir("sign_circuit_verification_key_registry_version");
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

            GenesisTools::sign_circuit_verification_key_registry(
                &to_sign_registry_path,
                &temp_dir.join("signed-registry.json"),
                &genesis_secret_key_path,
            )
            .expect_err("a registry version below the minimum must fail signing");
        }

        #[test]
        fn fails_on_an_invalid_registry_file() {
            let temp_dir = get_temp_dir("sign_circuit_verification_key_registry_invalid");
            let (genesis_secret_key_path, _) = write_genesis_secret_key(&temp_dir);
            let to_sign_registry_path = temp_dir.join("registry.json");
            std::fs::write(&to_sign_registry_path, "not a registry").unwrap();

            GenesisTools::sign_circuit_verification_key_registry(
                &to_sign_registry_path,
                &temp_dir.join("signed-registry.json"),
                &genesis_secret_key_path,
            )
            .expect_err("an invalid registry file must fail signing");
        }
    }
}
