use anyhow::Context;
use semver::Version;
use std::path::PathBuf;
use std::sync::Arc;

use mithril_common::crypto_helper::ManifestSigner;
use mithril_file_archiver::FileArchiver;

use crate::artifact_builder::{
    AncillaryArtifactBuilder, AncillaryFileUploader, CardanoBlocksTransactionsArtifactBuilder,
    CardanoDatabaseArtifactBuilder, CardanoStakeDistributionArtifactBuilder,
    CardanoTransactionsArtifactBuilder, DigestArtifactBuilder, DigestFileUploader,
    DigestSnapshotter, ImmutableArtifactBuilder, ImmutableFilesUploader,
    MithrilStakeDistributionArtifactBuilder,
};
use crate::configuration::AncillaryFilesSignerConfig;
use crate::dependency_injection::builder::SNAPSHOT_ARTIFACTS_DIR;
use crate::dependency_injection::{DependenciesBuilder, DependenciesBuilderError, Result};
use crate::file_uploaders::{
    CloudRemotePath, CloudUploader, FileUploadRetryPolicy, GCloudBackendUploader, IpfsUploader,
    LocalUploader,
};
use crate::get_dependency;
use crate::http_server::{CARDANO_DATABASE_DOWNLOAD_PATH, SNAPSHOT_DOWNLOAD_PATH};
use crate::services::ancillary_signer::{
    AncillarySigner, AncillarySignerWithGcpKms, AncillarySignerWithSecretKey,
};
use crate::services::{
    CompressedArchiveSnapshotter, DumbSnapshotter, MithrilSignedEntityService, SignedEntityService,
    SignedEntityServiceArtifactsDependencies, Snapshotter,
};
use crate::tools::DEFAULT_GCP_CREDENTIALS_JSON_ENV_VAR;
use crate::tools::kubo_rpc_client::{IpfsMfsDirPath, KuboRpcClient};
use crate::tools::url_sanitizer::SanitizedUrlWithTrailingSlash;
use crate::{DumbUploader, ExecutionEnvironment, FileUploader, SnapshotUploaderType};

impl DependenciesBuilder {
    async fn build_signed_entity_service(&mut self) -> Result<Arc<dyn SignedEntityService>> {
        let logger = self.root_logger();
        let signed_entity_storer = self.get_signed_entity_storer().await?;
        let epoch_service = self.get_epoch_service().await?;
        let mithril_stake_distribution_artifact_builder = Arc::new(
            MithrilStakeDistributionArtifactBuilder::new(epoch_service.clone()),
        );
        let cardano_node_version =
            self.configuration.parsed_cardano_node_version().map_err(|e| {
                DependenciesBuilderError::Initialization {
                    message: "Error while retrieving cardano node version".to_string(),
                    error: Some(e),
                }
            })?;
        let legacy_prover_service = self.get_legacy_prover_service().await?;
        let cardano_transactions_artifact_builder = Arc::new(
            CardanoTransactionsArtifactBuilder::new(legacy_prover_service.clone()),
        );
        let prover_service = self.get_prover_service().await?;
        let cardano_blocks_transactions_artifact_builder = Arc::new(
            CardanoBlocksTransactionsArtifactBuilder::new(prover_service.clone()),
        );
        let stake_store = self.get_stake_store().await?;
        let cardano_stake_distribution_artifact_builder =
            Arc::new(CardanoStakeDistributionArtifactBuilder::new(stake_store));
        let cardano_database_artifact_builder = Arc::new(
            self.build_cardano_database_artifact_builder(cardano_node_version)
                .await?,
        );
        let dependencies = SignedEntityServiceArtifactsDependencies::new(
            mithril_stake_distribution_artifact_builder,
            cardano_transactions_artifact_builder,
            cardano_blocks_transactions_artifact_builder,
            cardano_stake_distribution_artifact_builder,
            cardano_database_artifact_builder,
        );
        let signed_entity_service = Arc::new(MithrilSignedEntityService::new(
            signed_entity_storer,
            dependencies,
            self.get_signed_entity_type_lock().await?,
            self.get_metrics_service().await?,
            logger,
        ));

        // Compute the cache pool for prover service
        // This is done here to avoid circular dependencies between the prover service and the signed entity service
        // TODO: Make this part of a warmup phase of the aggregator?
        if let Some(signed_entity) =
            signed_entity_service.get_last_cardano_transaction_snapshot().await?
        {
            legacy_prover_service
                .compute_cache(signed_entity.artifact.block_number)
                .await?;
        }

        Ok(signed_entity_service)
    }

    /// [SignedEntityService] service
    pub async fn get_signed_entity_service(&mut self) -> Result<Arc<dyn SignedEntityService>> {
        get_dependency!(self.signed_entity_service)
    }

    async fn build_file_archiver(&mut self) -> Result<Arc<FileArchiver>> {
        let archive_verification_directory =
            std::env::temp_dir().join("mithril_archiver_verify_archive");
        let file_archiver = Arc::new(FileArchiver::new(
            self.configuration.zstandard_parameters().unwrap_or_default(),
            archive_verification_directory,
            self.root_logger(),
        ));

        Ok(file_archiver)
    }

    async fn get_file_archiver(&mut self) -> Result<Arc<FileArchiver>> {
        get_dependency!(self.file_archiver)
    }

    async fn get_ancillary_signer(&self) -> Result<Arc<dyn AncillarySigner>> {
        match &self.configuration.ancillary_files_signer_config() {
            AncillaryFilesSignerConfig::SecretKey { secret_key } => {
                let manifest_signer = ManifestSigner::from_secret_key(
                    secret_key
                        .as_str()
                        .try_into()
                        .with_context(|| "Failed to build ancillary signer: Invalid secret key")?,
                );

                Ok(Arc::new(AncillarySignerWithSecretKey::new(
                    manifest_signer,
                    self.root_logger(),
                )))
            }
            AncillaryFilesSignerConfig::GcpKms {
                resource_name,
                credentials_json_env_var,
            } => {
                let service = AncillarySignerWithGcpKms::new(
                    resource_name.clone(),
                    credentials_json_env_var.clone(),
                    self.root_logger(),
                )
                .await?;

                Ok(Arc::new(service))
            }
        }
    }

    async fn build_snapshotter(&mut self) -> Result<Arc<dyn Snapshotter>> {
        let snapshotter: Arc<dyn Snapshotter> = match self.configuration.environment() {
            ExecutionEnvironment::Production => {
                let ongoing_snapshot_directory =
                    self.configuration.get_snapshot_dir()?.join("pending_snapshot");

                Arc::new(CompressedArchiveSnapshotter::new(
                    self.configuration.parsed_cardano_node_version()?,
                    self.configuration.db_directory().clone(),
                    ongoing_snapshot_directory,
                    self.configuration.snapshot_compression_algorithm(),
                    self.get_file_archiver().await?,
                    self.get_ancillary_signer().await?,
                    self.root_logger(),
                )?)
            }
            _ => Arc::new(DumbSnapshotter::new(
                self.configuration.snapshot_compression_algorithm(),
            )),
        };

        Ok(snapshotter)
    }

    async fn build_digests_snapshotter(
        &mut self,
        digests_path: PathBuf,
    ) -> Result<DigestSnapshotter> {
        Ok(DigestSnapshotter {
            file_archiver: self.get_file_archiver().await?,
            target_location: digests_path,
            compression_algorithm: self.configuration.snapshot_compression_algorithm(),
        })
    }

    /// [Snapshotter] service.
    pub async fn get_snapshotter(&mut self) -> Result<Arc<dyn Snapshotter>> {
        get_dependency!(self.snapshotter)
    }

    async fn build_snapshot_uploader(&mut self) -> Result<Arc<dyn FileUploader>> {
        let logger = self.root_logger();
        if self.configuration.environment() == ExecutionEnvironment::Production {
            match self.configuration.snapshot_uploader_type() {
                SnapshotUploaderType::Gcp => {
                    let allow_overwrite = true;
                    let remote_folder_path = CloudRemotePath::new("cardano-immutable-files-full");

                    Ok(Arc::new(
                        self.build_gcp_uploader(remote_folder_path, allow_overwrite).await?,
                    ))
                }
                SnapshotUploaderType::Local => {
                    let server_url_prefix = self.configuration.get_server_url()?;
                    let snapshot_url_prefix =
                        server_url_prefix.sanitize_join(SNAPSHOT_DOWNLOAD_PATH)?;
                    let snapshot_artifacts_dir =
                        self.configuration.get_snapshot_dir()?.join(SNAPSHOT_ARTIFACTS_DIR);
                    std::fs::create_dir_all(&snapshot_artifacts_dir).map_err(|e| {
                        DependenciesBuilderError::Initialization {
                            message: format!(
                                "Cannot create '{snapshot_artifacts_dir:?}' directory."
                            ),
                            error: Some(e.into()),
                        }
                    })?;

                    Ok(Arc::new(LocalUploader::new(
                        snapshot_url_prefix,
                        &snapshot_artifacts_dir,
                        FileUploadRetryPolicy::default(),
                        logger,
                    )))
                }
            }
        } else {
            Ok(Arc::new(DumbUploader::new(FileUploadRetryPolicy::never())))
        }
    }

    /// Get a [FileUploader]
    pub async fn get_snapshot_uploader(&mut self) -> Result<Arc<dyn FileUploader>> {
        get_dependency!(self.snapshot_uploader)
    }

    async fn build_gcp_uploader(
        &self,
        remote_folder_path: CloudRemotePath,
        allow_overwrite: bool,
    ) -> Result<CloudUploader> {
        let logger = self.root_logger();
        let bucket = self.configuration.snapshot_bucket_name().to_owned().ok_or_else(|| {
            DependenciesBuilderError::MissingConfiguration("snapshot_bucket_name".to_string())
        })?;

        Ok(CloudUploader::new(
            Arc::new(
                GCloudBackendUploader::try_new(
                    bucket,
                    self.configuration.snapshot_use_cdn_domain(),
                    DEFAULT_GCP_CREDENTIALS_JSON_ENV_VAR.to_string(),
                    logger.clone(),
                )
                .await?,
            ),
            remote_folder_path,
            allow_overwrite,
            FileUploadRetryPolicy::default(),
        ))
    }

    async fn build_ipfs_uploader(
        &self,
        rpc_url: SanitizedUrlWithTrailingSlash,
    ) -> Result<IpfsUploader> {
        let rpc_api_client = KuboRpcClient::new(rpc_url, self.root_logger())?;
        Ok(IpfsUploader::new(
            Arc::new(rpc_api_client),
            IpfsMfsDirPath::from("/mithril"),
            &self.root_logger(),
        ))
    }

    async fn build_cardano_database_ancillary_uploaders(
        &self,
    ) -> Result<Vec<Arc<dyn AncillaryFileUploader>>> {
        let logger = self.root_logger();
        if self.configuration.environment() == ExecutionEnvironment::Production {
            match self.configuration.snapshot_uploader_type() {
                SnapshotUploaderType::Gcp => {
                    let allow_overwrite = true;
                    let remote_folder_path =
                        CloudRemotePath::new("cardano-database").join("ancillary");

                    Ok(vec![Arc::new(
                        self.build_gcp_uploader(remote_folder_path, allow_overwrite).await?,
                    )])
                }
                SnapshotUploaderType::Local => {
                    let server_url_prefix = self.configuration.get_server_url()?;
                    let ancillary_url_prefix = server_url_prefix
                        .sanitize_join(&format!("{CARDANO_DATABASE_DOWNLOAD_PATH}/ancillary/"))?;
                    let target_dir = self.get_cardano_db_artifacts_dir()?.join("ancillary");

                    std::fs::create_dir_all(&target_dir).map_err(|e| {
                        DependenciesBuilderError::Initialization {
                            message: format!("Cannot create '{target_dir:?}' directory."),
                            error: Some(e.into()),
                        }
                    })?;

                    Ok(vec![Arc::new(LocalUploader::new(
                        ancillary_url_prefix,
                        &target_dir,
                        FileUploadRetryPolicy::default(),
                        logger,
                    ))])
                }
            }
        } else {
            Ok(vec![Arc::new(DumbUploader::new(
                FileUploadRetryPolicy::never(),
            ))])
        }
    }

    async fn build_cardano_database_immutable_uploaders(
        &self,
    ) -> Result<Vec<Arc<dyn ImmutableFilesUploader>>> {
        let logger = self.root_logger();
        if self.configuration.environment() == ExecutionEnvironment::Production {
            let mut uploaders: Vec<Arc<dyn ImmutableFilesUploader>> =
                match self.configuration.snapshot_uploader_type() {
                    SnapshotUploaderType::Gcp => {
                        let allow_overwrite = false;
                        let remote_folder_path =
                            CloudRemotePath::new("cardano-database").join("immutable");

                        vec![Arc::new(
                            self.build_gcp_uploader(remote_folder_path, allow_overwrite).await?,
                        )]
                    }
                    SnapshotUploaderType::Local => {
                        let server_url_prefix = self.configuration.get_server_url()?;
                        let immutable_url_prefix = server_url_prefix.sanitize_join(&format!(
                            "{CARDANO_DATABASE_DOWNLOAD_PATH}/immutable/"
                        ))?;

                        vec![Arc::new(LocalUploader::new_without_copy(
                            immutable_url_prefix,
                            FileUploadRetryPolicy::default(),
                            logger,
                        ))]
                    }
                };

            if let Some(url) = self.configuration.get_ipfs_rpc_url()? {
                uploaders.push(Arc::new(self.build_ipfs_uploader(url).await?));
            }

            Ok(uploaders)
        } else {
            Ok(vec![Arc::new(DumbUploader::new(
                FileUploadRetryPolicy::never(),
            ))])
        }
    }

    async fn build_cardano_database_digests_uploaders(
        &self,
    ) -> Result<Vec<Arc<dyn DigestFileUploader>>> {
        let logger = self.root_logger();
        if self.configuration.environment() == ExecutionEnvironment::Production {
            match self.configuration.snapshot_uploader_type() {
                SnapshotUploaderType::Gcp => {
                    let allow_overwrite = false;
                    let remote_folder_path =
                        CloudRemotePath::new("cardano-database").join("digests");

                    Ok(vec![Arc::new(
                        self.build_gcp_uploader(remote_folder_path, allow_overwrite).await?,
                    )])
                }
                SnapshotUploaderType::Local => {
                    let server_url_prefix = self.configuration.get_server_url()?;
                    let digests_url_prefix = server_url_prefix
                        .sanitize_join(&format!("{CARDANO_DATABASE_DOWNLOAD_PATH}/digests/"))?;
                    let target_dir = self.get_cardano_db_artifacts_dir()?.join("digests");

                    std::fs::create_dir_all(&target_dir).map_err(|e| {
                        DependenciesBuilderError::Initialization {
                            message: format!("Cannot create '{target_dir:?}' directory."),
                            error: Some(e.into()),
                        }
                    })?;

                    Ok(vec![Arc::new(LocalUploader::new(
                        digests_url_prefix,
                        &target_dir,
                        FileUploadRetryPolicy::default(),
                        logger,
                    ))])
                }
            }
        } else {
            Ok(vec![Arc::new(DumbUploader::new(
                FileUploadRetryPolicy::never(),
            ))])
        }
    }

    async fn build_cardano_database_artifact_builder(
        &mut self,
        cardano_node_version: Version,
    ) -> Result<CardanoDatabaseArtifactBuilder> {
        let snapshot_dir = self.configuration.get_snapshot_dir()?;
        let immutable_dir = self.get_cardano_db_artifacts_dir()?.join("immutable");

        let ancillary_builder = Arc::new(AncillaryArtifactBuilder::new(
            self.build_cardano_database_ancillary_uploaders().await?,
            self.get_snapshotter().await?,
            self.configuration.get_network()?,
            self.root_logger(),
        )?);

        let immutable_builder = Arc::new(ImmutableArtifactBuilder::new(
            immutable_dir,
            self.build_cardano_database_immutable_uploaders().await?,
            self.get_snapshotter().await?,
            self.root_logger(),
        )?);

        let digests_path = snapshot_dir.join("pending_cardano_database_digests");
        let digests_snapshotter = self.build_digests_snapshotter(digests_path.clone()).await?;

        let digest_builder = Arc::new(DigestArtifactBuilder::new(
            self.configuration.get_server_url()?,
            self.build_cardano_database_digests_uploaders().await?,
            digests_snapshotter,
            self.configuration.get_network()?,
            digests_path,
            self.get_immutable_file_digest_mapper().await?,
            self.root_logger(),
        )?);

        Ok(CardanoDatabaseArtifactBuilder::new(
            self.configuration.get_network()?,
            &cardano_node_version,
            ancillary_builder,
            immutable_builder,
            digest_builder,
        ))
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::temp_dir_create;
    use mithril_persistence::sqlite::ConnectionBuilder;

    use crate::ServeCommandConfiguration;
    use crate::dependency_injection::builder::CARDANO_DB_ARTIFACTS_DIR;

    use super::*;

    #[tokio::test]
    async fn if_not_local_uploader_create_cardano_database_immutable_dirs() {
        let snapshot_directory = temp_dir_create!();
        let cdb_dir = snapshot_directory.join(CARDANO_DB_ARTIFACTS_DIR);
        let ancillary_dir = cdb_dir.join("ancillary");
        let immutable_dir = cdb_dir.join("immutable");
        let digests_dir = cdb_dir.join("digests");

        let mut dep_builder = {
            let config = ServeCommandConfiguration {
                // Test environment yield dumb uploaders
                environment: ExecutionEnvironment::Test,
                ..ServeCommandConfiguration::new_sample(snapshot_directory)
            };

            DependenciesBuilder::new_with_stdout_logger(Arc::new(config))
        };

        assert!(!ancillary_dir.exists());
        assert!(!immutable_dir.exists());
        assert!(!digests_dir.exists());

        dep_builder
            .build_cardano_database_artifact_builder(Version::parse("1.0.0").unwrap())
            .await
            .unwrap();

        assert!(!ancillary_dir.exists());
        assert!(immutable_dir.exists());
        assert!(!digests_dir.exists());
    }

    #[tokio::test]
    async fn if_local_uploader_creates_all_cardano_database_subdirs() {
        let snapshot_directory = temp_dir_create!();
        let cdb_dir = snapshot_directory.join(CARDANO_DB_ARTIFACTS_DIR);
        let ancillary_dir = cdb_dir.join("ancillary");
        let immutable_dir = cdb_dir.join("immutable");
        let digests_dir = cdb_dir.join("digests");

        let mut dep_builder = {
            let config = ServeCommandConfiguration {
                // Must use production environment to make `snapshot_uploader_type` effective
                environment: ExecutionEnvironment::Production,
                snapshot_uploader_type: SnapshotUploaderType::Local,
                ..ServeCommandConfiguration::new_sample(snapshot_directory)
            };

            DependenciesBuilder::new_with_stdout_logger(Arc::new(config))
        };
        // In production environment the builder can't create in-memory SQLite connections, we
        // need to provide it manually to avoid creations of unnecessary files.
        dep_builder.sqlite_connection =
            Some(Arc::new(ConnectionBuilder::open_memory().build().unwrap()));

        assert!(!ancillary_dir.exists());
        assert!(!immutable_dir.exists());
        assert!(!digests_dir.exists());

        dep_builder
            .build_cardano_database_artifact_builder(Version::parse("1.0.0").unwrap())
            .await
            .unwrap();

        assert!(ancillary_dir.exists());
        assert!(immutable_dir.exists());
        assert!(digests_dir.exists());
    }
}
