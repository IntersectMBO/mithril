use anyhow::Context;
use slog::{Logger, warn};
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

use mithril_client::{
    CardanoDatabaseSnapshot, MithrilResult,
    cardano_database_client::{CardanoDatabaseClient, DownloadUnpackOptions, ImmutableFileRange},
    common::{ImmutableFileNumber, SignedEntityTypeDiscriminants},
};

use crate::{
    CommandContext,
    commands::cardano_db::{
        download::DB_DIRECTORY_NAME,
        shared_steps::{self, ComputeCardanoDatabaseMessageOptions},
    },
    utils::{
        CardanoDbDownloadChecker, CardanoDbUtils, ExpanderUtils, IndicatifFeedbackReceiver,
        ProgressOutputType, ProgressPrinter,
    },
};

const DISK_SPACE_SAFETY_MARGIN_RATIO: f64 = 0.1;

struct RestorationOptions {
    db_dir: PathBuf,
    immutable_file_range: ImmutableFileRange,
    download_unpack_options: DownloadUnpackOptions,
    disk_space_safety_margin_ratio: f64,
}

#[derive(Debug, Clone)]
pub(super) struct PreparedCardanoDbV2Download {
    pub(super) hash: String,
    pub(super) download_dir: String,
    pub(super) start: Option<ImmutableFileNumber>,
    pub(super) end: Option<ImmutableFileNumber>,
    pub(super) include_ancillary: bool,
    pub(super) ancillary_verification_key: Option<String>,
    pub(super) ipfs_rpc_url: Option<String>,
    pub(super) allow_override: bool,
}

impl PreparedCardanoDbV2Download {
    pub async fn execute(&self, context: &CommandContext) -> MithrilResult<()> {
        if self.ipfs_rpc_url.is_some() {
            context.require_unstable("cardano-db download --ipfs-rpc-url <url>", None)?;
        }

        let restoration_options = RestorationOptions {
            db_dir: Path::new(&self.download_dir).join(DB_DIRECTORY_NAME),
            immutable_file_range: shared_steps::immutable_file_range(self.start, self.end),
            download_unpack_options: DownloadUnpackOptions {
                allow_override: self.allow_override,
                include_ancillary: self.include_ancillary,
                ..DownloadUnpackOptions::default()
            },
            disk_space_safety_margin_ratio: DISK_SPACE_SAFETY_MARGIN_RATIO,
        };

        let progress_output_type = if context.is_json_output_enabled() {
            ProgressOutputType::JsonReporter
        } else {
            ProgressOutputType::Tty
        };
        let progress_printer = ProgressPrinter::new(progress_output_type, 7);
        let client = context
            .setup_mithril_client_builder()?
            .with_capabilities(SignedEntityTypeDiscriminants::CardanoDatabase.into())
            .add_feedback_receiver(Arc::new(IndicatifFeedbackReceiver::new(
                progress_output_type,
                context.logger().clone(),
            )))
            .set_ancillary_verification_key(self.ancillary_verification_key.clone())
            .with_ipfs_rpc_url(self.ipfs_rpc_url.clone())
            .build()?;

        let get_list_of_artifact_ids = || async {
            let cardano_db_snapshots = client.cardano_database_v2().list().await.with_context(
                || "Can not get the list of artifacts while retrieving the latest cardano db hash",
            )?;

            Ok(cardano_db_snapshots
                .iter()
                .map(|cardano_db| cardano_db.hash.to_owned())
                .collect::<Vec<String>>())
        };

        let cardano_db_message = client
            .cardano_database_v2()
            .get(
                &ExpanderUtils::expand_eventual_id_alias(&self.hash, get_list_of_artifact_ids())
                    .await?,
            )
            .await?
            .with_context(|| format!("Can not get the cardano db for hash: '{}'", self.hash))?;

        Self::check_local_disk_info(
            1,
            &progress_printer,
            &restoration_options,
            &cardano_db_message,
            self.allow_override,
        )?;

        let certificate = shared_steps::fetch_certificate_and_verifying_chain(
            2,
            &progress_printer,
            &client,
            &cardano_db_message.certificate_hash,
        )
        .await?;

        Self::download_and_unpack_cardano_database_snapshot(
            context.logger(),
            3,
            &progress_printer,
            client.cardano_database_v2(),
            &cardano_db_message,
            &restoration_options,
        )
        .await
        .with_context(|| {
            format!(
                "Can not download and unpack cardano db snapshot for hash: '{}'",
                self.hash
            )
        })?;

        let verified_digests = shared_steps::download_and_verify_digests(
            4,
            &progress_printer,
            &client,
            &certificate,
            &cardano_db_message,
        )
        .await
        .with_context(|| {
            format!(
                "Can not download and verify digests file for cardano db snapshot with hash: '{}'",
                self.hash
            )
        })?;

        let options = ComputeCardanoDatabaseMessageOptions {
            db_dir: restoration_options.db_dir.clone(),
            immutable_file_range: restoration_options.immutable_file_range,
            allow_missing: false,
        };

        let merkle_proof = shared_steps::verify_cardano_database(
            5,
            &progress_printer,
            &client,
            &certificate,
            &cardano_db_message,
            &options,
            &verified_digests,
        )
        .await
        .with_context(|| format!("Can not verify cardano database for hash: '{}'", self.hash))?;

        let message = shared_steps::compute_cardano_db_snapshot_message(
            6,
            &progress_printer,
            &certificate,
            &merkle_proof,
        )
        .await?;

        shared_steps::verify_message_matches_certificate(
            context.logger(),
            7,
            &progress_printer,
            &certificate,
            &message,
            &cardano_db_message,
            &restoration_options.db_dir,
        )
        .await?;

        shared_steps::log_download_information(
            &restoration_options.db_dir,
            &cardano_db_message.hash,
            &cardano_db_message.network,
            &cardano_db_message.cardano_node_version,
            context.is_json_output_enabled(),
            restoration_options.download_unpack_options.include_ancillary,
        )?;

        Ok(())
    }

    fn compute_total_immutables_restored_size(
        cardano_db: &CardanoDatabaseSnapshot,
        restoration_options: &RestorationOptions,
    ) -> u64 {
        let total_immutables_restored = restoration_options
            .immutable_file_range
            .length(cardano_db.beacon.immutable_file_number);

        total_immutables_restored * cardano_db.immutables.average_size_uncompressed
    }

    fn add_safety_margin(size: u64, margin_ratio: f64) -> u64 {
        (size as f64 * (1.0 + margin_ratio)) as u64
    }

    fn compute_required_disk_space_for_snapshot(
        cardano_db: &CardanoDatabaseSnapshot,
        restoration_options: &RestorationOptions,
    ) -> u64 {
        if restoration_options.immutable_file_range == ImmutableFileRange::Full {
            cardano_db.total_db_size_uncompressed
        } else {
            let total_immutables_restored_size =
                Self::compute_total_immutables_restored_size(cardano_db, restoration_options);

            let mut total_size =
                total_immutables_restored_size + cardano_db.digests.size_uncompressed;
            if restoration_options.download_unpack_options.include_ancillary {
                total_size += cardano_db.ancillary.size_uncompressed;
            }

            Self::add_safety_margin(
                total_size,
                restoration_options.disk_space_safety_margin_ratio,
            )
        }
    }

    fn check_local_disk_info(
        step_number: u16,
        progress_printer: &ProgressPrinter,
        restoration_options: &RestorationOptions,
        cardano_db: &CardanoDatabaseSnapshot,
        allow_override: bool,
    ) -> MithrilResult<()> {
        progress_printer.report_step(step_number, "Checking local disk info…")?;

        CardanoDbDownloadChecker::ensure_dir_exist(&restoration_options.db_dir)?;
        if let Err(e) = CardanoDbDownloadChecker::check_prerequisites_for_uncompressed_data(
            &restoration_options.db_dir,
            Self::compute_required_disk_space_for_snapshot(cardano_db, restoration_options),
            allow_override,
        ) {
            progress_printer
                .report_step(step_number, &CardanoDbUtils::check_disk_space_error(e)?)?;
        }

        Ok(())
    }

    async fn download_and_unpack_cardano_database_snapshot(
        logger: &Logger,
        step_number: u16,
        progress_printer: &ProgressPrinter,
        client: Arc<CardanoDatabaseClient>,
        cardano_database_snapshot: &CardanoDatabaseSnapshot,
        restoration_options: &RestorationOptions,
    ) -> MithrilResult<()> {
        progress_printer.report_step(
            step_number,
            "Downloading and unpacking the cardano db snapshot",
        )?;
        client
            .download_unpack(
                cardano_database_snapshot,
                &restoration_options.immutable_file_range,
                &restoration_options.db_dir,
                restoration_options.download_unpack_options,
            )
            .await?;

        // The cardano db snapshot download does not fail if the statistic call fails.
        // It would be nice to implement tests to verify the behavior of `add_statistics`
        let full_restoration = restoration_options.immutable_file_range == ImmutableFileRange::Full;
        let include_ancillary = restoration_options.download_unpack_options.include_ancillary;
        let number_of_immutable_files_restored = restoration_options
            .immutable_file_range
            .length(cardano_database_snapshot.beacon.immutable_file_number);
        if let Err(e) = client
            .add_statistics(
                full_restoration,
                include_ancillary,
                number_of_immutable_files_restored,
            )
            .await
        {
            warn!(
                logger, "Could not increment cardano db snapshot download statistics";
                "error" => ?e
            );
        }

        // Append 'clean' file to speedup node bootstrap
        if let Err(error) = File::create(restoration_options.db_dir.join("clean")) {
            warn!(
                logger, "Could not create clean shutdown marker file in directory '{}'", restoration_options.db_dir.display();
                "error" => error.to_string()
            );
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mithril_client::common::test::Dummy;
    use mithril_client::common::{AncillaryMessagePart, DigestsMessagePart, ImmutablesMessagePart};

    use super::*;

    #[test]
    fn compute_required_disk_space_for_snapshot_when_full_restoration() {
        let cardano_db_snapshot = CardanoDatabaseSnapshot {
            total_db_size_uncompressed: 123,
            ..CardanoDatabaseSnapshot::dummy()
        };
        let restoration_options = RestorationOptions {
            immutable_file_range: ImmutableFileRange::Full,
            db_dir: PathBuf::from("db_dir"),
            download_unpack_options: DownloadUnpackOptions::default(),
            disk_space_safety_margin_ratio: 0.0,
        };

        let required_size = PreparedCardanoDbV2Download::compute_required_disk_space_for_snapshot(
            &cardano_db_snapshot,
            &restoration_options,
        );

        assert_eq!(required_size, 123);
    }

    #[test]
    fn compute_required_disk_space_for_snapshot_when_partial_restoration_and_no_ancillary_files() {
        let cardano_db_snapshot = CardanoDatabaseSnapshot {
            digests: DigestsMessagePart {
                size_uncompressed: 50,
                locations: vec![],
            },
            immutables: ImmutablesMessagePart {
                average_size_uncompressed: 100,
                locations: vec![],
            },
            ancillary: AncillaryMessagePart {
                size_uncompressed: 300,
                locations: vec![],
            },
            ..CardanoDatabaseSnapshot::dummy()
        };
        let restoration_options = RestorationOptions {
            immutable_file_range: ImmutableFileRange::Range(10, 19),
            db_dir: PathBuf::from("db_dir"),
            download_unpack_options: DownloadUnpackOptions {
                include_ancillary: false,
                ..DownloadUnpackOptions::default()
            },
            disk_space_safety_margin_ratio: 0.0,
        };

        let required_size = PreparedCardanoDbV2Download::compute_required_disk_space_for_snapshot(
            &cardano_db_snapshot,
            &restoration_options,
        );

        let digest_size = cardano_db_snapshot.digests.size_uncompressed;
        let average_size_uncompressed_immutable =
            cardano_db_snapshot.immutables.average_size_uncompressed;

        let expected_size = digest_size + 10 * average_size_uncompressed_immutable;
        assert_eq!(required_size, expected_size);
    }

    #[test]
    fn compute_required_disk_space_for_snapshot_when_partial_restoration_and_ancillary_files() {
        let cardano_db_snapshot = CardanoDatabaseSnapshot {
            digests: DigestsMessagePart {
                size_uncompressed: 50,
                locations: vec![],
            },
            immutables: ImmutablesMessagePart {
                average_size_uncompressed: 100,
                locations: vec![],
            },
            ancillary: AncillaryMessagePart {
                size_uncompressed: 300,
                locations: vec![],
            },
            ..CardanoDatabaseSnapshot::dummy()
        };
        let restoration_options = RestorationOptions {
            immutable_file_range: ImmutableFileRange::Range(10, 19),
            db_dir: PathBuf::from("db_dir"),
            download_unpack_options: DownloadUnpackOptions {
                include_ancillary: true,
                ..DownloadUnpackOptions::default()
            },
            disk_space_safety_margin_ratio: 0.0,
        };

        let required_size = PreparedCardanoDbV2Download::compute_required_disk_space_for_snapshot(
            &cardano_db_snapshot,
            &restoration_options,
        );

        let digest_size = cardano_db_snapshot.digests.size_uncompressed;
        let average_size_uncompressed_immutable =
            cardano_db_snapshot.immutables.average_size_uncompressed;
        let ancillary_size = cardano_db_snapshot.ancillary.size_uncompressed;

        let expected_size = digest_size + 10 * average_size_uncompressed_immutable + ancillary_size;
        assert_eq!(required_size, expected_size);
    }

    #[test]
    fn add_safety_margin_apply_margin_with_ratio() {
        assert_eq!(
            PreparedCardanoDbV2Download::add_safety_margin(100, 0.1),
            110
        );
        assert_eq!(
            PreparedCardanoDbV2Download::add_safety_margin(100, 0.5),
            150
        );
        assert_eq!(
            PreparedCardanoDbV2Download::add_safety_margin(100, 1.5),
            250
        );

        assert_eq!(PreparedCardanoDbV2Download::add_safety_margin(0, 0.1), 0);

        assert_eq!(
            PreparedCardanoDbV2Download::add_safety_margin(100, 0.0),
            100
        );
    }
}
