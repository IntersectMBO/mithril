use std::ops::RangeInclusive;
use std::path::Path;

use anyhow::anyhow;

use mithril_cardano_node_internal_database::{IMMUTABLE_DIR, LEDGER_DIR, VOLATILE_DIR};

use crate::MithrilResult;
use crate::common::ImmutableFileNumber;
#[cfg(feature = "unstable")]
use crate::common::Percentage;

/// Options for downloading and unpacking a Cardano database
#[derive(Debug, Copy, Clone)]
pub struct DownloadUnpackOptions {
    /// Allow overriding the destination directory
    pub allow_override: bool,

    /// Include ancillary files in the download
    pub include_ancillary: bool,

    /// Maximum number of parallel downloads
    pub max_parallel_downloads: usize,
}

/// Options to override the IPFS share used to download immutable files
///
/// Hidden: this control is only needed for testing until IPFS is fully deployed.
#[cfg(feature = "unstable")]
#[derive(Debug, Copy, Clone, Default)]
#[doc(hidden)]
pub enum IpfsShare {
    /// Use a custom share of the immutables files to download through IPFS
    Custom(Percentage),
    /// Fetch the share from the aggregator with a fall-back to a hardcoded default
    #[default]
    FromAggregator,
}

impl Default for DownloadUnpackOptions {
    fn default() -> Self {
        Self {
            allow_override: false,
            include_ancillary: false,
            max_parallel_downloads: 20,
        }
    }
}

impl DownloadUnpackOptions {
    /// Verify if the download options are compatible with the immutable file range.
    pub fn verify_compatibility(
        &self,
        immutable_file_range: &RangeInclusive<ImmutableFileNumber>,
        last_immutable_file_number: ImmutableFileNumber,
    ) -> MithrilResult<()> {
        if self.include_ancillary && !immutable_file_range.contains(&last_immutable_file_number) {
            return Err(anyhow!(
                "The last immutable file number {last_immutable_file_number} is outside the range: {immutable_file_range:?}"
            ));
        }

        Ok(())
    }

    /// Verify if the target directory is writable.
    pub fn verify_can_write_to_target_directory(&self, target_dir: &Path) -> MithrilResult<()> {
        fn subdir_should_not_exist(
            parent: &Path,
            name_in_error: &str,
            subdir: &str,
        ) -> MithrilResult<()> {
            if parent.join(subdir).exists() {
                anyhow::bail!("{name_in_error} target directory already exists in: {parent:?}")
            }
            Ok(())
        }

        if !self.allow_override {
            subdir_should_not_exist(target_dir, "Immutable files", IMMUTABLE_DIR)?;
            if self.include_ancillary {
                subdir_should_not_exist(target_dir, "Volatile", VOLATILE_DIR)?;
                subdir_should_not_exist(target_dir, "Ledger", LEDGER_DIR)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::cardano_database_client::ImmutableFileRange;

    use super::*;

    mod verify_compatibility {
        use super::*;

        #[test]
        fn succeeds_if_without_ancillary_download() {
            let download_options = DownloadUnpackOptions {
                include_ancillary: false,
                ..DownloadUnpackOptions::default()
            };
            let immutable_file_range = ImmutableFileRange::Range(1, 10);
            let last_immutable_file_number = 10;

            download_options
                .verify_compatibility(
                    &immutable_file_range
                        .to_range_inclusive(last_immutable_file_number)
                        .unwrap(),
                    last_immutable_file_number,
                )
                .unwrap();
        }

        #[test]
        fn succeeds_if_with_ancillary_download_and_compatible_range() {
            let download_options = DownloadUnpackOptions {
                include_ancillary: true,
                ..DownloadUnpackOptions::default()
            };
            let immutable_file_range = ImmutableFileRange::Range(7, 10);
            let last_immutable_file_number = 10;

            download_options
                .verify_compatibility(
                    &immutable_file_range
                        .to_range_inclusive(last_immutable_file_number)
                        .unwrap(),
                    last_immutable_file_number,
                )
                .unwrap();
        }

        #[test]
        fn fails_if_with_ancillary_download_and_incompatible_range() {
            let download_options = DownloadUnpackOptions {
                include_ancillary: true,
                ..DownloadUnpackOptions::default()
            };
            let immutable_file_range = ImmutableFileRange::Range(7, 10);
            let last_immutable_file_number = 123;

            download_options
            .verify_compatibility(
            &immutable_file_range
                .to_range_inclusive(last_immutable_file_number)
                .unwrap(),
            last_immutable_file_number,
        )
            .expect_err("verify_download_options_compatibility should fail as the last immutable file number is outside the range");
        }
    }

    mod verify_can_write_to_target_directory {
        use std::fs;

        use mithril_common::temp_dir_create;

        use super::*;

        #[test]
        fn always_succeeds_with_allow_overwrite() {
            let target_dir = temp_dir_create!();

            let download_options = DownloadUnpackOptions {
                allow_override: true,
                include_ancillary: false,
                ..DownloadUnpackOptions::default()
            };

            download_options
                .verify_can_write_to_target_directory(&target_dir)
                .unwrap();

            fs::create_dir_all(target_dir.join(IMMUTABLE_DIR)).unwrap();
            fs::create_dir_all(target_dir.join(VOLATILE_DIR)).unwrap();
            fs::create_dir_all(target_dir.join(LEDGER_DIR)).unwrap();
            download_options
                .verify_can_write_to_target_directory(&target_dir)
                .unwrap();

            DownloadUnpackOptions {
                allow_override: true,
                include_ancillary: true,
                ..DownloadUnpackOptions::default()
            }
            .verify_can_write_to_target_directory(&target_dir)
            .unwrap();
        }

        #[test]
        fn fails_without_allow_overwrite_and_non_empty_immutable_target_dir() {
            let target_dir = temp_dir_create!();
            fs::create_dir_all(target_dir.join(IMMUTABLE_DIR)).unwrap();

            DownloadUnpackOptions {
                allow_override: false,
                include_ancillary: false,
                ..DownloadUnpackOptions::default()
            }
            .verify_can_write_to_target_directory(&target_dir)
            .expect_err("verify_can_write_to_target_directory should fail");

            DownloadUnpackOptions {
                allow_override: false,
                include_ancillary: true,
                ..DownloadUnpackOptions::default()
            }
            .verify_can_write_to_target_directory(&target_dir)
            .expect_err("verify_can_write_to_target_directory should fail");
        }

        #[test]
        fn fails_without_allow_overwrite_and_non_empty_ledger_target_dir() {
            let target_dir = temp_dir_create!();
            fs::create_dir_all(target_dir.join(LEDGER_DIR)).unwrap();

            DownloadUnpackOptions {
                allow_override: false,
                include_ancillary: true,
                ..DownloadUnpackOptions::default()
            }
            .verify_can_write_to_target_directory(&target_dir)
            .expect_err("verify_can_write_to_target_directory should fail");

            DownloadUnpackOptions {
                allow_override: false,
                include_ancillary: false,
                ..DownloadUnpackOptions::default()
            }
            .verify_can_write_to_target_directory(&target_dir)
            .unwrap();
        }

        #[test]
        fn fails_without_allow_overwrite_and_non_empty_volatile_target_dir() {
            let target_dir = temp_dir_create!();
            fs::create_dir_all(target_dir.join(VOLATILE_DIR)).unwrap();

            DownloadUnpackOptions {
                allow_override: false,
                include_ancillary: true,
                ..DownloadUnpackOptions::default()
            }
            .verify_can_write_to_target_directory(&target_dir)
            .expect_err("verify_can_write_to_target_directory should fail");

            DownloadUnpackOptions {
                allow_override: false,
                include_ancillary: false,
                ..DownloadUnpackOptions::default()
            }
            .verify_can_write_to_target_directory(&target_dir)
            .unwrap();
        }
    }
}
