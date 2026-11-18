use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use pallas_hardano::storage::immutable::chunk;
use pallas_traverse::MultiEraBlock;
use thiserror::Error;

use mithril_common::StdResult;
use mithril_common::entities::{BlockNumber, ImmutableFileNumber, SlotNumber};

use crate::entities::CertifyingBlock;

/// Error raised when reading the certifying blocks of the immutable files.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertifyingBlocksReaderError {
    /// The predecessor of a certifying block announces no endorser block or its immutable file is missing.
    #[error(
        "Certifying block {block_number} of immutable file {immutable_file_number} has no announcing predecessor"
    )]
    MissingAnnouncement {
        /// Number of the certifying block.
        block_number: BlockNumber,

        /// Number of the immutable file holding the certifying block.
        immutable_file_number: ImmutableFileNumber,
    },
}

/// The endorser block announced by a block, carried to its direct successor.
#[derive(Debug, Clone)]
struct Announcement {
    /// Slot of the announcing block.
    slot_number: SlotNumber,

    /// Announced hash of the endorser block body.
    endorser_block_hash: String,

    /// Announced size of the endorser block body in bytes.
    endorser_block_size: u32,
}

/// What to do with a block of an immutable file that cannot be read or decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnreadableBlockPolicy {
    /// Fail, a completed immutable file holds only whole blocks.
    Fail,

    /// Stop at the block, the node was appending it while the partial immutable file was copied.
    StopReading,
}

/// Reads the blocks of an immutable file that certify an endorser block.
///
/// A certifying block certifies the endorser block announced by its direct predecessor, which may be
/// the last block of the previous immutable file.
pub struct CertifyingBlocksReader;

impl CertifyingBlocksReader {
    /// Lists the certifying blocks of the copy of a partial immutable file read from `partial_immutable_dir`,
    /// taking the announcement of its first block from the previous immutable file read in `previous_chunk_dir`.
    ///
    /// The node may append a block while the files are copied: the listing stops at the first block of
    /// the copy that cannot be read or decoded.
    pub fn list_partial_with_previous_chunk_dir(
        partial_immutable_dir: &Path,
        previous_chunk_dir: &Path,
        immutable_file_number: ImmutableFileNumber,
    ) -> StdResult<Vec<CertifyingBlock>> {
        let mut previous_announcement =
            Self::last_announcement_of_previous_file(previous_chunk_dir, immutable_file_number)?;
        let mut certifying_blocks = Vec::new();
        Self::collect(
            partial_immutable_dir,
            immutable_file_number,
            UnreadableBlockPolicy::StopReading,
            &mut previous_announcement,
            &mut certifying_blocks,
        )?;

        Ok(certifying_blocks)
    }

    /// Lists the certifying blocks of consecutive immutable files in one pass, each file decoded once.
    pub fn list_range(
        immutable_dir: &Path,
        immutable_file_numbers: RangeInclusive<ImmutableFileNumber>,
    ) -> StdResult<Vec<CertifyingBlock>> {
        let mut previous_announcement = Self::last_announcement_of_previous_file(
            immutable_dir,
            *immutable_file_numbers.start(),
        )?;
        let mut certifying_blocks = Vec::new();
        for immutable_file_number in immutable_file_numbers {
            Self::collect(
                immutable_dir,
                immutable_file_number,
                UnreadableBlockPolicy::Fail,
                &mut previous_announcement,
                &mut certifying_blocks,
            )?;
        }

        Ok(certifying_blocks)
    }

    /// Name of the chunk file of an immutable file number, padded on five digits.
    fn immutable_chunk_name(immutable_file_number: ImmutableFileNumber) -> String {
        format!("{immutable_file_number:05}")
    }

    /// Appends the certifying blocks of an immutable file, carrying the last announcement across files.
    fn collect(
        immutable_dir: &Path,
        immutable_file_number: ImmutableFileNumber,
        unreadable_block_policy: UnreadableBlockPolicy,
        previous_announcement: &mut Option<Announcement>,
        certifying_blocks: &mut Vec<CertifyingBlock>,
    ) -> StdResult<()> {
        let chunk_name = Self::immutable_chunk_name(immutable_file_number);
        for raw_block in Self::read_chunk(immutable_dir, &chunk_name)? {
            let raw_block = match raw_block {
                Ok(raw_block) => raw_block,
                Err(_) if unreadable_block_policy == UnreadableBlockPolicy::StopReading => break,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("Could not read a block of immutable file {chunk_name}")
                    });
                }
            };
            let block = match MultiEraBlock::decode(&raw_block) {
                Ok(block) => block,
                Err(_) if unreadable_block_policy == UnreadableBlockPolicy::StopReading => break,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("Could not decode a block of immutable file {chunk_name}")
                    });
                }
            };
            let header = block.header();

            if header.block_body_contains_leios_cert() == Some(true) {
                let announcement = previous_announcement.take().ok_or(
                    CertifyingBlocksReaderError::MissingAnnouncement {
                        block_number: BlockNumber(block.number()),
                        immutable_file_number,
                    },
                )?;
                certifying_blocks.push(CertifyingBlock {
                    immutable_file_number,
                    block_number: BlockNumber(block.number()),
                    slot_number: SlotNumber(block.slot()),
                    block_hash: block.hash().to_string(),
                    announcing_slot_number: announcement.slot_number,
                    endorser_block_hash: announcement.endorser_block_hash,
                    endorser_block_size: announcement.endorser_block_size,
                });
            }

            *previous_announcement = Self::announcement_of(&block);
        }

        Ok(())
    }

    /// Reads the announcement of the last block of the previous immutable file, if the file is there.
    fn last_announcement_of_previous_file(
        immutable_dir: &Path,
        immutable_file_number: ImmutableFileNumber,
    ) -> StdResult<Option<Announcement>> {
        if immutable_file_number == 0 {
            return Ok(None);
        }
        let previous_chunk_name = Self::immutable_chunk_name(immutable_file_number - 1);
        if !Self::chunk_path(immutable_dir, &previous_chunk_name).exists() {
            return Ok(None);
        }

        let mut announcement = None;
        for raw_block in Self::read_chunk(immutable_dir, &previous_chunk_name)? {
            let raw_block = raw_block.with_context(|| {
                format!("Could not read a block of immutable file {previous_chunk_name}")
            })?;
            let block = MultiEraBlock::decode(&raw_block).with_context(|| {
                format!("Could not decode a block of immutable file {previous_chunk_name}")
            })?;
            announcement = Self::announcement_of(&block);
        }

        Ok(announcement)
    }

    /// Extracts the endorser block announced by a block, if any.
    fn announcement_of(block: &MultiEraBlock) -> Option<Announcement> {
        block.header().eb_announcement().map(|announcement| Announcement {
            slot_number: SlotNumber(block.slot()),
            endorser_block_hash: hex::encode(announcement.eb_hash),
            endorser_block_size: announcement.eb_size,
        })
    }

    /// Opens the blocks reader of an immutable file.
    fn read_chunk(immutable_dir: &Path, chunk_name: &str) -> StdResult<chunk::Reader> {
        chunk::read_blocks(immutable_dir, chunk_name).map_err(|e| {
            anyhow!(
                "Could not open immutable file {chunk_name} in '{}': {e:?}",
                immutable_dir.display()
            )
        })
    }

    /// Path of the chunk file of an immutable file.
    fn chunk_path(immutable_dir: &Path, chunk_name: &str) -> PathBuf {
        immutable_dir.join(format!("{chunk_name}.chunk"))
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::test::TempDir;

    use crate::test::LeiosFixtures;

    use super::*;

    fn immutable_dir() -> PathBuf {
        LeiosFixtures::directory().join("immutable")
    }

    fn immutable_dir_with_only(numbers: &[ImmutableFileNumber], name: &str) -> PathBuf {
        let dir = TempDir::create("certifying_blocks_reader", name);
        LeiosFixtures::copy_immutable_files_to(&dir, numbers);

        dir.join("immutable")
    }

    #[test]
    fn list_range_returns_the_certifying_blocks_with_their_announcements_in_chain_order() {
        let blocks = CertifyingBlocksReader::list_range(&immutable_dir(), 0..=7).unwrap();

        assert_eq!(
            blocks
                .iter()
                .map(|block| block.endorser_block_hash.as_str())
                .collect::<Vec<_>>(),
            LeiosFixtures::ENDORSER_BLOCK_HASHES
        );
        assert_eq!(
            blocks[0],
            CertifyingBlock {
                immutable_file_number: 4,
                block_number: BlockNumber(36),
                slot_number: SlotNumber(437),
                block_hash: "c2a4f7d341ac034adaef490ef7b2a5ff621ce62c1fe4c2299d4426dd181924ee"
                    .to_string(),
                announcing_slot_number: SlotNumber(413),
                endorser_block_hash: LeiosFixtures::ENDORSER_BLOCK_HASHES[0].to_string(),
                endorser_block_size: 45402,
            }
        );
    }

    #[test]
    fn list_range_returns_nothing_for_files_without_certifying_block() {
        let blocks = CertifyingBlocksReader::list_range(&immutable_dir(), 0..=3).unwrap();

        assert!(blocks.is_empty());
    }

    #[test]
    fn list_range_takes_the_announcement_of_its_first_block_from_the_previous_file() {
        let blocks = CertifyingBlocksReader::list_range(&immutable_dir(), 7..=7).unwrap();

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].block_number, BlockNumber(59));
        assert_eq!(blocks[0].announcing_slot_number, SlotNumber(680));
    }

    #[test]
    fn list_range_fails_when_the_announcing_block_is_in_a_missing_previous_file() {
        let dir = immutable_dir_with_only(&[7], "missing_previous_file");

        let error = CertifyingBlocksReader::list_range(&dir, 7..=7).unwrap_err();

        assert_eq!(
            error.downcast_ref::<CertifyingBlocksReaderError>(),
            Some(&CertifyingBlocksReaderError::MissingAnnouncement {
                block_number: BlockNumber(59),
                immutable_file_number: 7,
            })
        );
    }

    #[test]
    fn list_range_fails_when_an_immutable_file_is_missing() {
        let dir = immutable_dir_with_only(&[0, 2], "missing_file_in_range");

        CertifyingBlocksReader::list_range(&dir, 0..=2)
            .expect_err("should fail on a missing immutable file");
    }

    #[test]
    fn list_partial_with_previous_chunk_dir_reads_the_previous_file_from_another_directory() {
        let partial_dir = immutable_dir_with_only(&[7], "partial_chunk_dir");
        let previous_dir = immutable_dir_with_only(&[6], "previous_chunk_dir");

        let blocks = CertifyingBlocksReader::list_partial_with_previous_chunk_dir(
            &partial_dir,
            &previous_dir,
            7,
        )
        .unwrap();

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].announcing_slot_number, SlotNumber(680));
    }

    #[test]
    fn list_partial_with_previous_chunk_dir_stops_at_a_block_appended_during_the_copy() {
        let partial_dir = immutable_dir_with_only(&[5], "torn_partial_chunk_dir");
        let chunk_path = partial_dir.join("00005.chunk");
        let chunk = std::fs::read(&chunk_path).unwrap();
        std::fs::write(&chunk_path, &chunk[..chunk.len() - 10]).unwrap();

        let blocks = CertifyingBlocksReader::list_partial_with_previous_chunk_dir(
            &partial_dir,
            &immutable_dir(),
            5,
        )
        .unwrap();

        assert_eq!(
            blocks.iter().map(|block| block.block_number).collect::<Vec<_>>(),
            vec![BlockNumber(47)]
        );
    }

    #[test]
    fn list_range_fails_on_a_truncated_completed_file() {
        let dir = immutable_dir_with_only(&[4, 5], "torn_completed_chunk_dir");
        let chunk_path = dir.join("00005.chunk");
        let chunk = std::fs::read(&chunk_path).unwrap();
        std::fs::write(&chunk_path, &chunk[..chunk.len() - 10]).unwrap();

        CertifyingBlocksReader::list_range(&dir, 5..=5)
            .expect_err("should fail on a truncated completed file");
    }
}
