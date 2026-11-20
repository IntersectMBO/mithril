use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Context;

use mithril_cardano_node_internal_database::{IMMUTABLE_DIR, immutable_trio_names};
use mithril_common::entities::ImmutableFileNumber;

use crate::{MithrilResult, utils::move_file};

/// Check that the unpacked immutable archive holds exactly the immutable directory and the
/// regular files of the immutable trio, nothing else.
pub async fn verify_immutable_archive_members(
    staging_dir: &Path,
    immutable_file_number: ImmutableFileNumber,
) -> MithrilResult<()> {
    let staging_entries = list_entry_names(staging_dir).await?;
    let expected_staging_entries = BTreeSet::from([IMMUTABLE_DIR.to_string()]);
    if staging_entries != expected_staging_entries {
        anyhow::bail!(
            "Unexpected entries in the archive of immutable file {immutable_file_number}: expected {expected_staging_entries:?}, found {staging_entries:?}"
        );
    }

    let staged_immutable_dir = staging_dir.join(IMMUTABLE_DIR);
    let expected_names: BTreeSet<String> =
        immutable_trio_names(immutable_file_number).into_iter().collect();
    let found_names = list_entry_names(&staged_immutable_dir).await?;
    if found_names != expected_names {
        anyhow::bail!(
            "Unexpected content in the archive of immutable file {immutable_file_number}: expected {expected_names:?}, found {found_names:?}"
        );
    }

    for name in &expected_names {
        let path = staged_immutable_dir.join(name);
        let metadata = tokio::fs::symlink_metadata(&path)
            .await
            .with_context(|| format!("Could not read metadata of '{}'", path.display()))?;
        if !metadata.is_file() {
            anyhow::bail!(
                "Entry '{name}' of the archive of immutable file {immutable_file_number} is not a regular file"
            );
        }
    }

    Ok(())
}

/// List the names of the entries of a directory.
async fn list_entry_names(dir: &Path) -> MithrilResult<BTreeSet<String>> {
    let mut entries = tokio::fs::read_dir(dir)
        .await
        .with_context(|| format!("Could not read directory '{}'", dir.display()))?;
    let mut names = BTreeSet::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .with_context(|| format!("Could not read an entry of directory '{}'", dir.display()))?
    {
        names.insert(entry.file_name().to_string_lossy().to_string());
    }

    Ok(names)
}

/// Move the immutable trio from the staging directory to the immutable directory of the
/// target directory, creating the latter when it does not exist.
pub async fn promote_immutable_files(
    staging_dir: &Path,
    target_dir: &Path,
    immutable_file_number: ImmutableFileNumber,
) -> MithrilResult<()> {
    let target_immutable_dir = target_dir.join(IMMUTABLE_DIR);
    tokio::fs::create_dir_all(&target_immutable_dir)
        .await
        .with_context(|| {
            format!(
                "Could not create directory '{}'",
                target_immutable_dir.display()
            )
        })?;
    for name in immutable_trio_names(immutable_file_number) {
        let source = staging_dir.join(IMMUTABLE_DIR).join(&name);
        let destination = target_immutable_dir.join(&name);
        move_file(&source, &destination).await.with_context(|| {
            format!(
                "Could not move '{}' to '{}'",
                source.display(),
                destination.display()
            )
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use mithril_common::test::{assert_dir_eq, temp_dir_create};

    use super::super::test_utils::{FULL_TRIO, create_file, create_immutable_trio};
    use super::*;

    mod verify_immutable_archive_members {
        use super::*;

        #[tokio::test]
        async fn accepts_an_archive_holding_exactly_the_immutable_trio() {
            let staging_dir = temp_dir_create!();
            create_immutable_trio(&staging_dir, &FULL_TRIO);

            verify_immutable_archive_members(&staging_dir, 1)
                .await
                .expect("an archive holding exactly the immutable trio must be accepted");
        }

        #[tokio::test]
        async fn rejects_an_archive_with_an_entry_outside_the_immutable_trio() {
            let staging_dir = temp_dir_create!();
            create_immutable_trio(&staging_dir, &FULL_TRIO);
            create_file(&staging_dir.join("ledger"), "state");

            verify_immutable_archive_members(&staging_dir, 1)
                .await
                .expect_err("an archive with an entry outside the immutable trio must be rejected");
        }

        #[tokio::test]
        async fn rejects_an_archive_missing_a_file_of_the_immutable_trio() {
            let staging_dir = temp_dir_create!();
            create_immutable_trio(&staging_dir, &["00001.chunk", "00001.primary"]);

            verify_immutable_archive_members(&staging_dir, 1)
                .await
                .expect_err("an archive missing a file of the immutable trio must be rejected");
        }

        #[tokio::test]
        async fn rejects_an_archive_whose_trio_entry_is_not_a_regular_file() {
            let staging_dir = temp_dir_create!();
            create_immutable_trio(&staging_dir, &["00001.primary", "00001.secondary"]);
            std::fs::create_dir_all(staging_dir.join(IMMUTABLE_DIR).join("00001.chunk")).unwrap();

            verify_immutable_archive_members(&staging_dir, 1)
                .await
                .expect_err("a trio entry that is a directory must be rejected");
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn rejects_an_archive_whose_trio_entry_is_a_symlink() {
            let temp_dir = temp_dir_create!();
            let staging_dir = temp_dir.join("staging");
            create_immutable_trio(&staging_dir, &["00001.primary", "00001.secondary"]);
            create_file(&temp_dir, "outside_file");
            std::os::unix::fs::symlink(
                temp_dir.join("outside_file"),
                staging_dir.join(IMMUTABLE_DIR).join("00001.chunk"),
            )
            .unwrap();

            verify_immutable_archive_members(&staging_dir, 1)
                .await
                .expect_err("a trio entry that is a symlink must be rejected");
        }

        #[tokio::test]
        async fn rejects_an_archive_carrying_a_file_of_another_immutable() {
            let staging_dir = temp_dir_create!();
            create_immutable_trio(&staging_dir, &FULL_TRIO);
            create_immutable_trio(&staging_dir, &["00002.chunk"]);

            verify_immutable_archive_members(&staging_dir, 1)
                .await
                .expect_err("a file of another immutable must be rejected");
        }

        #[tokio::test]
        async fn rejects_a_raw_file_in_place_of_the_unpacked_archive() {
            let staging_dir = temp_dir_create!();
            create_file(&staging_dir, "00001.tar.zst");

            verify_immutable_archive_members(&staging_dir, 1)
                .await
                .expect_err("a raw file in place of the immutable archive must be rejected");
        }
    }

    mod promote_immutable_files {
        #[cfg(target_os = "linux")]
        use std::os::unix::fs::MetadataExt;

        use super::*;

        #[tokio::test]
        async fn moves_the_trio_to_the_immutable_directory_of_the_target_directory() {
            let temp_dir = temp_dir_create!();
            let staging_dir = temp_dir.join("staging");
            let target_dir = temp_dir.join("target");
            create_immutable_trio(&staging_dir, &FULL_TRIO);
            std::fs::create_dir(&target_dir).unwrap();

            promote_immutable_files(&staging_dir, &target_dir, 1).await.unwrap();

            assert_dir_eq!(
                &target_dir,
                "* immutable/
                 ** 00001.chunk
                 ** 00001.primary
                 ** 00001.secondary"
            );
        }

        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn moves_the_trio_to_an_immutable_directory_on_another_filesystem() {
            let temp_dir = temp_dir_create!();
            let staging_dir = temp_dir.join("staging");
            let target_dir = temp_dir.join("target");
            let other_filesystem_dir = Path::new("/dev/shm").join(format!(
                "mithril_client_promotes_the_immutable_trio_{}",
                std::process::id()
            ));
            assert_ne!(
                std::fs::metadata(&temp_dir).unwrap().dev(),
                std::fs::metadata("/dev/shm").unwrap().dev(),
                "this test needs '/dev/shm' and the temporary directory on two filesystems"
            );
            create_immutable_trio(&staging_dir, &FULL_TRIO);
            std::fs::create_dir(&target_dir).unwrap();
            let _ = std::fs::remove_dir_all(&other_filesystem_dir);
            std::fs::create_dir(&other_filesystem_dir).unwrap();
            std::os::unix::fs::symlink(&other_filesystem_dir, target_dir.join(IMMUTABLE_DIR))
                .unwrap();

            let result = promote_immutable_files(&staging_dir, &target_dir, 1).await;

            let promoted_trio: Vec<bool> = FULL_TRIO
                .iter()
                .map(|name| other_filesystem_dir.join(name).is_file())
                .collect();
            std::fs::remove_dir_all(&other_filesystem_dir).unwrap();
            result.expect("the trio must be promoted across filesystems");
            assert_eq!(vec![true, true, true], promoted_trio);
        }
    }
}
