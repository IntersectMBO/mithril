use std::{
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::Context;

use crate::MithrilResult;

/// Create a directory if it does not exist
pub fn create_directory_if_not_exists(dir: &Path) -> MithrilResult<()> {
    if dir.exists() {
        return Ok(());
    }

    fs::create_dir_all(dir).with_context(|| "Failed creating directory")
}

/// Delete a directory if it exists
pub fn delete_directory(dir: &Path) -> MithrilResult<()> {
    if dir.exists() {
        fs::remove_dir_all(dir).with_context(|| "Failed deleting directory")?;
    }

    Ok(())
}

/// Move a file to its destination, copying it when both are not on the same filesystem.
pub async fn move_file(source: &Path, destination: &Path) -> io::Result<()> {
    match tokio::fs::rename(source, destination).await {
        Err(error) if error.kind() == io::ErrorKind::CrossesDevices => {
            copy_then_remove_file(source, destination).await
        }
        result => result,
    }
}

/// Copy a file to its destination then remove it.
///
/// The content is copied next to the destination then renamed over it, so that a failed copy
/// leaves an existing destination untouched and never a partial one.
async fn copy_then_remove_file(source: &Path, destination: &Path) -> io::Result<()> {
    let partial_destination = partial_copy_path(destination)?;
    let copied = match tokio::fs::copy(source, &partial_destination).await {
        Ok(_) => tokio::fs::rename(&partial_destination, destination).await,
        Err(error) => Err(error),
    };
    if let Err(error) = copied {
        let _ = tokio::fs::remove_file(&partial_destination).await;
        return Err(error);
    }

    tokio::fs::remove_file(source).await
}

/// Path of the partial copy of a file, a sibling of its destination.
fn partial_copy_path(destination: &Path) -> io::Result<PathBuf> {
    let mut partial_file_name = destination
        .file_name()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("'{}' has no file name", destination.display()),
            )
        })?
        .to_os_string();
    partial_file_name.push(".partial");

    Ok(destination.with_file_name(partial_file_name))
}

/// Read files in a directory
pub fn read_files_in_directory(dir: &Path) -> MithrilResult<Vec<PathBuf>> {
    let mut files = vec![];
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            files.push(path);
        }
    }

    Ok(files)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt;

    use mithril_common::temp_dir_create;

    use super::*;

    #[tokio::test]
    async fn move_file_moves_a_file_within_a_filesystem() {
        let temp_dir = temp_dir_create!();
        let source = temp_dir.join("source");
        let destination = temp_dir.join("destination");
        fs::write(&source, "content").unwrap();

        move_file(&source, &destination).await.unwrap();

        assert!(!source.exists());
        assert_eq!("content", fs::read_to_string(&destination).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn move_file_moves_a_file_to_another_filesystem() {
        let temp_dir = temp_dir_create!();
        let source = temp_dir.join("source");
        let destination = Path::new("/dev/shm").join(format!(
            "mithril_client_move_file_to_another_filesystem_{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&destination);
        fs::write(&source, "content").unwrap();
        assert_ne!(
            fs::metadata(&temp_dir).unwrap().dev(),
            fs::metadata("/dev/shm").unwrap().dev(),
            "this test needs '/dev/shm' and the temporary directory on two filesystems"
        );

        let moved = move_file(&source, &destination).await;

        let destination_content = fs::read_to_string(&destination);
        let _ = fs::remove_file(&destination);
        moved.unwrap();
        assert!(!source.exists());
        assert_eq!("content", destination_content.unwrap());
    }

    #[tokio::test]
    async fn move_file_fails_when_the_source_does_not_exist() {
        let temp_dir = temp_dir_create!();
        let destination = temp_dir.join("destination");

        let error = move_file(&temp_dir.join("missing"), &destination)
            .await
            .expect_err("a missing source can not be moved");

        assert_eq!(io::ErrorKind::NotFound, error.kind());
        assert!(!destination.exists());
    }

    #[tokio::test]
    async fn copy_then_remove_file_copies_the_content_and_removes_the_source() {
        let temp_dir = temp_dir_create!();
        let source = temp_dir.join("source");
        let destination = temp_dir.join("destination");
        fs::write(&source, "content").unwrap();

        copy_then_remove_file(&source, &destination).await.unwrap();

        assert!(!source.exists());
        assert_eq!("content", fs::read_to_string(&destination).unwrap());
    }

    #[tokio::test]
    async fn copy_then_remove_file_replaces_an_existing_destination() {
        let temp_dir = temp_dir_create!();
        let source = temp_dir.join("source");
        let destination = temp_dir.join("destination");
        fs::write(&source, "new content").unwrap();
        fs::write(&destination, "old content").unwrap();

        copy_then_remove_file(&source, &destination).await.unwrap();

        assert!(!source.exists());
        assert_eq!("new content", fs::read_to_string(&destination).unwrap());
        assert_eq!(1, read_files_in_directory(&temp_dir).unwrap().len());
    }

    #[tokio::test]
    async fn copy_then_remove_file_keeps_an_existing_destination_when_the_copy_fails() {
        let temp_dir = temp_dir_create!();
        let destination = temp_dir.join("destination");
        fs::write(&destination, "old content").unwrap();

        copy_then_remove_file(&temp_dir.join("missing"), &destination)
            .await
            .expect_err("a missing source can not be copied");

        assert_eq!("old content", fs::read_to_string(&destination).unwrap());
        assert_eq!(1, read_files_in_directory(&temp_dir).unwrap().len());
    }
}
