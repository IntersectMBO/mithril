use std::fmt::Display;
use std::path::Path;

use anyhow::Context;

use mithril_common::StdResult;

/// A path to a Mutable File System directory in IPFS.
///
/// It enforces that the path is absolute and has a trailing slash.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct IpfsMfsDirPath(String);

impl IpfsMfsDirPath {
    /// Return a path for a file in this directory whose name is taken from `file_path`.
    ///
    /// Only the final component of `file_path` is used. Returns an error if the path
    /// has no file name.
    pub fn join_file_name_from<P: AsRef<Path>>(&self, file_path: P) -> StdResult<String> {
        let filename = file_path
            .as_ref()
            .file_name()
            .with_context(|| {
                format!(
                    "Failed to get filename from path: {}",
                    file_path.as_ref().display()
                )
            })?
            .to_string_lossy();
        Ok(format!("{}{filename}", self.0))
    }
}

impl Display for IpfsMfsDirPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de> serde::Deserialize<'de> for IpfsMfsDirPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let path = String::deserialize(deserializer)?;
        Ok(Self::from(path))
    }
}

impl AsRef<str> for IpfsMfsDirPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for IpfsMfsDirPath {
    /// Converts a [String] into an `IpfsMfsDirPath`.
    ///
    /// It ensures the following:
    /// - The resulting path always starts with a '/' if it does not already.
    /// - The resulting path always ends with a '/' if it does not already.
    fn from(path: String) -> Self {
        let mut path = path;
        if !path.starts_with('/') {
            path.insert(0, '/');
        }

        if !path.ends_with('/') {
            path.push('/');
        }

        Self(path)
    }
}

impl From<&str> for IpfsMfsDirPath {
    /// Converts a [str] into an `IpfsMfsDirPath`.
    ///
    /// It ensures the following:
    /// - The resulting path always starts with a '/' if it does not already.
    /// - The resulting path always ends with a '/' if it does not already.
    fn from(value: &str) -> Self {
        value.to_string().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_absolute_and_trailing_slash() {
        assert_eq!("/", IpfsMfsDirPath::from("").as_ref());
        assert_eq!("/", IpfsMfsDirPath::from("/").as_ref());
        assert_eq!("/dir/", IpfsMfsDirPath::from("/dir").as_ref());
        assert_eq!("/dir/", IpfsMfsDirPath::from("/dir/").as_ref());
        assert_eq!("/dir/subdir/", IpfsMfsDirPath::from("/dir/subdir").as_ref());
        assert_eq!(
            "/dir/subdir/",
            IpfsMfsDirPath::from("/dir/subdir/").as_ref()
        );
    }

    #[test]
    fn deserializing_enforces_absolute_and_trailing_slash() {
        assert_eq!(
            IpfsMfsDirPath::from("/"),
            serde_json::from_str(r#""""#).unwrap()
        );
        assert_eq!(
            IpfsMfsDirPath::from("/"),
            serde_json::from_str(r#""/""#).unwrap(),
        );
        assert_eq!(
            IpfsMfsDirPath::from("/dir/"),
            serde_json::from_str(r#""/dir""#).unwrap(),
        );
        assert_eq!(
            IpfsMfsDirPath::from("/dir/"),
            serde_json::from_str(r#""/dir/""#).unwrap(),
        );
        assert_eq!(
            IpfsMfsDirPath::from("/dir with spaces/"),
            serde_json::from_str(r#""/dir with spaces/""#).unwrap()
        );
        assert_eq!(
            IpfsMfsDirPath::from("/dir/subdir/"),
            serde_json::from_str(r#""/dir/subdir""#).unwrap()
        );
        assert_eq!(
            IpfsMfsDirPath::from("/dir/subdir/"),
            serde_json::from_str(r#""/dir/subdir/""#).unwrap()
        );
    }

    #[test]
    fn join_file_name_from_builds_mfs_path_from_directory_and_file_name() {
        let path = IpfsMfsDirPath::from("/test/dir")
            .join_file_name_from("/local/archive/dummy-file.txt")
            .unwrap();

        assert_eq!("/test/dir/dummy-file.txt", path);
    }

    #[test]
    fn join_file_name_from_returns_error_when_path_has_no_file_name() {
        let error = IpfsMfsDirPath::from("/test/dir")
            .join_file_name_from(Path::new(""))
            .unwrap_err();

        assert!(error.to_string().contains("Failed to get filename from path"));
    }
}
