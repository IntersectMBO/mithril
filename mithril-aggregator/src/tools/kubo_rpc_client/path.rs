use std::fmt::Display;

/// A path to a Mutable File System directory in IPFS.
///
/// It enforces that the path is absolute and has a trailing slash.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct IpfsMfsDirPath(String);

impl IpfsMfsDirPath {
    /// Creates a new instance of `IpfsMfsDirPath` from the given path-like input.
    ///
    /// This function takes an input that can be represented as a string and ensures
    /// the following:
    /// - The resulting path always starts with a '/' if it does not already.
    /// - The resulting path always ends with a '/' if it does not already.
    pub fn from<P: AsRef<str>>(path: P) -> Self {
        let mut path = path.as_ref().to_string();

        if !path.starts_with('/') {
            path.insert(0, '/');
        }

        if !path.ends_with('/') {
            path.push('/');
        }

        Self(path)
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
        Ok(Self::from(&path))
    }
}

impl AsRef<str> for IpfsMfsDirPath {
    fn as_ref(&self) -> &str {
        &self.0
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
}
