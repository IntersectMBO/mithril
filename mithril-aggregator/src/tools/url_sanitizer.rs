use anyhow::{Context, anyhow};
use reqwest::Url;
use std::fmt::{Display, Formatter};
use std::ops::Deref;

use mithril_common::StdResult;

/// A sanitized URL, guaranteed to have a trailing slash and no empty segments
///
/// This type is meant to be used as a base path to produce resources path, for example:
/// `https://example.xy/download/` can be joined with `artifact/file.zip` to produce a download link
#[derive(Debug, Clone, PartialOrd, PartialEq, Eq, Ord, Hash)]
pub struct SanitizedUrlWithTrailingSlash {
    internal_url: Url,
}

impl SanitizedUrlWithTrailingSlash {
    /// Join this URL with the given path, the resulting URL is guaranteed to have a trailing slash
    ///
    /// See [Url::join] for more details
    pub fn sanitize_join(&self, input: &str) -> StdResult<SanitizedUrlWithTrailingSlash> {
        let url = self.internal_url.join(input).with_context(|| {
            format!(
                "Could not join `{}` to URL `{input}`",
                self.internal_url.as_str()
            )
        })?;
        sanitize_url_path(&url)
    }

    /// Parse an absolute URL from a string.
    ///
    /// See [Url::parse] for more details
    pub fn parse(input: &str) -> StdResult<SanitizedUrlWithTrailingSlash> {
        let url = Url::parse(input).with_context(|| format!("Could not parse URL `{input}`"))?;
        sanitize_url_path(&url)
    }

    /// Consumes this [SanitizedUrlWithTrailingSlash] and returns the underlying [Url]
    pub fn into_url(self) -> Url {
        self.internal_url
    }
}

impl PartialEq<Url> for SanitizedUrlWithTrailingSlash {
    fn eq(&self, other: &Url) -> bool {
        self.internal_url.eq(other)
    }
}

impl Deref for SanitizedUrlWithTrailingSlash {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.internal_url
    }
}

impl From<SanitizedUrlWithTrailingSlash> for Url {
    fn from(value: SanitizedUrlWithTrailingSlash) -> Self {
        value.internal_url
    }
}

impl Display for SanitizedUrlWithTrailingSlash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.internal_url.fmt(f)
    }
}

/// Sanitize URL path by removing empty segments and adding trailing slash
pub fn sanitize_url_path(url: &Url) -> StdResult<SanitizedUrlWithTrailingSlash> {
    let segments_non_empty = url
        .path_segments()
        .map(|s| s.into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>())
        .unwrap_or_default();
    let mut url = url.clone();
    {
        let mut url_path_segments = url
            .path_segments_mut()
            .map_err(|e| anyhow!("error parsing URL: {e:?}"))?;
        let url_path_segments_cleared = url_path_segments.clear();
        for segment in segments_non_empty {
            url_path_segments_cleared.push(segment);
        }
        url_path_segments_cleared.push("");
    }

    Ok(SanitizedUrlWithTrailingSlash { internal_url: url })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_url_path() {
        let url = Url::parse("http://example.com/a//b/c.ext?test=123").unwrap();
        assert_eq!(
            "http://example.com/a/b/c.ext/?test=123",
            sanitize_url_path(&url).unwrap().as_str()
        );

        let url = Url::parse("http://example.com/a//b/c.ext").unwrap();
        assert_eq!(
            "http://example.com/a/b/c.ext/",
            sanitize_url_path(&url).unwrap().as_str()
        );

        let url = Url::parse("http://example.com/a//b/c").unwrap();
        assert_eq!(
            "http://example.com/a/b/c/",
            sanitize_url_path(&url).unwrap().as_str()
        );

        let url = Url::parse("http://example.com/").unwrap();
        assert_eq!(
            "http://example.com/",
            sanitize_url_path(&url).unwrap().as_str()
        );

        let url = Url::parse("http://example.com").unwrap();
        assert_eq!(
            "http://example.com/",
            sanitize_url_path(&url).unwrap().as_str()
        );
    }

    #[test]
    fn test_sanitize_url_join() {
        let sanitized_url = sanitize_url_path(&Url::parse("http://example.com/").unwrap()).unwrap();
        assert_eq!(
            "http://example.com/a/b/c_ext/",
            sanitized_url.sanitize_join("a//b/c_ext").unwrap().as_str()
        );
    }

    #[test]
    fn test_sanitize_url_parse() {
        let sanitized_url =
            SanitizedUrlWithTrailingSlash::parse("http://example.com/a//b/c.ext?test=123").unwrap();
        assert_eq!(
            "http://example.com/a/b/c.ext/?test=123",
            sanitized_url.as_str()
        );
    }
}
