use reqwest::Url;

pub fn enforce_trailing_slash(mut url: Url) -> Url {
    // Trailing slash is significant because url::join
    // (https://docs.rs/url/latest/url/struct.Url.html#method.join) will remove
    // the 'path' part of the url if it doesn't end with a trailing slash.
    if url.as_str().ends_with('/') {
        url
    } else {
        url.set_path(&format!("{}/", url.path()));
        url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforce_trailing_slash_for_url() {
        let url_without_trailing_slash = Url::parse("http://localhost:8080/api").unwrap();
        let url_with_trailing_slash = Url::parse("http://localhost:8080/api/").unwrap();

        assert_eq!(
            url_with_trailing_slash,
            enforce_trailing_slash(url_without_trailing_slash.clone())
        );
        assert_eq!(
            url_with_trailing_slash,
            enforce_trailing_slash(url_with_trailing_slash.clone())
        );
    }
}
