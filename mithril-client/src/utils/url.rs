use std::net::IpAddr;

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

/// Whether the host of the URL is a loopback address or `localhost`
pub fn is_loopback(url: &Url) -> bool {
    match url.host_str() {
        Some(host) if host.eq_ignore_ascii_case("localhost") => true,
        // IPv6 hosts are enclosed in brackets
        Some(host) => host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback()),
        None => false,
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

    #[test]
    fn loopback_hosts_are_loopback() {
        for url in [
            "http://127.0.0.1:5001/",
            "http://127.1.2.3:5001/",
            "http://[::1]:5001/",
            "http://localhost:5001/",
            "http://LOCALHOST:5001/",
        ] {
            assert!(is_loopback(&Url::parse(url).unwrap()), "{url}");
        }
    }

    #[test]
    fn other_hosts_are_not_loopback() {
        for url in [
            "http://192.168.1.10:5001/",
            "http://[2001:db8::1]:5001/",
            "http://ipfs.example.com:5001/",
            "http://localhost.example.com:5001/",
        ] {
            assert!(!is_loopback(&Url::parse(url).unwrap()), "{url}");
        }
    }
}
