mod api;
mod credentials;
mod path;
pub mod query;

pub use api::{DEFAULT_TIMEOUT_SECS, KuboRpcClient, KuboRpcQuery, TIMEOUT_FOR_SLOW_QUERY_SECS};
pub use credentials::KuboRpcCredentials;
pub use path::IpfsMfsDirPath;

#[cfg(test)]
mod test_tools {
    use httpmock::MockServer;

    use crate::test::TestLogger;
    use crate::tools::url_sanitizer::SanitizedUrlWithTrailingSlash;

    use super::KuboRpcClient;

    pub(super) fn setup_server_and_client() -> (MockServer, KuboRpcClient) {
        let server = MockServer::start();
        let client = KuboRpcClient::new(
            SanitizedUrlWithTrailingSlash::parse(&server.base_url()).unwrap(),
            TestLogger::stdout(),
            None,
        )
        .unwrap();

        (server, client)
    }
}
