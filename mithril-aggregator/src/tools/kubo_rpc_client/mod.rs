mod api;
mod path;
pub mod query;

pub use api::{KuboRpcClient, KuboRpcQuery};
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
        )
        .unwrap();

        (server, client)
    }
}
