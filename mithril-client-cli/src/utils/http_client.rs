use std::time::Duration;

use reqwest::{Client, ClientBuilder};

/// Maximum duration to connect to the server
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum duration without receiving data from the server
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Reqwest client builder with the connect and read timeouts of the CLI downloads, so a stalled
/// server fails the request instead of hanging it.
pub fn http_client_builder() -> ClientBuilder {
    http_client_builder_with_read_timeout(READ_TIMEOUT)
}

fn http_client_builder_with_read_timeout(read_timeout: Duration) -> ClientBuilder {
    Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(read_timeout)
}

#[cfg(test)]
mod tests {
    use httpmock::MockServer;

    use super::*;

    #[tokio::test]
    async fn request_fails_when_the_server_does_not_send_data_within_the_read_timeout() {
        let server = MockServer::start();
        server.mock(|_, then| {
            then.delay(Duration::from_secs(2));
        });
        let client = http_client_builder_with_read_timeout(Duration::from_millis(200))
            .build()
            .unwrap();

        let error = client
            .get(server.base_url())
            .send()
            .await
            .expect_err("Should fail when the server stalls");

        assert!(error.is_timeout(), "Unexpected error: {error:?}");
    }
}
