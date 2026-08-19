use std::time::Duration;

use anyhow::Context;
use reqwest::{RequestBuilder, Response, StatusCode, Url};
use slog::{Logger, trace};

use mithril_common::logging::LoggerExtensions;
use mithril_common::{StdError, StdResult};

use crate::tools::url_sanitizer::SanitizedUrlWithTrailingSlash;

/// Trait for defining RPC queries to the Kubo IPFS node.
#[async_trait::async_trait]
pub trait KuboRpcQuery: Sync {
    /// The type of the successful response from this query.
    type Response;

    /// Returns the API route path for this query.
    fn route(&self) -> String;

    /// Configures the RPC request before sending.
    ///
    /// Override this method to add query parameters, headers, or body to the request.
    ///
    /// Note: Configuration made by the [KuboRpcClient] won't be overridden since they are applied after this method.
    async fn configure_request(
        &self,
        request_builder: RequestBuilder,
    ) -> StdResult<RequestBuilder> {
        Ok(request_builder)
    }

    /// Timeout for the RPC request.
    fn timeout() -> Duration {
        Duration::from_secs(1)
    }

    /// Handles a successful RPC response and converts it to the expected response type.
    async fn handle_success(&self, response: Response) -> StdResult<Self::Response>;

    /// Handles an error RPC response
    ///
    /// Default to returning an error with the response text, but can be overridden to handle errors
    /// differently.
    async fn handle_error(&self, response: Response) -> StdResult<Self::Response> {
        let status_code = response.status();
        let response_text = response.text().await.unwrap_or_else(|e| e.to_string());

        Err(format_response_error(status_code, &response_text))
    }
}

/// HTTP client for sending RPC requests to a Kubo IPFS node.
///
/// This requester handles the HTTP communication layer, including request construction,
/// timeout management, and error handling.
pub struct KuboRpcClient {
    rpc_base_url: Url,
    client: reqwest::Client,
    logger: Logger,
}

impl KuboRpcClient {
    /// Creates a new Kubo RPC client.
    pub fn new(rpc_base_url: SanitizedUrlWithTrailingSlash, logger: Logger) -> StdResult<Self> {
        Ok(Self {
            rpc_base_url: rpc_base_url.into(),
            client: reqwest::Client::builder()
                .build()
                .with_context(|| "RPC client creation failed")?,
            logger: logger.new_with_component_name::<Self>(),
        })
    }

    /// Sends an RPC query to the Kubo node and returns the parsed response.
    ///
    /// Returns an error if the request fails, times out, or the response indicates failure.
    pub async fn send<Q: KuboRpcQuery>(&self, query: Q) -> StdResult<Q::Response> {
        let route = query.route();
        let endpoint = join_endpoint(&self.rpc_base_url, &route)?;
        trace!(self.logger, "Kubo RPC POST"; "endpoint" => %endpoint);

        let request_builder = query
            .configure_request(self.client.post(endpoint))
            .await
            .with_context(|| {
                format!("Failed to configure request for Kubo RPC endpoint: '{route}'")
            })?
            .timeout(Q::timeout());

        let response = request_builder
            .send()
            .await
            .with_context(|| format!("Failed to send request to Kubo RPC endpoint: '{route}'"))?;

        if response.status().is_success() {
            query.handle_success(response).await
        } else {
            query.handle_error(response).await
        }
    }
}

fn join_endpoint(base_url: &Url, endpoint: &str) -> StdResult<Url> {
    let normalized_endpoint = if let Some(stripped_endpoint) = endpoint.strip_prefix("/") {
        stripped_endpoint
    } else {
        endpoint
    };

    base_url
        .join(normalized_endpoint)
        .with_context(|| format!("Could not join `{base_url}` to URL `{endpoint}`"))
}

pub(super) fn format_response_error(status: StatusCode, response_text: &str) -> StdError {
    anyhow::anyhow!("Request to Kubo RPC failed: {status}: '{response_text}'")
}

#[cfg(test)]
mod tests {
    use httpmock::Method::POST;

    use crate::tools::kubo_rpc_client::test_tools::setup_server_and_client;

    use super::*;

    struct QueryWithoutResponse;

    #[async_trait::async_trait]
    impl KuboRpcQuery for QueryWithoutResponse {
        type Response = ();

        fn route(&self) -> String {
            "foo".to_string()
        }

        async fn handle_success(&self, _response: Response) -> StdResult<Self::Response> {
            Ok(())
        }
    }

    struct QueryWithResponseAndParam {
        param: String,
    }

    #[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
    struct QueryResponse {
        foo: String,
        bar: u32,
    }

    #[async_trait::async_trait]
    impl KuboRpcQuery for QueryWithResponseAndParam {
        type Response = QueryResponse;

        fn route(&self) -> String {
            "/foo".to_string()
        }

        async fn configure_request(
            &self,
            request_builder: RequestBuilder,
        ) -> StdResult<RequestBuilder> {
            Ok(request_builder.query(&[("param", &self.param)]))
        }

        async fn handle_success(&self, response: Response) -> StdResult<Self::Response> {
            let json = response.json().await?;
            Ok(json)
        }
    }

    #[test]
    fn join_an_endpoint_with_a_leading_slash_should_keep_existing_components() {
        let base_url = Url::parse("http://localhost:5001/api/v0/").unwrap();

        assert_eq!(
            "http://localhost:5001/api/v0/foo",
            join_endpoint(&base_url, "/foo").unwrap().as_str()
        );
    }

    #[tokio::test]
    async fn minimal_request_with_only_route() {
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/foo");
            then.status(200);
        });

        client.send(QueryWithoutResponse).await.unwrap();
    }

    #[tokio::test]
    async fn minimal_request_with_route_and_param() {
        let expected_response = QueryResponse {
            foo: "pika".to_string(),
            bar: 123,
        };
        let (server, client) = setup_server_and_client();
        server.mock(|when, then| {
            when.method(POST).path("/foo").query_param("param", "bar");
            then.status(200).json_body_obj(&expected_response);
        });

        let response = client
            .send(QueryWithResponseAndParam {
                param: "bar".to_string(),
            })
            .await
            .unwrap();

        assert_eq!(expected_response, response);
    }

    #[tokio::test]
    async fn query_times_out_when_response_exceeds_configured_timeout() {
        struct TimeoutQuery;

        #[async_trait::async_trait]
        impl KuboRpcQuery for TimeoutQuery {
            type Response = ();

            fn route(&self) -> String {
                "will_timeout".to_string()
            }

            fn timeout() -> Duration {
                Duration::from_millis(10)
            }

            async fn handle_success(&self, _response: Response) -> StdResult<Self::Response> {
                Ok(())
            }
        }

        let (server, client) = setup_server_and_client();
        let _server_mock = server.mock(|when, then| {
            when.any_request();
            then.delay(Duration::from_millis(100));
        });

        let error = client.send(TimeoutQuery).await.unwrap_err();

        assert!(
            format!("{error:?}").contains("operation timed out"),
            "Expected error message to contain 'operation timed out'\ngot '{error:?}'",
        )
    }

    mod errors {
        use super::*;

        macro_rules! assert_error_text_contains {
            ($error: expr, $expect_contains: expr) => {
                let error = &$error;
                assert!(
                    error.contains($expect_contains),
                    "Expected error message to contain '{}'\ngot '{error:?}'",
                    $expect_contains,
                );
            };
        }

        #[tokio::test]
        async fn handle_json_errors() {
            let json = serde_json::json!({"title": "error", "message":"an error"});
            let (server, client) = setup_server_and_client();
            server.mock(|when, then| {
                when.any_request();
                then.status(400).json_body(json.clone());
            });

            let err = client.send(QueryWithoutResponse).await.unwrap_err();
            assert_error_text_contains!(err.to_string(), &json.to_string());
        }

        #[tokio::test]
        async fn handle_malformed_json() {
            let malformed_json = r###"{"title": "error" "message":"an error"}"###;
            let (server, client) = setup_server_and_client();
            server.mock(|when, then| {
                when.any_request();
                then.status(400)
                    .body(malformed_json)
                    .header("Content-Type", "application/json");
            });

            let err = client.send(QueryWithoutResponse).await.unwrap_err();
            assert_error_text_contains!(err.to_string(), &malformed_json.to_string());
        }

        #[tokio::test]
        async fn handle_text_error() {
            let (server, client) = setup_server_and_client();
            server.mock(|when, then| {
                when.any_request();
                then.status(400).body("an error message");
            });

            let err = client.send(QueryWithoutResponse).await.unwrap_err();
            assert_error_text_contains!(err.to_string(), ": 'an error message'");
        }

        #[tokio::test]
        async fn handle_4xx_error() {
            let (server, client) = setup_server_and_client();
            server.mock(|when, then| {
                when.any_request();
                then.status(400).body("an error message");
            });

            let err = client.send(QueryWithoutResponse).await.unwrap_err();
            assert_error_text_contains!(
                err.to_string(),
                "Request to Kubo RPC failed: 400 Bad Request:"
            );
        }

        #[tokio::test]
        async fn handle_5xx_error() {
            let (server, client) = setup_server_and_client();
            server.mock(|when, then| {
                when.any_request();
                then.status(500).body("an error message");
            });

            let err = client.send(QueryWithoutResponse).await.unwrap_err();
            assert_error_text_contains!(
                err.to_string(),
                "Request to Kubo RPC failed: 500 Internal Server Error:"
            );
        }
    }
}
