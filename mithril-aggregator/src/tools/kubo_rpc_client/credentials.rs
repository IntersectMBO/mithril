use base64::{Engine, prelude::BASE64_STANDARD};
use serde::Deserialize;

use mithril_common::entities::ConfigSecret;

/// Credentials to authenticate to a Kubo RPC API protected by `API.Authorizations`
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum KuboRpcCredentials {
    /// HTTP Basic authentication, matches a `basic:<username>:<password>` Kubo auth secret
    Basic {
        username: String,
        password: ConfigSecret<String>,
    },
    /// Bearer token, matches a `bearer:<token>` Kubo auth secret
    Bearer { token: ConfigSecret<String> },
}

impl KuboRpcCredentials {
    pub(crate) fn to_header_value(&self) -> String {
        match self {
            Self::Basic { username, password } => format!(
                "Basic {}",
                BASE64_STANDARD.encode(format!("{username}:{}", password.expose_secret()))
            ),
            Self::Bearer { token } => format!("Bearer {}", token.expose_secret()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_header_value_is_the_base64_encoded_username_and_password() {
        // Example from RFC 7617
        let credentials = KuboRpcCredentials::Basic {
            username: "Aladdin".to_string(),
            password: ConfigSecret::new("open sesame".to_string()),
        };

        assert_eq!(
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            credentials.to_header_value()
        );
    }

    #[test]
    fn bearer_header_value_is_the_token() {
        let credentials = KuboRpcCredentials::Bearer {
            token: ConfigSecret::new("my-token".to_string()),
        };

        assert_eq!("Bearer my-token", credentials.to_header_value());
    }

    #[test]
    fn debug_output_does_not_expose_secrets() {
        let basic = KuboRpcCredentials::Basic {
            username: "mithril".to_string(),
            password: ConfigSecret::new("basic-secret".to_string()),
        };
        let bearer = KuboRpcCredentials::Bearer {
            token: ConfigSecret::new("bearer-secret".to_string()),
        };

        assert!(!format!("{basic:?}").contains("basic-secret"));
        assert!(!format!("{bearer:?}").contains("bearer-secret"));
    }
}
