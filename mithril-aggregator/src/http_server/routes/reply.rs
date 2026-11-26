use std::path::Path;

use serde::Serialize;
use warp::http::StatusCode;

use mithril_common::StdError;
use mithril_common::entities::{ClientError, ServerError};
use mithril_persistence::sqlite::error::{PRIMARY_ERROR_CODE_MASK, SQLITE_BUSY, SqliteError};

use crate::SignerRegistrationError;
use crate::tools::downcast_check;

pub struct MithrilStatusCode();

impl MithrilStatusCode {
    pub fn registration_round_not_yet_opened() -> StatusCode {
        // The unwrap is safe here because `from_16` function return error only for values outside of the range 100-999,
        StatusCode::from_u16(550).unwrap()
    }
}

pub fn json<T>(value: &T, status_code: StatusCode) -> Box<dyn warp::Reply>
where
    T: Serialize,
{
    Box::new(warp::reply::with_status(
        warp::reply::json(value),
        status_code,
    ))
}

pub fn empty(status_code: StatusCode) -> Box<dyn warp::Reply> {
    Box::new(warp::reply::with_status(warp::reply::reply(), status_code))
}

pub fn bad_request(label: String, message: String) -> Box<dyn warp::Reply> {
    json(&ClientError::new(label, message), StatusCode::BAD_REQUEST)
}

pub fn gone(label: String, message: String) -> Box<dyn warp::Reply> {
    json(&ClientError::new(label, message), StatusCode::GONE)
}

pub fn server_error<E: Into<StdError>>(error: E) -> Box<dyn warp::Reply> {
    let std_error: StdError = error.into();
    let status_code = {
        let mut code = StatusCode::INTERNAL_SERVER_ERROR;

        if downcast_check::<SqliteError>(&std_error, |e| {
            e.code
                .is_some_and(|code| code & PRIMARY_ERROR_CODE_MASK == SQLITE_BUSY)
        }) {
            code = StatusCode::SERVICE_UNAVAILABLE;
        }

        if downcast_check::<SignerRegistrationError>(&std_error, |e| {
            matches!(e, SignerRegistrationError::RegistrationRoundNotYetOpened)
        }) {
            code = MithrilStatusCode::registration_round_not_yet_opened();
        }

        code
    };

    json(&ServerError::new(format!("{std_error:?}")), status_code)
}

pub fn internal_server_error<T: Into<ServerError>>(message: T) -> Box<dyn warp::Reply> {
    json(&message.into(), StatusCode::INTERNAL_SERVER_ERROR)
}

pub fn add_content_disposition_header(
    reply: warp::fs::File,
    filepath: &Path,
) -> Box<dyn warp::Reply> {
    Box::new(warp::reply::with_header(
        reply,
        "Content-Disposition",
        format!(
            "attachment; filename=\"{}\"",
            filepath.file_name().unwrap().to_str().unwrap()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use warp::Reply;

    use mithril_persistence::sqlite::error::SQLITE_BUSY_SNAPSHOT;

    use super::*;

    #[test]
    fn test_server_error_convert_std_error_to_500_by_default() {
        let error = anyhow!("Some error");
        let response = server_error(error).into_response();

        assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, response.status());
    }

    #[test]
    fn test_server_error_convert_wrapped_sqlite_busy_error_to_503() {
        let res = sqlite::Error {
            code: Some(SQLITE_BUSY),
            message: None,
        };
        let response = server_error(res).into_response();

        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, response.status());

        // Wrapping the error in a StdError should also work
        let res = anyhow!(sqlite::Error {
            code: Some(SQLITE_BUSY),
            message: None,
        });
        let response = server_error(res).into_response();

        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, response.status());
    }

    #[test]
    fn test_server_error_convert_sqlite_busy_extended_error_to_503() {
        let res = sqlite::Error {
            code: Some(SQLITE_BUSY_SNAPSHOT),
            message: None,
        };
        let response = server_error(res).into_response();

        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, response.status());
    }

    #[test]
    fn test_server_error_convert_signer_registration_round_not_yet_opened_to_550() {
        let err = SignerRegistrationError::RegistrationRoundNotYetOpened;
        let response = server_error(err).into_response();

        assert_eq!(
            MithrilStatusCode::registration_round_not_yet_opened(),
            response.status()
        );

        // Wrapping the error in a StdError should also work
        let err = anyhow!(SignerRegistrationError::RegistrationRoundNotYetOpened);
        let response = server_error(err).into_response();

        assert_eq!(
            MithrilStatusCode::registration_round_not_yet_opened(),
            response.status()
        );
    }
}
