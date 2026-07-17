mod certificates_hash_migrator;
mod era;
pub mod file_archiver;
pub mod file_size;
mod genesis;
mod protocol_configuration;
pub mod signer_importer;
mod single_signature_authenticator;
pub mod url_sanitizer;
mod vacuum_tracker;

pub use certificates_hash_migrator::CertificatesHashMigrator;
pub use era::EraTools;
#[cfg(feature = "future_snark")]
pub use genesis::GenesisSignedPayload;
pub use genesis::GenesisTools;
pub use protocol_configuration::ProtocolConfigurationTools;
pub use single_signature_authenticator::*;
pub use vacuum_tracker::VacuumTracker;

/// Default environment variable name where the GCP credentials JSON is stored.
pub(crate) const DEFAULT_GCP_CREDENTIALS_JSON_ENV_VAR: &str = "GOOGLE_APPLICATION_CREDENTIALS_JSON";

/// Downcast the error to the specified error type and check if the error satisfies the condition.
pub(crate) fn downcast_check<E>(
    error: &mithril_common::StdError,
    check: impl Fn(&E) -> bool,
) -> bool
where
    E: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
{
    if let Some(inner_error) = error.downcast_ref::<E>() {
        return check(inner_error);
    }
    false
}
