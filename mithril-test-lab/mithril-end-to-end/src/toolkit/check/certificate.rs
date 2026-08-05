use anyhow::{Context, anyhow};
use slog_scope::info;

use mithril_common::{
    StdResult,
    entities::Epoch,
    messages::{CertificateListItemMessage, CertificateMessage},
};

use crate::{Aggregator, poll_until, toolkit::ScenarioToolkitContext, utils::AttemptResult};

use super::utils;

#[derive(Debug, Clone)]
pub struct CheckCertificateToolkit {
    context: ScenarioToolkitContext,
}

impl CheckCertificateToolkit {
    pub fn new(context: ScenarioToolkitContext) -> Self {
        Self { context }
    }

    pub async fn is_creating_certificate_with_min_epoch(
        &self,
        aggregator: &Aggregator,
        min_epoch_expected: Epoch,
    ) -> StdResult<CertificateListItemMessage> {
        utils::wait_for_latest_artifact_with_condition(
            &format!("Certificate for epoch {}", min_epoch_expected),
            "/certificates",
            |a: &CertificateListItemMessage| a.hash.clone(),
            &self.context,
            aggregator,
            |c| c.epoch >= min_epoch_expected,
            |last_invalid_cert| {
                format!(
                    "no certificate found with epoch >= {min_epoch_expected}\nlast certificate: {last_invalid_cert:?}",
                )
            },
        )
        .await
    }

    pub async fn is_creating_certificate_with_enough_signers(
        &self,
        aggregator: &Aggregator,
        certificate_hash: &str,
        total_signers_expected: usize,
    ) -> StdResult<()> {
        let url = format!("{}/certificate/{certificate_hash}", aggregator.endpoint());
        info!("Waiting for the aggregator to create a certificate"; "aggregator" => &aggregator.name());

        async fn fetch_certificate_message(url: String) -> StdResult<Option<CertificateMessage>> {
            match utils::get_json_response::<CertificateMessage>(url).await? {
                Ok(certificate) => Ok(Some(certificate)),
                Err(err) => Err(anyhow!(err).context("Invalid snapshot body")),
            }
        }

        match poll_until!(
            self.context.existing_artifact_fetch_timeout(),
            self.context.poll_backoff(),
            { fetch_certificate_message(url.clone()).await }
        ) {
            AttemptResult::Ok(certificate) => {
                info!("Aggregator produced a certificate"; "certificate" => ?certificate);
                if certificate.metadata.signers.len() == total_signers_expected {
                    info!(
                        "Certificate is signed by expected number of signers: {} >= {} ",
                        certificate.metadata.signers.len(),
                        total_signers_expected ;
                        "aggregator" => &aggregator.name()
                    );
                    Ok(())
                } else {
                    Err(anyhow!(
                        "Certificate is not signed by expected number of signers: {} < {} ",
                        certificate.metadata.signers.len(),
                        total_signers_expected
                    ))
                }
            }
            AttemptResult::Err(error) => Err(error),
            AttemptResult::Timeout(..) => Err(anyhow!(
                "Timeout exhausted assert_is_creating_certificate, no response from `{url}`"
            )),
        }
        .with_context(|| format!("Requesting aggregator `{}`", aggregator.name()))
    }
}
